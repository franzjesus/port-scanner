//! TCP-based host discovery.
//!
//! [`TcpDiscovery`] resolves every address in a [`ScanTarget`] to a terminal
//! up/down state by probing a small set of well-known TCP ports
//! ([`PROBE_PORTS`]) and classifying each connect result with
//! [`classify_connect`].
//!
//! ## Why TCP
//!
//! ICMP echo discovery requires opening an ICMP socket, which on many systems
//! fails for unprivileged users (`EPERM`). TCP connect probes need no special
//! privileges, which makes this the fallback discovery mechanism when an ICMP
//! socket cannot be opened.
//!
//! ## Classification
//!
//! A host is **up** when any probe reaches a live endpoint: the connection is
//! accepted, or a closed port answers with a refusal (a RST that surfaces as
//! `ECONNREFUSED` on Linux). A host is **down** when every probe times out or
//! is reported unreachable.
//!
//! ## Scheduling model
//!
//! Probes run in a bounded, persistent pool of worker threads rather than
//! spawning one task per probe. The pool size is the configured concurrency
//! capped at the number of (host, port) probes ([`worker_count`]), and workers
//! claim work from a shared atomic counter over the flattened probe list.
//!
//! Results are batched: each worker records its per-probe outcome in a shared
//! list, and once every worker has drained the work list the outcomes are
//! aggregated per host (a host is up when any probe classified up, carrying
//! the minimum measured latency) and emitted in sorted IP order as
//! [`ScanEvent::HostDiscovered`] / [`ScanEvent::Progress`].
//!
//! ## Cancellation
//!
//! Cancellation is cooperative. Workers check the flag before starting each new
//! connection, so once it is set no further probes start while in-flight
//! connects are allowed to complete (bounded by [`DiscoveryConfig::timeout`]).
//! If the work list drains with cancellation requested, [`TcpDiscovery::discover`]
//! emits [`ScanEvent::Cancelled`] and returns [`DiscoveryOutcome::Cancelled`]
//! without emitting any partial results.
//!
//! Like [`IcmpDiscovery`], `discover` is the unframed core: it never emits
//! [`ScanEvent::Started`] or [`ScanEvent::Finished`]; the orchestrating scan
//! frames a whole run with a single pair of those events.

use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::network::{Host, HostState};
use crate::scanner::ports::worker_count;
use crate::scanner::{DiscoveryConfig, DiscoveryOutcome, HostDiscovery, ScanError, ScanEvent};
use crate::target::ScanTarget;

/// The well-known TCP ports probed to decide whether a host is up.
///
/// A live host answers every one of these with either an accepted connection or
/// a refusal, so probing a handful of common ports is enough to distinguish a
/// reachable host from an absent one without scanning the full port space.
const PROBE_PORTS: [u16; 4] = [22, 80, 443, 3389];

/// Resolves hosts by TCP connect probes.
///
/// The unit type carries no per-instance state; all tunables are passed to
/// [`TcpDiscovery::discover`] through [`DiscoveryConfig`]. It exists to satisfy
/// the [`HostDiscovery`] trait and leaves room for future per-instance options.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpDiscovery;

/// Classify the result of a single TCP connect probe into a host state.
///
/// A host is considered **up** when a connect attempt reached a live endpoint:
///
/// - the connection was accepted (`Ok`), or
/// - the endpoint answered with a connection refusal (`ConnectionRefused`).
///   On Linux a closed port on a live host produces a RST that surfaces as
///   `ECONNREFUSED`, so a refusal proves the host is reachable and running.
///
/// Every other failure (timeout, host or network unreachable, ...) means no
/// endpoint answered and the host is classified **down**.
pub(crate) fn classify_connect(result: Result<TcpStream, io::Error>) -> HostState {
    match result {
        Ok(_) => HostState::Up,
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => HostState::Up,
        Err(_) => HostState::Down,
    }
}

impl HostDiscovery for TcpDiscovery {
    fn discover(
        &self,
        target: &ScanTarget,
        config: &DiscoveryConfig,
        events: &Sender<ScanEvent>,
        cancel: &Arc<AtomicBool>,
    ) -> Result<DiscoveryOutcome, ScanError> {
        // Enumerate every address up front (bounded by MAX_SUBNET_SIZE) so the
        // work list can be flattened and counted.
        let addresses: Vec<Ipv4Addr> = target.iter().collect();
        if addresses.is_empty() {
            return Ok(DiscoveryOutcome::Completed(Vec::new()));
        }

        // Flatten the (host, port) work into a stable list. Each address probes
        // every port in PROBE_PORTS, so the list is `addresses × PROBE_PORTS`.
        let work: Arc<Vec<(Ipv4Addr, u16)>> = Arc::new(
            addresses
                .iter()
                .flat_map(|ip| PROBE_PORTS.iter().map(|port| (*ip, *port)))
                .collect(),
        );
        let total = addresses.len() as u64;
        let next = Arc::new(AtomicUsize::new(0));
        let results: Arc<Mutex<Vec<(Ipv4Addr, HostState, Duration)>>> =
            Arc::new(Mutex::new(Vec::new()));

        // Spawn a bounded, persistent pool. Workers claim indices from the
        // shared counter until the list is drained or cancellation is set.
        let mut handles = Vec::new();
        for _ in 0..worker_count(config.concurrency, work.len()) {
            let work = Arc::clone(&work);
            let next = Arc::clone(&next);
            let results = Arc::clone(&results);
            let cancel = Arc::clone(cancel);
            let timeout = config.timeout;
            let work_len = work.len();
            handles.push(thread::spawn(move || loop {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let idx = next.fetch_add(1, Ordering::Relaxed);
                if idx >= work_len {
                    break;
                }
                let (ip, port) = work[idx];
                let addr = SocketAddr::new(ip.into(), port);
                let start = Instant::now();
                let state = classify_connect(TcpStream::connect_timeout(&addr, timeout));
                let latency = start.elapsed();
                results.lock().unwrap().push((ip, state, latency));
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        // Move the collected outcomes out of the shared buffer.
        let outcomes = {
            let mut guard = results.lock().unwrap();
            std::mem::take(&mut *guard)
        };

        // Cancellation wins: nothing was emitted yet (emission is batched
        // after the join), so there are no partial results to report.
        if cancel.load(Ordering::Relaxed) {
            let _ = events.send(ScanEvent::Cancelled);
            return Ok(DiscoveryOutcome::Cancelled);
        }

        // Aggregate per host: a host is up when any probe classified up, and its
        // latency is the fastest up-classified probe.
        let mut by_host: BTreeMap<Ipv4Addr, (HostState, Option<Duration>)> = BTreeMap::new();
        for (ip, state, latency) in outcomes {
            let entry = by_host.entry(ip).or_insert((HostState::Down, None));
            if state == HostState::Up {
                entry.0 = HostState::Up;
                entry.1 = Some(match entry.1 {
                    Some(current) => current.min(latency),
                    None => latency,
                });
            }
        }

        // Emit in sorted IP order so the output is deterministic.
        let mut up_hosts: Vec<Host> = Vec::new();
        for (i, (ip, (state, latency))) in by_host.into_iter().enumerate() {
            let host = match (state, latency) {
                (HostState::Up, Some(latency)) => Host::up(ip, latency),
                _ => Host::down(ip),
            };
            let _ = events.send(ScanEvent::HostDiscovered(host.clone()));
            let completed = i as u64 + 1;
            let _ = events.send(ScanEvent::Progress { completed, total });
            if state == HostState::Up {
                up_hosts.push(host);
            }
        }

        Ok(DiscoveryOutcome::Completed(up_hosts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;

    /// Connect to a local listener and return the accepted stream, proving
    /// the `Ok` arm of [`classify_connect`] against a real socket.
    fn live_local_stream() -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local listener");
        let addr = listener.local_addr().expect("listener local address");
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1))
            .expect("connect to local listener");
        drop(listener);
        stream
    }

    /// Build a socket error of the given kind, as the kernel would report it.
    fn socket_err(kind: io::ErrorKind) -> io::Error {
        io::Error::new(kind, "test error")
    }

    #[test]
    fn accepted_connection_classifies_up() {
        let result: Result<TcpStream, io::Error> = Ok(live_local_stream());
        assert_eq!(classify_connect(result), HostState::Up);
    }

    #[test]
    fn refused_connection_classifies_up() {
        let result = Err(socket_err(io::ErrorKind::ConnectionRefused));
        assert_eq!(classify_connect(result), HostState::Up);
    }

    #[test]
    fn timed_out_connection_classifies_down() {
        let result = Err(socket_err(io::ErrorKind::TimedOut));
        assert_eq!(classify_connect(result), HostState::Down);
    }

    #[test]
    fn host_unreachable_classifies_down() {
        let result = Err(socket_err(io::ErrorKind::HostUnreachable));
        assert_eq!(classify_connect(result), HostState::Down);
    }

    #[test]
    fn network_unreachable_classifies_down() {
        let result = Err(socket_err(io::ErrorKind::NetworkUnreachable));
        assert_eq!(classify_connect(result), HostState::Down);
    }

    /// A short discovery timeout for the integration tests below: long enough
    /// to be realistic, short enough to keep the suite fast.
    const TEST_TIMEOUT: Duration = Duration::from_millis(200);

    /// Run discovery on a single target and collect the events it emitted.
    fn discover_single(
        target: ScanTarget,
        cancel: Arc<AtomicBool>,
    ) -> (DiscoveryOutcome, Vec<ScanEvent>) {
        let config = DiscoveryConfig {
            timeout: TEST_TIMEOUT,
            concurrency: 16,
        };
        let (tx, rx) = mpsc::channel();
        let outcome = TcpDiscovery
            .discover(&target, &config, &tx, &cancel)
            .unwrap();
        drop(tx);
        let events = rx.try_iter().collect();
        (outcome, events)
    }

    /// The loopback address is always live, so every probe port either accepts
    /// or refuses, both of which classify up. Discovery must report it as a
    /// single up host with a measured latency, in the unframed event order.
    #[test]
    fn discovers_localhost_as_up() {
        let cancel = Arc::new(AtomicBool::new(false));
        let (outcome, events) = discover_single(ScanTarget::Host(Ipv4Addr::LOCALHOST), cancel);

        let up_hosts = match outcome {
            DiscoveryOutcome::Completed(hosts) => hosts,
            DiscoveryOutcome::Cancelled => panic!("localhost discovery was cancelled"),
        };

        // One address → exactly one HostDiscovered plus one Progress report.
        assert_eq!(events.len(), 2, "unexpected event sequence: {events:?}");
        match &events[0] {
            ScanEvent::HostDiscovered(host) => {
                assert_eq!(host.ip, Ipv4Addr::LOCALHOST);
                assert_eq!(host.state, HostState::Up);
                assert!(host.latency.is_some(), "up host carries a latency");
            }
            other => panic!("first event should be HostDiscovered, got {other:?}"),
        }
        match &events[1] {
            ScanEvent::Progress { completed, total } => {
                assert_eq!(*completed, 1);
                assert_eq!(*total, 1);
            }
            other => panic!("second event should be Progress, got {other:?}"),
        }
        assert_eq!(up_hosts.len(), 1);
        assert_eq!(up_hosts[0].ip, Ipv4Addr::LOCALHOST);
    }

    /// 192.0.2.1 is in TEST-NET-1 (RFC 5737), reserved for documentation and
    /// never assigned to a real host, so every probe times out or is reported
    /// unreachable. Discovery must classify it down and return no up hosts.
    #[test]
    fn classifies_reserved_address_as_down() {
        let cancel = Arc::new(AtomicBool::new(false));
        let (outcome, events) =
            discover_single(ScanTarget::Host("192.0.2.1".parse().unwrap()), cancel);

        let up_hosts = match outcome {
            DiscoveryOutcome::Completed(hosts) => hosts,
            DiscoveryOutcome::Cancelled => panic!("reserved-address discovery was cancelled"),
        };

        assert_eq!(events.len(), 2, "unexpected event sequence: {events:?}");
        match &events[0] {
            ScanEvent::HostDiscovered(host) => {
                assert_eq!(host.ip, "192.0.2.1".parse::<Ipv4Addr>().unwrap());
                assert_eq!(host.state, HostState::Down);
            }
            other => panic!("first event should be HostDiscovered, got {other:?}"),
        }
        match &events[1] {
            ScanEvent::Progress { completed, total } => {
                assert_eq!(*completed, 1);
                assert_eq!(*total, 1);
            }
            other => panic!("second event should be Progress, got {other:?}"),
        }
        assert!(up_hosts.is_empty(), "a reserved address must not be up");
    }

    /// If cancellation is already set, no probe starts: the run emits exactly
    /// the Cancelled event and returns Cancelled with no partial results.
    #[test]
    fn honours_a_pre_set_cancellation() {
        let cancel = Arc::new(AtomicBool::new(true));
        let (outcome, events) = discover_single(ScanTarget::Host(Ipv4Addr::LOCALHOST), cancel);

        assert_eq!(events.len(), 1, "unexpected event sequence: {events:?}");
        assert!(matches!(&events[0], ScanEvent::Cancelled));
        assert!(matches!(outcome, DiscoveryOutcome::Cancelled));
    }
}
