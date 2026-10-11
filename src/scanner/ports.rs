//! TCP connect port scanning.
//!
//! [`TcpPortScanner`] probes the TCP ports of a single host with a bounded,
//! persistent pool of worker threads. Each worker pulls the next unprobed port
//! from a shared counter and attempts a TCP connect to it, reporting the result
//! (open or closed) as a [`ScanEvent::PortDiscovered`] as soon as it is known.
//!
//! ## Scheduling model
//!
//! The number of workers is the configured concurrency capped at the number of
//! ports to probe (and at least one when there is any work), so the pool is
//! bounded no matter how large the port selection is — a small selection does
//! not over-spawn and a full 65 535-port selection does not spawn an unbounded
//! number of threads. All workers share a single atomic counter over the sorted
//! port list; each worker claims the next index with a `fetch_add`, so every
//! port is probed exactly once and the work is distributed evenly without any
//! queue or per-port task.
//!
//! ## Cancellation
//!
//! Cancellation is cooperative. Workers check the flag before starting each new
//! connection, so once it is set no further ports are probed, while in-flight
//! connects are allowed to complete. This matches the cancellation rule in
//! `PLAN.md`: new work stops being scheduled, and no worker threads are left
//! running after [`PortScanner::scan`] returns.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::network::{Port, PortState};
use crate::ports::PortConfig;
use crate::scanner::{PortScanner, ScanError, ScanEvent};

/// Probes TCP ports using the connect technique.
///
/// The unit type carries no per-instance state; all tunables (port set, timeout,
/// concurrency bound) are passed to [`TcpPortScanner::scan`] through
/// [`PortConfig`]. It exists to satisfy the [`PortScanner`] trait and leaves
/// room for future per-instance options.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpPortScanner;

/// The number of worker threads to run for a work count and concurrency bound:
/// zero when there is no work, otherwise the concurrency clamped to the range
/// `[1, work]`. Capping at the work count keeps a small job from over-spawning;
/// the floor of one guards against a zero concurrency setting.
pub(crate) fn worker_count(concurrency: usize, work: usize) -> usize {
    if work == 0 {
        0
    } else {
        concurrency.max(1).min(work)
    }
}

impl PortScanner for TcpPortScanner {
    fn scan(
        &self,
        ip: Ipv4Addr,
        config: &PortConfig,
        events: &Sender<ScanEvent>,
        cancel: &Arc<AtomicBool>,
    ) -> Result<Vec<Port>, ScanError> {
        // The ports to probe, in ascending order. `PortSpec` guarantees they
        // are sorted and unique, so the shared counter below walks a stable
        // list.
        let ports: Vec<Port> = config.ports.iter().collect();
        let workers = worker_count(config.concurrency, ports.len());
        if workers == 0 {
            // An empty port selection has nothing to probe.
            return Ok(Vec::new());
        }

        // All workers share one `Arc` over the port list (cheap to clone per
        // worker even for a full scan) and one atomic counter of the next index
        // to claim. Open ports are collected into a shared `Vec` so the result
        // can be returned once every worker has drained its share.
        let ports = Arc::new(ports);
        let next = Arc::new(AtomicUsize::new(0));
        let open = Arc::new(Mutex::new(Vec::new()));
        let timeout = config.timeout;

        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let ports = Arc::clone(&ports);
            let next = Arc::clone(&next);
            let open = Arc::clone(&open);
            let events = events.clone();
            let cancel = Arc::clone(cancel);

            let handle = thread::spawn(move || {
                loop {
                    // Cooperative cancellation: stop before starting more work.
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    // Claim the next index; indices past the end signal that the
                    // work is done.
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= ports.len() {
                        return;
                    }
                    let port = ports[index];
                    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port.as_u16()));
                    let state = match TcpStream::connect_timeout(&addr, timeout) {
                        Ok(_) => PortState::Open,
                        // Refused, timed out, or unreachable all map to closed.
                        Err(_) => PortState::Closed,
                    };
                    let _ = events.send(ScanEvent::PortDiscovered { ip, port, state });
                    if state == PortState::Open {
                        // Record the open port so the caller can act on the
                        // result (for example, service detection).
                        if let Ok(mut open) = open.lock() {
                            open.push(port);
                        }
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for every worker to drain its share of the port list before
        // returning, so no threads outlive the call. A `JoinError` would mean a
        // worker panicked; the workers are written to be panic-free (every
        // index is bounds-checked and every `Result` handled), so the payload
        // is already surfaced on stderr and there is nothing to recover here.
        for handle in handles {
            let _ = handle.join();
        }

        // Every worker has finished, so the collected list is complete. The
        // ports were discovered concurrently, so sort them into a stable,
        // ascending order before returning. A poisoned lock means a worker
        // panicked mid-push; the (possibly partial) list is still usable.
        let mut open_ports = match open.lock() {
            Ok(open) => open.to_vec(),
            Err(poisoned) => poisoned.into_inner().to_vec(),
        };
        open_ports.sort_unstable();
        Ok(open_ports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_count_is_zero_for_no_ports() {
        assert_eq!(worker_count(128, 0), 0);
    }

    #[test]
    fn worker_count_is_capped_by_port_count() {
        // A large concurrency bound must not spawn more workers than there are
        // ports.
        assert_eq!(worker_count(128, 3), 3);
        assert_eq!(worker_count(65535, 100), 100);
    }

    #[test]
    fn worker_count_respects_a_small_concurrency() {
        // A small concurrency bound limits the pool even when more ports exist.
        assert_eq!(worker_count(2, 100), 2);
        assert_eq!(worker_count(1, 100), 1);
        assert_eq!(worker_count(1, 1), 1);
    }

    #[test]
    fn worker_count_never_zero_when_there_is_work() {
        // A zero concurrency setting still yields at least one worker so the
        // scan can make progress.
        assert_eq!(worker_count(0, 5), 1);
        assert_eq!(worker_count(0, 1), 1);
    }

    #[test]
    fn worker_count_is_identity_when_bounded() {
        // When the concurrency is between 1 and the port count, it is used as
        // is.
        assert_eq!(worker_count(64, 64), 64);
        assert_eq!(worker_count(50, 100), 50);
    }

    #[test]
    fn scan_reports_open_and_closed_ports_on_loopback() {
        use std::collections::BTreeMap;
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::time::Duration;

        use crate::ports::PortSpec;

        // Bind a real listener on loopback; the OS assigns a free ephemeral
        // port. The kernel completes the TCP handshake for connects to a
        // listening socket, so the port reads as open without anyone calling
        // `accept`.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let open_port = listener.local_addr().expect("listener address").port();

        // Bind and immediately drop a second listener to obtain a guaranteed-free
        // port to probe as closed.
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
        let closed_port = probe.local_addr().expect("probe address").port();
        drop(probe);
        assert_ne!(open_port, closed_port);

        let ip = Ipv4Addr::LOCALHOST;
        let config = PortConfig {
            ports: PortSpec::from_port_numbers([open_port, closed_port]),
            timeout: Duration::from_millis(500),
            concurrency: 4,
        };

        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let open_ports = TcpPortScanner
            .scan(ip, &config, &tx, &cancel)
            .expect("port scan should complete without error");

        // The scan returns exactly the ports it found open.
        assert_eq!(open_ports, vec![Port::new(open_port).unwrap()]);

        // Drop the original sender so the channel closes once every worker's
        // clone is dropped (they all are, since `scan` joins every worker).
        drop(tx);

        let mut states: BTreeMap<u16, PortState> = BTreeMap::new();
        for event in rx {
            if let ScanEvent::PortDiscovered { port, state, .. } = event {
                states.insert(port.as_u16(), state);
            }
        }

        assert_eq!(states.len(), 2, "expected one event per probed port");
        assert_eq!(states.get(&open_port), Some(&PortState::Open));
        assert_eq!(states.get(&closed_port), Some(&PortState::Closed));
    }
}
