//! ICMP-based host discovery.
//!
//! [`IcmpDiscovery`] resolves every address in a [`ScanTarget`] to a terminal
//! up/down state by sending one ICMP echo request per address and waiting for
//! an echo reply within the configured timeout.
//!
//! ## Scheduling model
//!
//! Probes run in bounded batches of [`DiscoveryConfig::concurrency`] addresses
//! rather than spawning an unbounded number of concurrent operations. For each
//! batch the module:
//!
//! 1. sends an echo request to every address in the batch, recording the send
//!    time for each;
//! 2. receives replies until the batch window (first send + timeout) closes;
//! 3. matches each reply to its in-flight address and marks that host **up**
//!    with the measured latency;
//! 4. marks every address that did not answer within the window **down**.
//!
//! Batches emit a continuous stream of [`ScanEvent`]s, so a `/24` scan at the
//! default settings resolves in roughly two timeout windows instead of 256.
//!
//! ## Reply matching
//!
//! Replies are matched by `(source address, sequence number)`. The sequence
//! number is the only field the kernel reliably echoes back, and it is unique
//! per in-flight probe. The ICMP identifier is intentionally **not** used:
//! for unprivileged datagram ping sockets the kernel assigns its own per-socket
//! identifier and overwrites the value the caller wrote, so matching on it
//! would discard valid replies.
//!
//! A late reply for a host already marked down in an earlier window is ignored
//! (the host is no longer in flight). This is an accepted limitation of the
//! bounded-batch design.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::network::Host;
use crate::scanner::icmp::{PingSocket, RecvResult};
use crate::scanner::{DiscoveryConfig, HostDiscovery, ScanError, ScanEvent};
use crate::target::ScanTarget;

/// Poll interval for the receive loop while waiting on a batch window.
const RECV_CHUNK: Duration = Duration::from_millis(50);

/// Resolves hosts by ICMP echo.
///
/// The unit type carries no per-instance state; all tunables are passed to
/// [`IcmpDiscovery::discover`] through [`DiscoveryConfig`]. It exists to satisfy
/// the [`HostDiscovery`] trait and leaves room for future per-instance options.
#[derive(Debug, Clone, Copy, Default)]
pub struct IcmpDiscovery;

impl HostDiscovery for IcmpDiscovery {
    fn discover(
        &self,
        target: &ScanTarget,
        config: &DiscoveryConfig,
        events: &Sender<ScanEvent>,
        cancel: &Arc<AtomicBool>,
    ) -> Result<(), ScanError> {
        // Enumerate every address up front (bounded by MAX_SUBNET_SIZE) so the
        // batch loop can index and count them.
        let addresses: Vec<Ipv4Addr> = target.iter().collect();
        let total = addresses.len() as u64;

        // Open the socket before announcing the scan so a socket failure is
        // reported as an error event instead of a half-started scan.
        let socket = match PingSocket::new() {
            Ok(socket) => socket,
            Err(e) => {
                let err = ScanError::Socket(e.to_string());
                let _ = events.send(ScanEvent::Error(err.clone()));
                return Err(err);
            }
        };
        let _ = events.send(ScanEvent::Started { total });

        let batch = config.concurrency.max(1);
        let mut completed: u64 = 0;

        for chunk in addresses.chunks(batch) {
            if cancel.load(Ordering::Relaxed) {
                let _ = events.send(ScanEvent::Cancelled);
                return Ok(());
            }

            // Send one echo request per address in the batch, remembering when
            // each was sent so replies can be timed.
            let window_start = Instant::now();
            let mut in_flight: HashMap<(Ipv4Addr, u16), Instant> =
                HashMap::with_capacity(chunk.len());
            for (i, addr) in chunk.iter().enumerate() {
                let seq = i as u16;
                if let Err(e) = socket.send(*addr, seq) {
                    // A send failure is a system error, not a normal network
                    // condition; it aborts the scan.
                    let _ = events.send(ScanEvent::Error(ScanError::Socket(e.to_string())));
                    return Err(ScanError::Socket(e.to_string()));
                }
                in_flight.insert((*addr, seq), Instant::now());
            }

            // Receive until the window closes, resolving hosts that reply.
            let deadline = window_start + config.timeout;
            loop {
                if cancel.load(Ordering::Relaxed) {
                    let _ = events.send(ScanEvent::Cancelled);
                    return Ok(());
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match socket.recv(remaining.min(RECV_CHUNK)) {
                    RecvResult::Reply { src, seq } => {
                        // A reply only matters if it matches a probe we sent in
                        // this batch; a late reply from an earlier batch is a
                        // no-op.
                        if let Some(sent_at) = in_flight.remove(&(src, seq)) {
                            let latency = Instant::now().saturating_duration_since(sent_at);
                            let _ = events.send(ScanEvent::HostDiscovered(Host::up(src, latency)));
                            completed += 1;
                            let _ = events.send(ScanEvent::Progress { completed, total });
                        }
                    }
                    // `recv` folds all receive errors into these two variants,
                    // so there is no separate error arm here.
                    RecvResult::Other | RecvResult::Timeout => {}
                }
            }

            // The window has closed: mark every host that never answered as
            // down, in sorted IP order so the output is deterministic.
            let mut down: Vec<Ipv4Addr> = in_flight.keys().map(|(ip, _)| *ip).collect();
            down.sort();
            for ip in down {
                let _ = events.send(ScanEvent::HostDiscovered(Host::down(ip)));
                completed += 1;
                let _ = events.send(ScanEvent::Progress { completed, total });
            }
        }

        let _ = events.send(ScanEvent::Finished);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::network::HostState;
    use std::sync::mpsc;

    /// Runs discovery against the loopback address and checks that it reports a
    /// single up host with a latency, in the expected event order.
    ///
    /// ICMP echo over an unprivileged datagram socket is not guaranteed on
    /// every platform (some sandboxes or hosts block it), so the test skips
    /// rather than failing when the socket cannot be opened.
    #[test]
    fn discovers_localhost() {
        let target = ScanTarget::Host(Ipv4Addr::LOCALHOST);
        let config = DiscoveryConfig::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();

        let result = IcmpDiscovery.discover(&target, &config, &tx, &cancel);
        drop(tx);

        // Skip in environments where ICMP is unavailable.
        assert!(
            result.is_ok(),
            "ICMP echo unavailable in this environment; skipping: {:?}",
            result.err()
        );

        let events: Vec<ScanEvent> = rx.try_iter().collect();
        assert_eq!(events.len(), 4, "unexpected event sequence: {events:?}");

        match &events[0] {
            ScanEvent::Started { total } => assert_eq!(*total, 1),
            other => panic!("expected Started, got {other:?}"),
        }
        match &events[1] {
            ScanEvent::HostDiscovered(host) => {
                assert_eq!(host.ip, Ipv4Addr::LOCALHOST);
                assert!(matches!(host.state, HostState::Up));
                assert!(host.latency.is_some(), "up host should carry a latency");
            }
            other => panic!("expected HostDiscovered, got {other:?}"),
        }
        match &events[2] {
            ScanEvent::Progress { completed, total } => {
                assert_eq!(*completed, 1);
                assert_eq!(*total, 1);
            }
            other => panic!("expected Progress, got {other:?}"),
        }
        assert!(matches!(&events[3], ScanEvent::Finished));
    }
}
