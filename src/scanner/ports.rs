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
use std::sync::Arc;
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

/// The number of worker threads to run for a port count and concurrency bound:
/// zero when there is no work, otherwise the concurrency clamped to the range
/// `[1, ports]`. Capping at the port count keeps a small selection from
/// over-spawning; the floor of one guards against a zero concurrency setting.
fn worker_count(concurrency: usize, ports: usize) -> usize {
    if ports == 0 {
        0
    } else {
        concurrency.max(1).min(ports)
    }
}

impl PortScanner for TcpPortScanner {
    fn scan(
        &self,
        ip: Ipv4Addr,
        config: &PortConfig,
        events: &Sender<ScanEvent>,
        cancel: &Arc<AtomicBool>,
    ) -> Result<(), ScanError> {
        // The ports to probe, in ascending order. `PortSpec` guarantees they
        // are sorted and unique, so the shared counter below walks a stable
        // list.
        let ports: Vec<Port> = config.ports.iter().collect();
        let workers = worker_count(config.concurrency, ports.len());
        if workers == 0 {
            // An empty port selection has nothing to probe.
            return Ok(());
        }

        // All workers share one `Arc` over the port list (cheap to clone per
        // worker even for a full scan) and one atomic counter of the next index
        // to claim.
        let ports = Arc::new(ports);
        let next = Arc::new(AtomicUsize::new(0));
        let timeout = config.timeout;

        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let ports = Arc::clone(&ports);
            let next = Arc::clone(&next);
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

        Ok(())
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
}
