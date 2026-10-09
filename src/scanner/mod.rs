//! Scanning engine.
//!
//! This module owns the scanner's event model and the discovery mechanisms
//! that produce it. It depends only on the structured network data models
//! (see the `network` module), never on the TUI, so the scanner can be used
//! and tested independently of terminal rendering.
//!
//! The scanner runs on a background thread and reports progress by sending
//! [`ScanEvent`]s to the TUI through a channel. Cancellation is signalled
//! out-of-band (see Phase 3 in `PLAN.md`).

use std::fmt;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SendError, Sender};
use std::sync::Arc;
use std::time::Duration;

use crate::network::{Host, Port, PortState};
use crate::ports::PortConfig;
use crate::target::ScanTarget;

/// ICMP echo (ping) primitives used by host discovery.
///
/// Kept private to the scanner module: it exposes only the low-level socket
/// mechanics, while the discovery layer decides how those probes are scheduled.
mod icmp;

/// Host discovery mechanisms built on the ICMP primitives above.
mod discovery;
// Re-exported so the discovery entry point is reachable as
// `scanner::IcmpDiscovery` from `main.rs`.
pub use discovery::IcmpDiscovery;

/// TCP port scanning for hosts found by discovery.
mod ports;
// Re-exported so the scanner entry point is reachable as
// `scanner::TcpPortScanner` from `main.rs`.
pub use ports::TcpPortScanner;

/// A structured message produced by the scanner as a scan progresses.
///
/// Events flow from the scanner (on a background thread) to the TUI through a
/// channel so results appear incrementally without blocking the UI thread. They
/// carry no TUI-specific types, which keeps the scanner decoupled from the
/// presentation layer.
#[derive(Debug)]
pub enum ScanEvent {
    /// A scan has started. `total` is the number of addresses that will be
    /// probed, used to drive the progress display.
    Started { total: u64 },
    /// A host has been resolved to a terminal state (up or down).
    HostDiscovered(Host),
    /// A TCP port has been probed and its state determined (open or closed).
    ///
    /// Emitted for every probed port so the TUI can update its view
    /// incrementally; the TUI stores only open ports on the host.
    PortDiscovered {
        /// The host the probed port belongs to.
        ip: Ipv4Addr,
        /// The probed port.
        port: Port,
        /// Whether the port is open or closed.
        state: PortState,
    },
    /// Progress update: `completed` hosts resolved out of `total`.
    Progress { completed: u64, total: u64 },
    /// The scan completed normally.
    Finished,
    /// The scan was cancelled by the user.
    Cancelled,
    /// A fatal error stopped the scan.
    Error(ScanError),
}

/// A fatal error that stops a scan.
///
/// Ordinary network conditions (a host not responding, a port refusing a
/// connection, a timeout) are not errors and never surface here; they are
/// represented by host/port state instead. Only conditions that prevent the
/// scan from continuing are reported as a [`ScanError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// A socket-level failure (creating the socket or sending a probe).
    Socket(String),
    /// A failure sending an event to the TUI, usually because the receiver was
    /// dropped (for example the TUI closed).
    Channel(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Socket(msg) => write!(f, "socket error: {msg}"),
            ScanError::Channel(msg) => write!(f, "channel error: {msg}"),
        }
    }
}

impl std::error::Error for ScanError {}

/// Allow `sender.send(event)?` in code that returns `Result<_, ScanError>`.
impl From<SendError<ScanEvent>> for ScanError {
    fn from(err: SendError<ScanEvent>) -> Self {
        ScanError::Channel(err.to_string())
    }
}

/// Tunables for a host-discovery run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryConfig {
    /// How long to wait for an ICMP reply before marking a host down.
    pub timeout: Duration,
    /// Maximum number of hosts probed concurrently.
    pub concurrency: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(300),
            concurrency: 128,
        }
    }
}

/// A mechanism for discovering which hosts in a target are up.
///
/// Implementations probe the target's addresses concurrently and report
/// results as [`ScanEvent`]s through the provided channel. Discovery is
/// blocking: the call returns once the target has been fully probed, the
/// scan was cancelled, or a fatal error occurred.
pub trait HostDiscovery {
    /// Probe `target`, reporting discovered hosts and progress through
    /// `events`.
    ///
    /// `cancel` is checked periodically; when set, discovery stops promptly
    /// without marking in-flight hosts down.
    fn discover(
        &self,
        target: &ScanTarget,
        config: &DiscoveryConfig,
        events: &Sender<ScanEvent>,
        cancel: &Arc<AtomicBool>,
    ) -> Result<(), ScanError>;
}

/// A mechanism for probing the TCP ports of a single host.
///
/// Implementations connect to every configured port concurrently (bounded by
/// [`PortConfig::concurrency`]) and report the state of each probed port as a
/// [`ScanEvent::PortDiscovered`] through the provided channel. Scanning is
/// blocking: the call returns once every port has been probed or the scan was
/// cancelled.
///
/// Unlike [`HostDiscovery`], this trait does not emit [`ScanEvent::Started`]
/// or [`ScanEvent::Finished`]; a whole scan (discovery plus ports) is framed by
/// a single pair of those events, owned by the orchestrating scan (see Phase 4
/// in `PLAN.md`).
pub trait PortScanner {
    /// Probe the configured ports on `ip`, reporting each result through
    /// `events`.
    ///
    /// `cancel` is checked before each new connection is started; when set, no
    /// further ports are probed (in-flight connections are allowed to finish).
    fn scan(
        &self,
        ip: Ipv4Addr,
        config: &PortConfig,
        events: &Sender<ScanEvent>,
        cancel: &Arc<AtomicBool>,
    ) -> Result<(), ScanError>;
}

/// Run a full scan of `target`: discover which hosts are up, then port-scan
/// every host that comes up.
///
/// This is the orchestrating entry point for a whole scan. A single run is
/// framed by exactly one [`ScanEvent::Started`] / [`ScanEvent::Finished`] pair;
/// discovery and port scanning stream their intermediate events
/// ([`ScanEvent::HostDiscovered`], [`ScanEvent::Progress`],
/// [`ScanEvent::PortDiscovered`]) inside that frame.
///
/// `discovery` tunes the ICMP probe stage and `ports` tunes the TCP port stage.
///
/// Cancellation is cooperative: when `cancel` is set, discovery stops (and
/// reports [`ScanEvent::Cancelled`]) and no further hosts are port-scanned;
/// in-flight connections are allowed to finish. Both normal completion and
/// cancellation return `Ok(())` — only a fatal error returns `Err`.
pub fn run_scan(
    target: &ScanTarget,
    discovery: &DiscoveryConfig,
    ports: &PortConfig,
    events: &Sender<ScanEvent>,
    cancel: &Arc<AtomicBool>,
) -> Result<(), ScanError> {
    // Enumerate every address up front (bounded by MAX_SUBNET_SIZE) so the
    // progress display has a stable total.
    let addresses: Vec<Ipv4Addr> = target.iter().collect();
    let total = addresses.len() as u64;

    // Open the socket before announcing the scan so a socket failure is
    // reported as an error event instead of a half-started scan.
    let socket = match icmp::PingSocket::new() {
        Ok(socket) => socket,
        Err(e) => {
            let err = ScanError::Socket(e.to_string());
            let _ = events.send(ScanEvent::Error(err.clone()));
            return Err(err);
        }
    };
    let _ = events.send(ScanEvent::Started { total });

    match discovery::sweep(&socket, &addresses, discovery, events, cancel)? {
        discovery::SweepOutcome::Completed(up_hosts) => {
            // Port-scan every host that came up. Cancellation is checked before
            // starting each host so a cancelled scan stops scheduling new work.
            for host in &up_hosts {
                if cancel.load(Ordering::Relaxed) {
                    let _ = events.send(ScanEvent::Cancelled);
                    return Ok(());
                }
                if let Err(err) = TcpPortScanner.scan(host.ip, ports, events, cancel) {
                    let _ = events.send(ScanEvent::Error(err.clone()));
                    return Err(err);
                }
            }
            // The last host's scan may have started before cancellation was
            // requested; if so, report it rather than finishing normally.
            if cancel.load(Ordering::Relaxed) {
                let _ = events.send(ScanEvent::Cancelled);
            } else {
                let _ = events.send(ScanEvent::Finished);
            }
        }
        // The sweep already emitted Cancelled; nothing further to report.
        discovery::SweepOutcome::Cancelled => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn events_carry_their_payload() {
        let started = ScanEvent::Started { total: 256 };
        let total = match started {
            ScanEvent::Started { total } => total,
            other => panic!("expected Started, got {other:?}"),
        };
        assert_eq!(total, 256);

        let host = Host::up(Ipv4Addr::new(10, 0, 0, 1), Duration::from_millis(5));
        let discovered = ScanEvent::HostDiscovered(host);
        let found = match discovered {
            ScanEvent::HostDiscovered(found) => found,
            other => panic!("expected HostDiscovered, got {other:?}"),
        };
        assert_eq!(found.ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(found.latency, Some(Duration::from_millis(5)));

        let progress = ScanEvent::Progress {
            completed: 3,
            total: 256,
        };
        let (completed, total) = match progress {
            ScanEvent::Progress { completed, total } => (completed, total),
            other => panic!("expected Progress, got {other:?}"),
        };
        assert_eq!(completed, 3);
        assert_eq!(total, 256);

        assert!(matches!(ScanEvent::Finished, ScanEvent::Finished));
        assert!(matches!(ScanEvent::Cancelled, ScanEvent::Cancelled));

        let error = ScanEvent::Error(ScanError::Socket("boom".to_string()));
        let cause = match error {
            ScanEvent::Error(cause) => cause,
            other => panic!("expected Error, got {other:?}"),
        };
        assert_eq!(cause, ScanError::Socket("boom".to_string()));
    }

    #[test]
    fn error_display_is_descriptive() {
        let socket = ScanError::Socket("cannot open socket".to_string());
        assert_eq!(socket.to_string(), "socket error: cannot open socket");

        let channel = ScanError::Channel("channel closed".to_string());
        assert_eq!(channel.to_string(), "channel error: channel closed");
    }

    #[test]
    fn send_error_converts_to_channel_error() {
        use std::sync::mpsc;
        let (tx, rx) = mpsc::channel::<ScanEvent>();
        drop(rx);
        let err = tx.send(ScanEvent::Finished).unwrap_err();
        let scan_error = ScanError::from(err);
        assert!(matches!(scan_error, ScanError::Channel(_)));
    }

    #[test]
    fn default_discovery_config() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.timeout, Duration::from_millis(300));
        assert_eq!(config.concurrency, 128);
    }

    /// Runs a full scan against loopback and checks that the whole run — host
    /// discovery plus port scanning — is framed by exactly one `Started` /
    /// `Finished` pair, with the host reported up and every probed port
    /// reported inside that frame.
    ///
    /// ICMP echo over an unprivileged datagram socket is not guaranteed on
    /// every platform, so the test skips rather than failing when the socket
    /// cannot be opened.
    #[test]
    fn run_scan_frames_the_whole_run_with_one_started_and_finished() {
        use std::net::TcpListener;
        use std::sync::mpsc;

        use crate::network::HostState;
        use crate::ports::PortSpec;

        // Bind a real listener on loopback for a guaranteed-open port and derive
        // a guaranteed-closed port the same way the port-scan test does.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let open_port = listener.local_addr().expect("listener address").port();
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
        let closed_port = probe.local_addr().expect("probe address").port();
        drop(probe);

        let target = ScanTarget::Host(Ipv4Addr::LOCALHOST);
        let discovery = DiscoveryConfig::default();
        let ports = PortConfig {
            ports: PortSpec::from_port_numbers([open_port, closed_port]),
            timeout: Duration::from_millis(500),
            concurrency: 4,
        };

        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let result = run_scan(&target, &discovery, &ports, &tx, &cancel);
        drop(tx);

        // Skip in environments where ICMP is unavailable.
        assert!(
            result.is_ok(),
            "ICMP echo unavailable in this environment; skipping: {:?}",
            result.err()
        );

        let events: Vec<ScanEvent> = rx.try_iter().collect();

        // Exactly one Started and one Finished, framing the whole run.
        let started = events
            .iter()
            .filter(|e| matches!(e, ScanEvent::Started { .. }))
            .count();
        let finished = events
            .iter()
            .filter(|e| matches!(e, ScanEvent::Finished))
            .count();
        assert_eq!(started, 1, "expected exactly one Started: {events:?}");
        assert_eq!(finished, 1, "expected exactly one Finished: {events:?}");

        // The frame opens with Started and closes with Finished.
        match &events.first() {
            Some(ScanEvent::Started { total }) => assert_eq!(*total, 1),
            other => panic!("expected Started first, got {other:?}"),
        }
        assert!(
            matches!(events.last(), Some(ScanEvent::Finished)),
            "expected Finished last: {events:?}"
        );

        // The loopback host is discovered up, inside the frame.
        let host_up = events.iter().any(|e| match e {
            ScanEvent::HostDiscovered(h) => {
                h.ip == Ipv4Addr::LOCALHOST && matches!(h.state, HostState::Up)
            }
            _ => false,
        });
        assert!(host_up, "expected loopback host reported up: {events:?}");

        // Every probed port is reported inside the frame.
        let port_events = events
            .iter()
            .filter(|e| matches!(e, ScanEvent::PortDiscovered { .. }))
            .count();
        assert_eq!(
            port_events, 2,
            "expected one event per probed port: {events:?}"
        );
    }
}
