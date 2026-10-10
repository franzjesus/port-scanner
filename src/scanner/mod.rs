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

use crate::network::{Host, Port, PortState, ServiceInfo};
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
// Re-exported so the discovery outcome is reachable as
// `scanner::DiscoveryOutcome`.
pub use discovery::DiscoveryOutcome;

/// TCP port scanning for hosts found by discovery.
mod ports;
// Re-exported so the scanner entry point is reachable as
// `scanner::TcpPortScanner` from `main.rs`.
pub use ports::TcpPortScanner;

/// Service detection for open ports (HTTP, HTTPS, SSH banners).
mod services;
// Used by [`run_scan`] to accept the detector set; the trait itself stays
// reachable as `scanner::services::ServiceDetector`.
use services::ServiceDetector;
// Re-exported so `main.rs` can build the default detector set for a scan.
pub use services::default_detectors;

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
    /// A service listening on an open port was identified.
    ///
    /// Emitted after a port is found open and a detector recognizes the
    /// service on it; the TUI attaches it to the host's probed-port record.
    /// Ports with no recognized service produce no event.
    ServiceDiscovered {
        /// The host the service was detected on.
        ip: Ipv4Addr,
        /// The port the service is listening on.
        port: Port,
        /// The identified service.
        service: ServiceInfo,
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

/// The complete configuration for a full scan: what to scan and how each stage
/// behaves.
///
/// A [`ScanConfig`] is the single object that describes a scan and is usable
/// without the TUI (see Phase 5 in `PLAN.md`). It bundles the target with the
/// per-stage tunables: [`DiscoveryConfig`] tunes the host-discovery stage and
/// [`PortConfig`] tunes the TCP port stage.
///
/// Timeout and concurrency are owned per stage rather than held globally, so
/// this struct deliberately has no top-level `timeout` or `concurrency`: the
/// discovery stage reads [`DiscoveryConfig::timeout`] /
/// [`DiscoveryConfig::concurrency`] and the port stage reads
/// [`PortConfig::timeout`] / [`PortConfig::concurrency`]. A single global value
/// would duplicate the per-stage state and be ambiguous (see the Phase 5 note
/// in `PLAN.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanConfig {
    /// What to scan: a single host or a subnet.
    pub target: ScanTarget,
    /// Tunables for the host-discovery stage.
    pub discovery: DiscoveryConfig,
    /// Tunables for the TCP port stage.
    pub ports: PortConfig,
    /// Whether to attempt service detection on open ports after the port
    /// stage. Enabled by default; can be turned off with the
    /// `--no-services` CLI flag.
    pub detect_services: bool,
}

/// Builds and runs one scan in a background thread.
///
/// The closure receives the scan configuration, the sender used to deliver
/// structured [`ScanEvent`]s, and the cancellation flag shared with the TUI.
/// Keeping the spawn logic behind a trait object lets the TUI start, cancel,
/// and rescan without knowing how scans are actually launched, which makes the
/// full lifecycle testable without touching the network.
pub type ScanSpawner = Box<
    dyn Fn(
            ScanConfig,
            std::sync::mpsc::Sender<ScanEvent>,
            std::sync::Arc<std::sync::atomic::AtomicBool>,
        ) + Send,
>;

impl ScanConfig {
    /// Create a configuration for `target` using the default discovery and
    /// port settings, with service detection enabled.
    pub fn new(target: ScanTarget) -> Self {
        Self {
            target,
            discovery: DiscoveryConfig::default(),
            ports: PortConfig::default(),
            detect_services: true,
        }
    }
}

/// A mechanism for discovering which hosts in a target are up.
///
/// Implementations probe the target's addresses concurrently and report
/// results as [`ScanEvent`]s through the provided channel. Discovery is
/// blocking: the call returns once the target has been fully probed, the
/// scan was cancelled, or a fatal error occurred.
///
/// `discover` is the unframed core of a scan: it emits
/// [`ScanEvent::HostDiscovered`], [`ScanEvent::Progress`], and (on
/// cancellation) [`ScanEvent::Cancelled`], but not [`ScanEvent::Started`] or
/// [`ScanEvent::Finished`]. A whole run is framed by a single pair of those
/// events, owned by the orchestrating [`run_scan`] (see Phase 4 in `PLAN.md`).
pub trait HostDiscovery {
    /// Probe `target`, reporting discovered hosts and progress through
    /// `events`.
    ///
    /// `cancel` is checked periodically; when set, discovery stops promptly
    /// without marking in-flight hosts down.
    ///
    /// Returns an error only for hard failures (e.g. the socket could not be
    /// opened); normal network conditions (timeouts, no responses) are not
    /// errors. On success the returned [`DiscoveryOutcome`] carries the up
    /// hosts (or `Cancelled` if cancellation was requested), so the
    /// orchestrator can drive port scanning without re-deriving the host list
    /// from the event stream.
    fn discover(
        &self,
        target: &ScanTarget,
        config: &DiscoveryConfig,
        events: &Sender<ScanEvent>,
        cancel: &Arc<AtomicBool>,
    ) -> Result<DiscoveryOutcome, ScanError>;
}

/// A mechanism for probing the TCP ports of a single host.
///
/// Implementations connect to every configured port concurrently (bounded by
/// [`PortConfig::concurrency`]) and report the state of each probed port as a
/// [`ScanEvent::PortDiscovered`] through the provided channel. Scanning is
/// blocking: the call returns once every port has been probed or the scan was
/// cancelled.
///
/// The returned `Vec<Port>` is the list of ports that were found **open**, in
/// ascending order. The orchestrator uses it to drive service detection without
/// re-deriving the open set from the event stream.
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
    ///
    /// Returns the ports that came up open, sorted ascending, so the caller can
    /// probe their services without re-scanning.
    fn scan(
        &self,
        ip: Ipv4Addr,
        config: &PortConfig,
        events: &Sender<ScanEvent>,
        cancel: &Arc<AtomicBool>,
    ) -> Result<Vec<Port>, ScanError>;
}

/// Run a full scan of `target`: discover which hosts are up, port-scan every
/// host that comes up, and (when enabled) detect the service on each open port.
///
/// This is the orchestrating entry point for a whole scan. A single run is
/// framed by exactly one [`ScanEvent::Started`] / [`ScanEvent::Finished`] (or
/// [`ScanEvent::Cancelled`]) pair; the discovery, port-scanning, and
/// service-detection stages stream their intermediate events
/// ([`ScanEvent::HostDiscovered`], [`ScanEvent::Progress`],
/// [`ScanEvent::PortDiscovered`], [`ScanEvent::ServiceDiscovered`]) inside
/// that frame.
///
/// The discovery, port-scanning, and service-detection mechanisms are supplied
/// as traits so this orchestrator stays independent of any concrete
/// implementation. `config` carries the target and the per-stage tunables
/// (see [`ScanConfig`]).
///
/// Service detection runs only when [`ScanConfig::detect_services`] is set and
/// `detectors` is non-empty; it probes each open port in turn and stops at the
/// first detector that recognizes the service. A detector failure never fails
/// the scan: the failed detector is skipped and the next one is tried.
///
/// Cancellation is cooperative: when `cancel` is set, discovery stops (and
/// reports [`ScanEvent::Cancelled`]) and no further hosts are port-scanned or
/// service-probed; in-flight connections are allowed to finish. Both normal
/// completion and cancellation return `Ok(())` — only a fatal error returns
/// `Err`.
pub fn run_scan<D: HostDiscovery, P: PortScanner>(
    config: &ScanConfig,
    discovery: &D,
    port_scanner: &P,
    detectors: &[Box<dyn ServiceDetector>],
    events: &Sender<ScanEvent>,
    cancel: &Arc<AtomicBool>,
) -> Result<(), ScanError> {
    // Count the addresses (bounded by MAX_SUBNET_SIZE) so the progress display
    // has a stable total; the discovery stage enumerates them itself.
    let total = config.target.iter().count() as u64;

    let _ = events.send(ScanEvent::Started { total });

    match discovery.discover(&config.target, &config.discovery, events, cancel)? {
        DiscoveryOutcome::Completed(up_hosts) => {
            // Port-scan every host that came up. Cancellation is checked before
            // starting each host so a cancelled scan stops scheduling new work.
            for host in &up_hosts {
                if cancel.load(Ordering::Relaxed) {
                    let _ = events.send(ScanEvent::Cancelled);
                    return Ok(());
                }
                let open_ports = match port_scanner.scan(host.ip, &config.ports, events, cancel) {
                    Ok(open_ports) => open_ports,
                    Err(err) => {
                        let _ = events.send(ScanEvent::Error(err.clone()));
                        return Err(err);
                    }
                };
                // Service detection on the ports that came up open. Skipped
                // entirely when disabled or when no detectors are configured.
                // Cancellation is checked before each new probe so a cancelled
                // scan stops scheduling further probes.
                if config.detect_services && !detectors.is_empty() {
                    for &port in &open_ports {
                        if cancel.load(Ordering::Relaxed) {
                            break;
                        }
                        for detector in detectors {
                            // First recognition wins for this port. Anything
                            // else (no match, or a probe failure) falls
                            // through to the next detector.
                            if let Ok(Some(service)) = detector.detect(host.ip, port) {
                                let _ = events.send(ScanEvent::ServiceDiscovered {
                                    ip: host.ip,
                                    port,
                                    service,
                                });
                                break;
                            }
                        }
                    }
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
        // Discovery already emitted Cancelled; nothing further to report.
        DiscoveryOutcome::Cancelled => {}
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

    #[test]
    fn scan_config_new_keeps_target_and_uses_default_stages() {
        let target = ScanTarget::Host(Ipv4Addr::LOCALHOST);
        let config = ScanConfig::new(target);
        assert_eq!(config.target, ScanTarget::Host(Ipv4Addr::LOCALHOST));
        assert_eq!(config.discovery, DiscoveryConfig::default());
        assert_eq!(config.ports, PortConfig::default());
        assert!(config.detect_services, "service detection is on by default");
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

        let config = ScanConfig {
            target: ScanTarget::Host(Ipv4Addr::LOCALHOST),
            discovery: DiscoveryConfig::default(),
            ports: PortConfig {
                ports: PortSpec::from_port_numbers([open_port, closed_port]),
                timeout: Duration::from_millis(500),
                concurrency: 4,
            },
            // Service detection stays off: this test only checks the scan
            // framing, and empty detectors would make detection a no-op anyway.
            detect_services: false,
        };

        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let result = run_scan(&config, &IcmpDiscovery, &TcpPortScanner, &[], &tx, &cancel);
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

    // --- Hermetic fakes for the service-detection orchestration -----------

    /// A [`HostDiscovery`] that reports the target's address as a single up
    /// host without touching the network, so the orchestrator can be tested
    /// independently of ICMP availability.
    struct FakeDiscovery;

    impl HostDiscovery for FakeDiscovery {
        fn discover(
            &self,
            target: &ScanTarget,
            _config: &DiscoveryConfig,
            events: &Sender<ScanEvent>,
            _cancel: &Arc<AtomicBool>,
        ) -> Result<DiscoveryOutcome, ScanError> {
            let ip = match target {
                ScanTarget::Host(ip) => *ip,
                ScanTarget::Subnet(net) => net.network(),
            };
            let host = Host::up(ip, Duration::from_millis(1));
            let _ = events.send(ScanEvent::HostDiscovered(host.clone()));
            let _ = events.send(ScanEvent::Progress {
                completed: 1,
                total: 1,
            });
            Ok(DiscoveryOutcome::Completed(vec![host]))
        }
    }

    /// A [`PortScanner`] that reports fixed open (80, 22) and closed (23)
    /// ports without touching the network.
    struct FakePortScanner;

    impl PortScanner for FakePortScanner {
        fn scan(
            &self,
            ip: Ipv4Addr,
            _config: &PortConfig,
            events: &Sender<ScanEvent>,
            _cancel: &Arc<AtomicBool>,
        ) -> Result<Vec<Port>, ScanError> {
            let open = [Port::new(80).unwrap(), Port::new(22).unwrap()];
            for port in open {
                let _ = events.send(ScanEvent::PortDiscovered {
                    ip,
                    port,
                    state: PortState::Open,
                });
            }
            let closed = Port::new(23).unwrap();
            let _ = events.send(ScanEvent::PortDiscovered {
                ip,
                port: closed,
                state: PortState::Closed,
            });
            Ok(open.to_vec())
        }
    }

    /// A [`ServiceDetector`] that recognizes one port with a fixed service
    /// name and nothing else.
    struct RecognizingDetector {
        port: Port,
        name: &'static str,
    }

    impl ServiceDetector for RecognizingDetector {
        fn detect(
            &self,
            _ip: Ipv4Addr,
            port: Port,
        ) -> Result<Option<ServiceInfo>, super::services::ServiceError> {
            if port == self.port {
                Ok(Some(ServiceInfo::new(self.name)))
            } else {
                Ok(None)
            }
        }
    }

    /// A [`ServiceDetector`] that never recognizes a service.
    struct NoMatchDetector;

    impl ServiceDetector for NoMatchDetector {
        fn detect(
            &self,
            _ip: Ipv4Addr,
            _port: Port,
        ) -> Result<Option<ServiceInfo>, super::services::ServiceError> {
            Ok(None)
        }
    }

    /// A [`ServiceDetector`] that always fails; the orchestrator must skip it
    /// without failing the scan.
    struct FailingDetector;

    impl ServiceDetector for FailingDetector {
        fn detect(
            &self,
            _ip: Ipv4Addr,
            _port: Port,
        ) -> Result<Option<ServiceInfo>, super::services::ServiceError> {
            Err(super::services::ServiceError::Io(
                "forced failure".to_string(),
            ))
        }
    }

    /// Runs the orchestrator against the hermetic fakes and returns the
    /// result plus every event that was produced.
    fn run_fake_scan(
        detect_services: bool,
        detectors: Vec<Box<dyn ServiceDetector>>,
    ) -> (Result<(), ScanError>, Vec<ScanEvent>) {
        use std::sync::mpsc;

        let config = ScanConfig {
            target: ScanTarget::Host(Ipv4Addr::LOCALHOST),
            discovery: DiscoveryConfig::default(),
            ports: PortConfig::default(),
            detect_services,
        };
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let result = run_scan(
            &config,
            &FakeDiscovery,
            &FakePortScanner,
            &detectors,
            &tx,
            &cancel,
        );
        drop(tx);
        (result, rx.try_iter().collect())
    }

    /// Collects the `(port, service)` pairs from `ServiceDiscovered` events.
    fn service_events(events: &[ScanEvent]) -> Vec<(Port, ServiceInfo)> {
        events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::ServiceDiscovered { port, service, .. } => {
                    Some((*port, service.clone()))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn run_scan_detects_services_on_open_ports_when_enabled() {
        let detectors: Vec<Box<dyn ServiceDetector>> = vec![Box::new(RecognizingDetector {
            port: Port::new(80).unwrap(),
            name: "http",
        })];
        let (result, events) = run_fake_scan(true, detectors);
        assert!(result.is_ok(), "scan must succeed: {result:?}");

        // Only the open port the detector recognizes gets a service; the
        // other open port (22) and the closed port (23) do not.
        let services = service_events(&events);
        assert_eq!(services.len(), 1, "events: {events:?}");
        assert_eq!(services[0].0, Port::new(80).unwrap());
        assert_eq!(services[0].1.name, "http");

        assert!(
            matches!(events.last(), Some(ScanEvent::Finished)),
            "scan still finishes: {events:?}"
        );
    }

    #[test]
    fn run_scan_skips_service_detection_when_disabled() {
        let detectors: Vec<Box<dyn ServiceDetector>> = vec![Box::new(RecognizingDetector {
            port: Port::new(80).unwrap(),
            name: "http",
        })];
        let (result, events) = run_fake_scan(false, detectors);
        assert!(result.is_ok(), "scan must succeed: {result:?}");
        assert!(
            service_events(&events).is_empty(),
            "detection must not run when disabled: {events:?}"
        );
    }

    #[test]
    fn run_scan_skips_service_detection_without_detectors() {
        let (result, events) = run_fake_scan(true, vec![]);
        assert!(result.is_ok(), "scan must succeed: {result:?}");
        assert!(
            service_events(&events).is_empty(),
            "no detectors means no detection: {events:?}"
        );
    }

    #[test]
    fn run_scan_first_recognizing_detector_wins() {
        let detectors: Vec<Box<dyn ServiceDetector>> = vec![
            Box::new(RecognizingDetector {
                port: Port::new(80).unwrap(),
                name: "alpha",
            }),
            Box::new(RecognizingDetector {
                port: Port::new(80).unwrap(),
                name: "beta",
            }),
        ];
        let (result, events) = run_fake_scan(true, detectors);
        assert!(result.is_ok(), "scan must succeed: {result:?}");

        let services = service_events(&events);
        assert_eq!(services.len(), 1, "one service per port: {events:?}");
        assert_eq!(services[0].1.name, "alpha", "first recognizer wins");
    }

    #[test]
    fn run_scan_detector_failure_is_skipped_not_fatal() {
        let detectors: Vec<Box<dyn ServiceDetector>> = vec![
            Box::new(FailingDetector),
            Box::new(RecognizingDetector {
                port: Port::new(80).unwrap(),
                name: "http",
            }),
        ];
        let (result, events) = run_fake_scan(true, detectors);
        assert!(
            result.is_ok(),
            "a detector failure must not fail the scan: {result:?}"
        );

        // The failing detector is skipped and the next one still reports.
        let services = service_events(&events);
        assert_eq!(services.len(), 1, "events: {events:?}");
        assert_eq!(services[0].1.name, "http");

        // A detector failure is not a scan error.
        assert!(
            !events.iter().any(|e| matches!(e, ScanEvent::Error(_))),
            "no Error event expected: {events:?}"
        );
    }

    #[test]
    fn run_scan_no_service_when_no_detector_recognizes() {
        let detectors: Vec<Box<dyn ServiceDetector>> =
            vec![Box::new(NoMatchDetector), Box::new(FailingDetector)];
        let (result, events) = run_fake_scan(true, detectors);
        assert!(result.is_ok(), "scan must succeed: {result:?}");
        assert!(
            service_events(&events).is_empty(),
            "no recognition means no service: {events:?}"
        );
        assert!(
            matches!(events.last(), Some(ScanEvent::Finished)),
            "scan still finishes: {events:?}"
        );
    }
}
