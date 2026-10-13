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
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SendError, Sender};
use std::sync::Arc;
use std::time::Duration;

use crate::network::{Host, MacAddress, Port, PortState, ServiceInfo};
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

/// TCP-based host discovery, used when an ICMP socket cannot be opened.
mod tcp_discovery;

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

/// Host enrichment: hostname (reverse DNS), MAC (ARP table), vendor (OUI).
mod enrichment;
// Used by [`run_scan`] to accept the enricher set; the trait itself stays
// reachable as `scanner::enrichment::HostEnricher`.
use enrichment::HostEnricher;
// Used by [`run_scan`] to merge per-host enricher contributions.
use enrichment::HostEnrichment;
// Used by [`run_scan`] to derive the vendor from a discovered MAC.
use enrichment::vendor_for;
// Re-exported so `main.rs` can build the default enricher set for a scan.
pub use enrichment::default_enrichers;

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
    /// Host enrichment data was discovered for a host.
    ///
    /// Emitted after the host's port scan, once the enrichment stage has
    /// contributed at least one field. Only the fields that were actually
    /// discovered are set; the TUI attaches them to the host.
    HostEnriched {
        /// The host the enrichment was discovered for.
        ip: Ipv4Addr,
        /// Reverse-DNS hostname, if one resolved.
        hostname: Option<String>,
        /// MAC address read from the ARP table, if present.
        mac: Option<MacAddress>,
        /// Vendor inferred from the MAC's OUI, if known.
        vendor: Option<String>,
    },
    /// Progress update: `completed` hosts resolved out of `total`.
    Progress { completed: u64, total: u64 },
    /// A non-fatal warning about the scan in progress.
    ///
    /// Emitted when the scanner recovers from a degraded condition, for
    /// example falling back from ICMP to TCP discovery because the ICMP socket
    /// could not be opened. Unlike [`ScanEvent::Error`], a warning does not
    /// stop the scan; the TUI displays it and clears it when the next scan
    /// starts.
    Warning(String),
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
#[derive(Debug, Clone)]
pub enum ScanError {
    /// A socket-level failure (creating the socket or sending a probe).
    ///
    /// The raw OS error code and message are stored separately (rather than the
    /// full [`std::io::Error`]) so the error stays `Clone`: the scan
    /// orchestrator re-emits a terminal error on the event stream *and* returns
    /// it, which needs two copies.
    Socket {
        /// The raw OS error code when the failure carried one. `EACCES` and
        /// `EPERM` mark an ICMP permission denial, which is recoverable by
        /// falling back to TCP port probing.
        raw_os_error: Option<i32>,
        /// The human-readable description of the socket failure.
        message: String,
    },
    /// A failure sending an event to the TUI, usually because the receiver was
    /// dropped (for example the TUI closed).
    Channel(String),
}

impl ScanError {
    /// Whether this error is a permission failure on the socket.
    ///
    /// An unprivileged ICMP datagram socket fails with `EACCES` when the
    /// process group is outside the kernel's `net.ipv4.ping_group_range`, and
    /// with `EPERM` in the raw-socket case. Both mean ICMP is unavailable on
    /// this system rather than a transient network condition, so the scanner
    /// can degrade to TCP port probing instead of aborting the scan.
    pub fn is_permission_denied(&self) -> bool {
        match self {
            ScanError::Socket { raw_os_error, .. } => {
                matches!(raw_os_error, Some(libc::EPERM) | Some(libc::EACCES))
            }
            ScanError::Channel(_) => false,
        }
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Socket { message, .. } => write!(f, "socket error: {message}"),
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

/// Wrap a socket [`std::io::Error`], preserving the raw OS code (when present)
/// so a permission denial can be detected later and the message kept for
/// display. This is what lets discovery stages write `socket.send(..)?` and
/// `PingSocket::new()?` directly in functions returning `Result<_, ScanError>`.
impl From<std::io::Error> for ScanError {
    fn from(err: std::io::Error) -> Self {
        ScanError::Socket {
            raw_os_error: err.raw_os_error(),
            message: err.to_string(),
        }
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
    /// The strategy used to resolve which hosts are up. Defaults to
    /// [`Discovery::Auto`]; selectable with the `--discovery` CLI flag.
    pub discovery_strategy: Discovery,
    /// Tunables for the host-discovery stage.
    pub discovery: DiscoveryConfig,
    /// Tunables for the TCP port stage.
    pub ports: PortConfig,
    /// Whether to attempt service detection on open ports after the port
    /// stage. Enabled by default; can be turned off with the
    /// `--no-services` CLI flag.
    pub detect_services: bool,
    /// Whether to enrich up hosts with hostname, MAC, and vendor data after
    /// their port scan. Enabled by default; can be turned off with the
    /// `--no-enrichment` CLI flag.
    pub enrich: bool,
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
    /// port settings, with service detection and host enrichment enabled.
    pub fn new(target: ScanTarget) -> Self {
        Self {
            target,
            discovery_strategy: Discovery::default(),
            discovery: DiscoveryConfig::default(),
            ports: PortConfig::default(),
            detect_services: true,
            enrich: true,
        }
    }
}

/// The host-discovery strategy used for a scan.
///
/// This is the single selection point for how a scan resolves which of the
/// target's hosts are up. [`Discovery::Auto`] is the default: it tries ICMP
/// echo first and, whenever ICMP is unavailable — the socket cannot be opened
/// or a probe is denied (for example the kernel rejects an unprivileged ICMP
/// datagram socket with `EACCES`) — emits a [`ScanEvent::Warning`] and falls
/// back to TCP port probing so the scan remains usable instead of failing.
/// [`Discovery::Icmp`] likewise falls back to TCP when ICMP is denied by
/// permission, but treats any other ICMP failure as a scan error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Discovery {
    /// Try ICMP echo first; fall back to TCP port probing (with a
    /// [`ScanEvent::Warning`]) whenever ICMP is unavailable.
    #[default]
    Auto,
    /// Resolve hosts with ICMP echo. A permission failure falls back to TCP
    /// port probing (with a [`ScanEvent::Warning`]); any other ICMP failure
    /// is a scan error.
    Icmp,
    /// Resolve hosts by probing a small fixed set of TCP ports.
    Tcp,
}

/// Error produced when a `--discovery` value cannot be parsed into a
/// [`Discovery`] strategy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// The given string is not one of `auto`, `icmp`, or `tcp`.
    UnknownStrategy {
        /// The offending input, for the error message.
        input: String,
    },
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::UnknownStrategy { input } => write!(
                f,
                "unknown discovery strategy {input:?}; expected one of: auto, icmp, tcp"
            ),
        }
    }
}

impl std::error::Error for DiscoveryError {}

impl FromStr for Discovery {
    type Err = DiscoveryError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "auto" => Ok(Discovery::Auto),
            "icmp" => Ok(Discovery::Icmp),
            "tcp" => Ok(Discovery::Tcp),
            other => Err(DiscoveryError::UnknownStrategy {
                input: other.to_string(),
            }),
        }
    }
}

impl HostDiscovery for Discovery {
    fn discover(
        &self,
        target: &ScanTarget,
        config: &DiscoveryConfig,
        events: &Sender<ScanEvent>,
        cancel: &Arc<AtomicBool>,
    ) -> Result<DiscoveryOutcome, ScanError> {
        match self {
            Discovery::Icmp => match IcmpDiscovery.discover(target, config, events, cancel) {
                Ok(outcome) => Ok(outcome),
                // ICMP was denied by permission (for example an unprivileged
                // ICMP datagram socket rejected with EACCES): warn and fall
                // back to TCP port probing so the scan stays usable.
                Err(err) if err.is_permission_denied() => {
                    let _ = events.send(ScanEvent::Warning(icmp_fallback_warning(&err)));
                    tcp_discovery::TcpDiscovery.discover(target, config, events, cancel)
                }
                // Any other ICMP failure is a genuine scan error and
                // propagates to the orchestrator.
                Err(err) => Err(err),
            },
            Discovery::Tcp => tcp_discovery::TcpDiscovery.discover(target, config, events, cancel),
            // Try ICMP first; whenever it is unavailable — the socket cannot
            // be opened or a probe is denied — warn and fall back to TCP port
            // probing so the scan stays usable.
            Discovery::Auto => match IcmpDiscovery.discover(target, config, events, cancel) {
                Ok(outcome) => Ok(outcome),
                Err(err) => {
                    let _ = events.send(ScanEvent::Warning(icmp_fallback_warning(&err)));
                    tcp_discovery::TcpDiscovery.discover(target, config, events, cancel)
                }
            },
        }
    }
}

/// Build the [`ScanEvent::Warning`] shown when ICMP discovery is unavailable
/// and the scan falls back to TCP port probing.
///
/// A permission denial is the common, expected case: the message names the
/// cause and offers the concrete fixes (run as root, grant `CAP_NET_RAW`, or
/// widen `net.ipv4.ping_group_range`). Any other failure is reported with its
/// underlying socket error.
fn icmp_fallback_warning(err: &ScanError) -> String {
    if err.is_permission_denied() {
        "ICMP unavailable (permission denied); falling back to TCP port probing. \
         Fix: run as root, grant CAP_NET_RAW, or widen net.ipv4.ping_group_range."
            .to_string()
    } else {
        format!("ICMP unavailable ({err}); falling back to TCP port probing")
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
/// host that comes up, and (when enabled) detect the service on each open port
/// and enrich each host with hostname, MAC, and vendor data.
///
/// This is the orchestrating entry point for a whole scan. A single run is
/// framed by exactly one [`ScanEvent::Started`] / [`ScanEvent::Finished`] (or
/// [`ScanEvent::Cancelled`]) pair; the discovery, port-scanning,
/// service-detection, and enrichment stages stream their intermediate events
/// ([`ScanEvent::HostDiscovered`], [`ScanEvent::Progress`],
/// [`ScanEvent::PortDiscovered`], [`ScanEvent::ServiceDiscovered`],
/// [`ScanEvent::HostEnriched`]) inside that frame.
///
/// The discovery, port-scanning, service-detection, and enrichment mechanisms
/// are supplied as traits so this orchestrator stays independent of any
/// concrete implementation. `config` carries the target and the per-stage
/// tunables (see [`ScanConfig`]).
///
/// Service detection runs only when [`ScanConfig::detect_services`] is set and
/// `detectors` is non-empty; it probes each open port in turn and stops at the
/// first detector that recognizes the service. A detector failure never fails
/// the scan: the failed detector is skipped and the next one is tried.
///
/// Enrichment runs only when [`ScanConfig::enrich`] is set and `enrichers` is
/// non-empty; each enricher is tried per host and its contributions (hostname,
/// MAC) are merged, with the vendor derived from the discovered MAC. A host
/// with no enrichment data produces no [`ScanEvent::HostEnriched`]. An
/// enricher failure never fails the scan: the failed enricher is skipped.
///
/// Cancellation is cooperative: when `cancel` is set, discovery stops (and
/// reports [`ScanEvent::Cancelled`]) and no further hosts are port-scanned,
/// service-probed, or enriched; in-flight connections are allowed to finish.
/// Both normal completion and cancellation return `Ok(())` — only a fatal
/// error returns `Err`.
pub fn run_scan<D: HostDiscovery, P: PortScanner>(
    config: &ScanConfig,
    discovery: &D,
    port_scanner: &P,
    detectors: &[Box<dyn ServiceDetector>],
    enrichers: &[Box<dyn HostEnricher>],
    events: &Sender<ScanEvent>,
    cancel: &Arc<AtomicBool>,
) -> Result<(), ScanError> {
    // Count the addresses (bounded by MAX_SUBNET_SIZE) so the progress display
    // has a stable total; the discovery stage enumerates them itself.
    let total = config.target.iter().count() as u64;

    let _ = events.send(ScanEvent::Started { total });

    let outcome = match discovery.discover(&config.target, &config.discovery, events, cancel) {
        Ok(outcome) => outcome,
        Err(err) => {
            // A fatal discovery failure must still reach the event stream: the
            // orchestrator drops the Result, so without this re-emit neither the
            // TUI nor the headless runner would see why the scan aborted.
            let _ = events.send(ScanEvent::Error(err.clone()));
            return Err(err);
        }
    };
    match outcome {
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
                // Enrichment for this host. Skipped entirely when disabled or
                // when no enrichers are configured. Cancellation is checked
                // before the stage so a cancelled scan stops scheduling further
                // enrichment work.
                if config.enrich && !enrichers.is_empty() {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    // Merge the contributions of every enricher; a failed or
                    // empty enricher simply adds nothing.
                    let mut merged = HostEnrichment::default();
                    for enricher in enrichers {
                        if let Ok(Some(enrichment)) = enricher.enrich(host.ip) {
                            // First contribution wins for a field.
                            merged.hostname = merged.hostname.or(enrichment.hostname);
                            merged.mac = merged.mac.or(enrichment.mac);
                        }
                    }
                    // A host with no enrichment data produces no event at all.
                    if !merged.is_empty() {
                        // The vendor is inferred from the discovered MAC's OUI.
                        let vendor = merged.mac.as_ref().and_then(vendor_for);
                        let _ = events.send(ScanEvent::HostEnriched {
                            ip: host.ip,
                            hostname: merged.hostname,
                            mac: merged.mac,
                            vendor,
                        });
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
    use super::discovery::icmp_echo_available;
    use super::enrichment::{EnrichmentError, HostEnrichment};
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

        let socket_err = std::io::Error::other("boom");
        let error = ScanEvent::Error(ScanError::from(socket_err));
        let cause = match error {
            ScanEvent::Error(cause) => cause,
            other => panic!("expected Error, got {other:?}"),
        };
        assert!(matches!(cause, ScanError::Socket { .. }));
        assert_eq!(cause.to_string(), "socket error: boom");

        let warning = ScanEvent::Warning("falling back to TCP discovery".to_string());
        let message = match warning {
            ScanEvent::Warning(message) => message,
            other => panic!("expected Warning, got {other:?}"),
        };
        assert_eq!(message, "falling back to TCP discovery");
    }

    /// When the ICMP socket can be opened, `Auto` behaves exactly like
    /// `Icmp` and emits no warning.
    ///
    /// This test requires ICMP echo to work in the test environment (as
    /// `discovers_localhost` in `discovery.rs` does); when it is unavailable,
    /// the fallback path under test here does not run.
    #[test]
    fn auto_uses_icmp_when_the_socket_opens() {
        // `Auto` falls back to TCP when ICMP is unavailable, so the result
        // alone cannot signal unavailability; probe up front and skip.
        if !icmp_echo_available() {
            eprintln!("test skipped: ICMP echo unavailable in this environment");
            return;
        }

        let target = ScanTarget::Host(Ipv4Addr::LOCALHOST);
        let config = DiscoveryConfig::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();

        let outcome = match Discovery::Auto.discover(&target, &config, &tx, &cancel) {
            Ok(outcome) => outcome,
            Err(err) => panic!("unexpected discovery error: {err:?}"),
        };
        drop(tx);
        let events: Vec<ScanEvent> = rx.try_iter().collect();

        // No warning: ICMP worked, so the fallback never engaged.
        assert!(
            !events.iter().any(|e| matches!(e, ScanEvent::Warning(_))),
            "Auto must not warn when ICMP is available: {events:?}"
        );

        match &outcome {
            DiscoveryOutcome::Completed(hosts) => {
                assert_eq!(hosts.len(), 1, "expected localhost to be up: {hosts:?}");
                assert_eq!(hosts[0].ip, Ipv4Addr::LOCALHOST);
                assert!(matches!(hosts[0].state, crate::network::HostState::Up));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn discovery_parses_from_its_cli_names() {
        assert_eq!("auto".parse::<Discovery>().unwrap(), Discovery::Auto);
        assert_eq!("icmp".parse::<Discovery>().unwrap(), Discovery::Icmp);
        assert_eq!("tcp".parse::<Discovery>().unwrap(), Discovery::Tcp);
    }

    #[test]
    fn discovery_rejects_unknown_strategies() {
        let err = "udp".parse::<Discovery>().unwrap_err();
        assert_eq!(
            err,
            DiscoveryError::UnknownStrategy {
                input: "udp".to_string()
            }
        );
        assert!(err.to_string().contains("udp"), "message: {err}");
    }

    #[test]
    fn error_display_is_descriptive() {
        let socket = ScanError::from(std::io::Error::other("cannot open socket"));
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
    fn permission_denied_detected_from_raw_os_error() {
        // EACCES (13) — the unprivileged SOCK_DGRAM ICMP case.
        let eacces = ScanError::Socket {
            raw_os_error: Some(libc::EACCES),
            message: "Permission denied (os error 13)".to_string(),
        };
        assert!(eacces.is_permission_denied());

        // EPERM (1) — the raw-socket case.
        let eperm = ScanError::Socket {
            raw_os_error: Some(libc::EPERM),
            message: "Operation not permitted (os error 1)".to_string(),
        };
        assert!(eperm.is_permission_denied());

        // A different OS code is not a permission denial.
        let einval = ScanError::Socket {
            raw_os_error: Some(libc::EINVAL),
            message: "Invalid argument (os error 22)".to_string(),
        };
        assert!(!einval.is_permission_denied());

        // No OS code at all (e.g. a synthetic error) is not a permission denial.
        let other = ScanError::Socket {
            raw_os_error: None,
            message: "boom".to_string(),
        };
        assert!(!other.is_permission_denied());

        // Channel errors are never permission denials.
        let channel = ScanError::Channel("closed".to_string());
        assert!(!channel.is_permission_denied());
    }

    #[test]
    fn from_io_error_preserves_raw_os_code_and_message() {
        // An io::Error carrying an OS code keeps the code and its message.
        let io_err = std::io::Error::from_raw_os_error(libc::EACCES);
        let scan_err = ScanError::from(io_err);
        assert!(scan_err.is_permission_denied());
        assert!(scan_err.to_string().starts_with("socket error"));

        // An io::Error without an OS code keeps its message but not a code.
        let io_err = std::io::Error::other("boom");
        let scan_err = ScanError::from(io_err);
        assert!(!scan_err.is_permission_denied());
        assert_eq!(scan_err.to_string(), "socket error: boom");
    }

    #[test]
    fn icmp_fallback_warning_names_the_fix_for_permission_denials() {
        let permission = ScanError::Socket {
            raw_os_error: Some(libc::EACCES),
            message: "Permission denied (os error 13)".to_string(),
        };
        let warning = icmp_fallback_warning(&permission);
        assert!(warning.contains("permission denied"), "warning: {warning}");
        assert!(warning.contains("TCP port probing"), "warning: {warning}");
        assert!(
            warning.contains("net.ipv4.ping_group_range"),
            "warning: {warning}"
        );

        // A non-permission failure is reported with its socket error.
        let other = ScanError::Socket {
            raw_os_error: Some(libc::EINVAL),
            message: "Invalid argument (os error 22)".to_string(),
        };
        let warning = icmp_fallback_warning(&other);
        assert!(
            warning.contains("socket error: Invalid argument (os error 22)"),
            "warning: {warning}"
        );
        assert!(warning.contains("TCP port probing"), "warning: {warning}");
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
        assert!(config.enrich, "enrichment is on by default");
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

        // Skip when ICMP echo is unavailable (e.g. CI without a raw socket).
        if !icmp_echo_available() {
            eprintln!("test skipped: ICMP echo unavailable in this environment");
            return;
        }

        // Bind a real listener on loopback for a guaranteed-open port and derive
        // a guaranteed-closed port the same way the port-scan test does.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let open_port = listener.local_addr().expect("listener address").port();
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
        let closed_port = probe.local_addr().expect("probe address").port();
        drop(probe);

        let config = ScanConfig {
            target: ScanTarget::Host(Ipv4Addr::LOCALHOST),
            discovery_strategy: Discovery::default(),
            discovery: DiscoveryConfig::default(),
            ports: PortConfig {
                ports: PortSpec::from_port_numbers([open_port, closed_port]),
                timeout: Duration::from_millis(500),
                concurrency: 4,
            },
            // Service detection stays off: this test only checks the scan
            // framing, and empty detectors would make detection a no-op anyway.
            detect_services: false,
            // Enrichment stays off: this test only checks the scan framing,
            // and the default enrichers would perform real network lookups.
            enrich: false,
        };

        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let result = run_scan(
            &config,
            &IcmpDiscovery,
            &TcpPortScanner,
            &[],
            &[],
            &tx,
            &cancel,
        );
        drop(tx);

        // Availability was verified above; an error here is unexpected.
        if let Err(err) = result {
            panic!("unexpected scan error: {err:?}");
        }

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

    /// A [`HostEnricher`] that always returns a fixed enrichment.
    struct FixedEnricher {
        enrichment: HostEnrichment,
    }

    impl HostEnricher for FixedEnricher {
        fn enrich(&self, _ip: Ipv4Addr) -> Result<Option<HostEnrichment>, EnrichmentError> {
            if self.enrichment.is_empty() {
                Ok(None)
            } else {
                Ok(Some(self.enrichment.clone()))
            }
        }
    }

    /// A [`HostEnricher`] that always fails; the orchestrator must skip it
    /// without failing the scan.
    struct FailingEnricher;

    impl HostEnricher for FailingEnricher {
        fn enrich(&self, _ip: Ipv4Addr) -> Result<Option<HostEnrichment>, EnrichmentError> {
            Err(EnrichmentError::Lookup("forced failure".to_string()))
        }
    }

    /// Runs the orchestrator against the hermetic fakes and returns the
    /// result plus every event that was produced.
    fn run_fake_scan(
        detect_services: bool,
        detectors: Vec<Box<dyn ServiceDetector>>,
        enrich: bool,
        enrichers: Vec<Box<dyn HostEnricher>>,
    ) -> (Result<(), ScanError>, Vec<ScanEvent>) {
        use std::sync::mpsc;

        let config = ScanConfig {
            target: ScanTarget::Host(Ipv4Addr::LOCALHOST),
            discovery_strategy: Discovery::default(),
            discovery: DiscoveryConfig::default(),
            ports: PortConfig::default(),
            detect_services,
            enrich,
        };
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let result = run_scan(
            &config,
            &FakeDiscovery,
            &FakePortScanner,
            &detectors,
            &enrichers,
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

    /// The `(ip, hostname, mac, vendor)` payload collected from
    /// `HostEnriched` events in tests.
    type EnrichedHost = (Ipv4Addr, Option<String>, Option<MacAddress>, Option<String>);

    /// Collects the `EnrichedHost` tuples from `HostEnriched` events.
    fn enrichment_events(events: &[ScanEvent]) -> Vec<EnrichedHost> {
        events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::HostEnriched {
                    ip,
                    hostname,
                    mac,
                    vendor,
                } => Some((*ip, hostname.clone(), *mac, vendor.clone())),
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
        let (result, events) = run_fake_scan(true, detectors, false, vec![]);
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
        let (result, events) = run_fake_scan(false, detectors, false, vec![]);
        assert!(result.is_ok(), "scan must succeed: {result:?}");
        assert!(
            service_events(&events).is_empty(),
            "detection must not run when disabled: {events:?}"
        );
    }

    #[test]
    fn run_scan_skips_service_detection_without_detectors() {
        let (result, events) = run_fake_scan(true, vec![], false, vec![]);
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
        let (result, events) = run_fake_scan(true, detectors, false, vec![]);
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
        let (result, events) = run_fake_scan(true, detectors, false, vec![]);
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
        let (result, events) = run_fake_scan(true, detectors, false, vec![]);
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

    #[test]
    fn run_scan_enriches_hosts_when_enabled() {
        let mac: MacAddress = "3c:52:82:aa:bb:cc".parse().unwrap();
        let enrichers: Vec<Box<dyn HostEnricher>> = vec![
            Box::new(FixedEnricher {
                enrichment: HostEnrichment {
                    hostname: Some("host.example".to_string()),
                    mac: None,
                },
            }),
            Box::new(FixedEnricher {
                enrichment: HostEnrichment {
                    hostname: None,
                    mac: Some(mac),
                },
            }),
        ];
        let (result, events) = run_fake_scan(false, vec![], true, enrichers);
        assert!(result.is_ok(), "scan must succeed: {result:?}");

        // The contributions of every enricher are merged into one event, and
        // the vendor is derived from the discovered MAC.
        let enriched = enrichment_events(&events);
        assert_eq!(enriched.len(), 1, "one event per host: {events:?}");
        let (ip, hostname, mac_found, vendor) = &enriched[0];
        assert_eq!(*ip, Ipv4Addr::LOCALHOST);
        assert_eq!(hostname.as_deref(), Some("host.example"));
        assert_eq!(mac_found.as_ref(), Some(&mac));
        assert!(
            vendor.is_some(),
            "vendor should be derived from the discovered MAC: {events:?}"
        );

        assert!(
            matches!(events.last(), Some(ScanEvent::Finished)),
            "scan still finishes: {events:?}"
        );
    }

    #[test]
    fn run_scan_skips_enrichment_when_disabled() {
        let enrichers: Vec<Box<dyn HostEnricher>> = vec![Box::new(FixedEnricher {
            enrichment: HostEnrichment {
                hostname: Some("host.example".to_string()),
                mac: None,
            },
        })];
        let (result, events) = run_fake_scan(false, vec![], false, enrichers);
        assert!(result.is_ok(), "scan must succeed: {result:?}");
        assert!(
            enrichment_events(&events).is_empty(),
            "enrichment must not run when disabled: {events:?}"
        );
    }

    #[test]
    fn run_scan_skips_enrichment_without_enrichers() {
        let (result, events) = run_fake_scan(false, vec![], true, vec![]);
        assert!(result.is_ok(), "scan must succeed: {result:?}");
        assert!(
            enrichment_events(&events).is_empty(),
            "no enrichers means no enrichment: {events:?}"
        );
    }

    #[test]
    fn run_scan_enricher_failure_is_skipped_not_fatal() {
        let enrichers: Vec<Box<dyn HostEnricher>> = vec![
            Box::new(FailingEnricher),
            Box::new(FixedEnricher {
                enrichment: HostEnrichment {
                    hostname: None,
                    mac: Some("00:1b:63:dd:ee:ff".parse().unwrap()),
                },
            }),
        ];
        let (result, events) = run_fake_scan(false, vec![], true, enrichers);
        assert!(
            result.is_ok(),
            "an enricher failure must not fail the scan: {result:?}"
        );

        // The failing enricher is skipped and the next one still reports.
        let enriched = enrichment_events(&events);
        assert_eq!(enriched.len(), 1, "events: {events:?}");
        assert!(
            enriched[0].2.is_some(),
            "the surviving enricher still contributes: {events:?}"
        );

        // An enricher failure is not a scan error.
        assert!(
            !events.iter().any(|e| matches!(e, ScanEvent::Error(_))),
            "no Error event expected: {events:?}"
        );
    }

    #[test]
    fn run_scan_no_enrichment_event_when_nothing_is_enriched() {
        let enrichers: Vec<Box<dyn HostEnricher>> = vec![
            Box::new(FailingEnricher),
            Box::new(FixedEnricher {
                enrichment: HostEnrichment::default(),
            }),
        ];
        let (result, events) = run_fake_scan(false, vec![], true, enrichers);
        assert!(result.is_ok(), "scan must succeed: {result:?}");
        assert!(
            enrichment_events(&events).is_empty(),
            "no enrichment data means no event: {events:?}"
        );
        assert!(
            matches!(events.last(), Some(ScanEvent::Finished)),
            "scan still finishes: {events:?}"
        );
    }
}
