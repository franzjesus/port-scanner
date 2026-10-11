//! Headless scan mode (PLAN.md Phase 11, task 11.9).
//!
//! Runs a full scan without the TUI and emits the same JSON export document
//! the TUI's export writes: the structured results are collected from the
//! scanner's event stream and rendered with [`ExportDocument`], so headless
//! output is byte-identical to a TUI export of the same scan.

use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use crate::export::ExportDocument;
use crate::network::host::Host;
use crate::scanner::{
    default_detectors, default_enrichers, run_scan, IcmpDiscovery, ScanConfig, ScanEvent,
    TcpPortScanner,
};

/// Apply one scanner event to the collected host list, mirroring the TUI's
/// `App::apply_event` — the single place scan results are turned into
/// structured state.
///
/// The TUI additionally tracks scan-state transitions and progress counts
/// (`Discovering` → `ScanningPorts` → terminal); those have no counterpart
/// in the export document, so this collector records only the host list that
/// the document is built from.
///
/// Returns `true` when the event is terminal (`Finished`, `Cancelled`, or
/// `Error`), in which case no further events are expected and the scan loop
/// should stop.
pub fn apply_event(hosts: &mut Vec<Host>, event: ScanEvent) -> bool {
    match event {
        // The TUI records the total, a start instant, and discovery counts for
        // progress and elapsed display; the export document carries none of
        // those, so there is nothing to do here.
        ScanEvent::Started { .. } | ScanEvent::Progress { .. } => false,
        ScanEvent::HostDiscovered(host) => {
            hosts.push(host);
            false
        }
        ScanEvent::PortDiscovered { ip, port, state } => {
            // The scanner emits this for every probed port (open or closed);
            // record each probed port with its state on the matching host. A
            // host is always discovered before its ports are probed, so it is
            // already present here; a miss is simply ignored.
            if let Some(host) = hosts.iter_mut().find(|h| h.ip == ip) {
                host.add_probed_port(port, state);
            }
            false
        }
        ScanEvent::ServiceDiscovered { ip, port, service } => {
            // Attach the detected service to the probed-port record. The
            // export does not carry services, but the collector mirrors the
            // TUI exactly so the collected state stays faithful. A missing
            // host or port entry is simply ignored.
            if let Some(host) = hosts.iter_mut().find(|h| h.ip == ip) {
                if let Some(probed) = host.ports.iter_mut().find(|p| p.port == port) {
                    probed.service = Some(service);
                }
            }
            false
        }
        ScanEvent::HostEnriched {
            ip,
            hostname,
            mac,
            vendor,
        } => {
            // Attach the enrichment to the host. The host was already
            // discovered before its enrichment ran; a missing host is simply
            // ignored. Only fields the enrichers actually produced are `Some`,
            // so `None` fields leave the host unchanged.
            if let Some(host) = hosts.iter_mut().find(|h| h.ip == ip) {
                if let Some(hostname) = hostname {
                    host.hostname = Some(hostname);
                }
                if let Some(mac) = mac {
                    host.mac = Some(mac);
                }
                if let Some(vendor) = vendor {
                    host.vendor = Some(vendor);
                }
            }
            false
        }
        // Terminal events end the scan loop.
        ScanEvent::Finished | ScanEvent::Cancelled | ScanEvent::Error(_) => true,
    }
}

/// Run a full scan without the TUI and write the JSON export document.
///
/// `output` selects the destination: `None` writes the document to stdout
/// (with a trailing newline), `Some(path)` writes it to that file,
/// overwriting any existing file (no trailing newline, matching the bytes the
/// TUI export writes). The document is built with [`ExportDocument::from_scan`]
/// and serialized with `serde_json::to_string_pretty` — the same pipeline the
/// TUI export uses — so headless output is byte-identical to a TUI export of
/// the same scan.
///
/// The scan runs inline on the calling thread: the event channel is
/// unbounded, so `send` never blocks and the scan cannot deadlock against the
/// drain loop below.
///
/// Returns [`ExitCode::SUCCESS`] when the scan completed or was cancelled
/// (both end with a usable result set) and the document was written;
/// [`ExitCode::FAILURE`] when the scan hit a fatal error or the document
/// could not be written.
pub fn run(config: &ScanConfig, output: Option<&Path>) -> ExitCode {
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));

    let result = run_scan(
        config,
        &IcmpDiscovery,
        &TcpPortScanner,
        &default_detectors(),
        &default_enrichers(),
        &tx,
        &cancel,
    );
    // Drop the sender so the receiver loop ends once the scan is done.
    drop(tx);

    // Fold the event stream into the host list until a terminal event.
    let mut hosts = Vec::new();
    for event in rx {
        if apply_event(&mut hosts, event) {
            break;
        }
    }

    // The `Result` is the authoritative outcome: a discovery failure returns
    // `Err` without an `Error` event, and a port-scanner failure returns
    // `Err` after sending one. On error, report it and write nothing.
    if let Err(err) = result {
        eprintln!("port-scanner: {err}");
        return ExitCode::FAILURE;
    }

    match render(config, &hosts) {
        Ok(json) => write_output(output, &json),
        Err(err) => {
            eprintln!("port-scanner: failed to serialize the export document: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Build the export document and render it as pretty-printed JSON, using the
/// same pipeline as the TUI export.
fn render(config: &ScanConfig, hosts: &[Host]) -> Result<String, serde_json::Error> {
    let document = ExportDocument::from_scan(&config.target, hosts);
    serde_json::to_string_pretty(&document)
}

/// Write the rendered JSON document to the chosen destination.
fn write_output(output: Option<&Path>, json: &str) -> ExitCode {
    match output {
        Some(path) => match fs::write(path, json) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("port-scanner: failed to write {path:?}: {err}");
                ExitCode::FAILURE
            }
        },
        None => {
            println!("{json}");
            ExitCode::SUCCESS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::mac::MacAddress;
    use crate::network::port::{Port, PortState, ProbedPort};
    use crate::network::service::ServiceInfo;
    use crate::scanner::ScanError;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn up_host(ip: &str) -> Host {
        Host::up(ip.parse().unwrap(), Duration::from_millis(1))
    }

    fn open_port(value: u16) -> Port {
        Port::new(value).unwrap()
    }

    #[test]
    fn host_discovered_pushes_the_host() {
        let mut hosts = Vec::new();
        let finished = apply_event(
            &mut hosts,
            ScanEvent::HostDiscovered(up_host("192.168.1.10")),
        );
        assert!(!finished);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "192.168.1.10".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn started_and_progress_do_not_change_the_hosts() {
        let mut hosts = vec![up_host("192.168.1.10")];
        assert!(!apply_event(&mut hosts, ScanEvent::Started { total: 256 }));
        assert!(!apply_event(
            &mut hosts,
            ScanEvent::Progress {
                completed: 1,
                total: 256
            }
        ));
        assert_eq!(hosts.len(), 1);
    }

    #[test]
    fn port_discovered_records_the_port_on_the_matching_host() {
        let mut hosts = vec![up_host("192.168.1.10")];
        let finished = apply_event(
            &mut hosts,
            ScanEvent::PortDiscovered {
                ip: "192.168.1.10".parse().unwrap(),
                port: open_port(22),
                state: PortState::Open,
            },
        );
        assert!(!finished);
        assert_eq!(
            hosts[0].ports,
            vec![ProbedPort::new(open_port(22), PortState::Open)]
        );
    }

    #[test]
    fn port_discovered_ignores_an_unknown_host() {
        let mut hosts = vec![up_host("192.168.1.10")];
        let finished = apply_event(
            &mut hosts,
            ScanEvent::PortDiscovered {
                ip: "10.0.0.1".parse().unwrap(),
                port: open_port(80),
                state: PortState::Open,
            },
        );
        assert!(!finished);
        assert!(hosts[0].ports.is_empty());
    }

    #[test]
    fn service_discovered_attaches_the_service_to_the_probed_port() {
        let mut hosts = vec![up_host("192.168.1.10")];
        hosts[0].add_probed_port(open_port(22), PortState::Open);
        let finished = apply_event(
            &mut hosts,
            ScanEvent::ServiceDiscovered {
                ip: "192.168.1.10".parse().unwrap(),
                port: open_port(22),
                service: ServiceInfo::new("ssh"),
            },
        );
        assert!(!finished);
        assert_eq!(hosts[0].ports[0].service, Some(ServiceInfo::new("ssh")));
    }

    #[test]
    fn service_discovered_ignores_a_missing_host_or_port() {
        let mut hosts = vec![up_host("192.168.1.10")];
        // Unknown host.
        let finished = apply_event(
            &mut hosts,
            ScanEvent::ServiceDiscovered {
                ip: "10.0.0.1".parse().unwrap(),
                port: open_port(22),
                service: ServiceInfo::new("ssh"),
            },
        );
        assert!(!finished);
        assert!(hosts[0].ports.is_empty());
        // Known host, unknown port.
        let finished = apply_event(
            &mut hosts,
            ScanEvent::ServiceDiscovered {
                ip: "192.168.1.10".parse().unwrap(),
                port: open_port(80),
                service: ServiceInfo::new("http"),
            },
        );
        assert!(!finished);
        assert!(hosts[0].ports.is_empty());
    }

    #[test]
    fn host_enriched_attaches_only_the_fields_that_are_present() {
        let mut hosts = vec![up_host("192.168.1.10")];
        let mac = MacAddress::new([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        let finished = apply_event(
            &mut hosts,
            ScanEvent::HostEnriched {
                ip: "192.168.1.10".parse().unwrap(),
                hostname: Some("host.example".to_string()),
                mac: Some(mac),
                vendor: None,
            },
        );
        assert!(!finished);
        assert_eq!(hosts[0].hostname.as_deref(), Some("host.example"));
        assert_eq!(hosts[0].mac, Some(mac));
        assert_eq!(hosts[0].vendor, None);
    }

    #[test]
    fn host_enriched_ignores_an_unknown_host() {
        let mut hosts = vec![up_host("192.168.1.10")];
        let finished = apply_event(
            &mut hosts,
            ScanEvent::HostEnriched {
                ip: "10.0.0.1".parse().unwrap(),
                hostname: Some("host.example".to_string()),
                mac: None,
                vendor: None,
            },
        );
        assert!(!finished);
        assert_eq!(hosts[0].hostname, None);
    }

    #[test]
    fn terminal_events_report_the_end_of_the_scan() {
        let mut hosts = vec![up_host("192.168.1.10")];
        assert!(apply_event(&mut hosts, ScanEvent::Finished));
        assert!(apply_event(&mut hosts, ScanEvent::Cancelled));
        assert!(apply_event(
            &mut hosts,
            ScanEvent::Error(ScanError::Socket("boom".to_string()))
        ));
        assert_eq!(hosts.len(), 1);
    }
}
