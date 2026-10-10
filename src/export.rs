//! JSON export of scan results (Phase 11).
//!
//! The export converts the in-memory scan state (target plus discovered hosts)
//! into dedicated serializable types and writes them to a JSON file. The
//! network model itself carries no serialization derives: the JSON document is
//! the application's export format and will be treated as a versioned public
//! format once the project is released.
//!
//! Export files are never overwritten: the base name is reused only while it
//! is free, otherwise a numeric suffix is incremented
//! (`port-scanner-export-2.json`, `port-scanner-export-3.json`, ...).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::network::host::{Host, HostState};
use crate::network::port::PortState;
use crate::target::ScanTarget;

/// Base file name for exports, chosen without a clock or timezone so the name
/// is deterministic.
pub const EXPORT_BASE_NAME: &str = "port-scanner-export.json";

/// The exported scan results document.
///
/// This is the shape written to the JSON file; see `PLAN.md` (Phase 11) for
/// the format example.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportDocument {
    /// The target the scan was run against, in its normalized form (e.g.
    /// `192.168.1.10` or `192.168.1.0/24`).
    pub target: String,
    /// Hosts in the order their scan events arrived.
    pub hosts: Vec<ExportHost>,
}

/// A host within an exported document.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportHost {
    /// The host's IPv4 address.
    pub ip: String,
    /// The host state, lowercase (`"up"` / `"down"`).
    pub state: &'static str,
    /// Round-trip time of the probe in milliseconds; absent when the host is
    /// down.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    /// The TCP ports probed on this host.
    pub ports: Vec<ExportPort>,
}

/// A probed port within an exported host.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportPort {
    /// The port number.
    pub port: u16,
    /// The protocol that was probed (always `"tcp"` for now).
    pub protocol: &'static str,
    /// The port state, lowercase (`"open"` / `"closed"`).
    pub state: &'static str,
}

impl ExportDocument {
    /// Build a document from the in-memory scan state.
    pub fn from_scan(target: &ScanTarget, hosts: &[Host]) -> Self {
        Self {
            target: target.to_string(),
            hosts: hosts.iter().map(ExportHost::from_host).collect(),
        }
    }
}

impl ExportHost {
    /// Convert a discovered host into its exported form.
    fn from_host(host: &Host) -> Self {
        Self {
            ip: host.ip.to_string(),
            state: match host.state {
                HostState::Up => "up",
                HostState::Down => "down",
            },
            latency_ms: host.latency.map(|latency| latency.as_secs_f64() * 1000.0),
            ports: host
                .ports
                .iter()
                .map(|probed| ExportPort {
                    port: probed.port.as_u16(),
                    protocol: "tcp",
                    state: match probed.state {
                        PortState::Open => "open",
                        PortState::Closed => "closed",
                    },
                })
                .collect(),
        }
    }
}

/// Choose the next unused export file name within `dir`.
///
/// Returns [`EXPORT_BASE_NAME`] while it is free, otherwise the first free
/// suffixed name `port-scanner-export-N.json` (starting at `N = 2`), so an
/// export never overwrites an earlier one.
fn next_export_path(dir: &Path) -> io::Result<PathBuf> {
    let base = dir.join(EXPORT_BASE_NAME);
    if !base.exists() {
        return Ok(base);
    }
    let stem = base
        .file_stem()
        .and_then(|name| name.to_str())
        .expect("export base name has a string stem");
    let extension = base
        .extension()
        .and_then(|name| name.to_str())
        .expect("export base name has a string extension");
    let mut suffix = 2u32;
    loop {
        let candidate = dir.join(format!("{stem}-{suffix}.{extension}"));
        if !candidate.exists() {
            return Ok(candidate);
        }
        suffix += 1;
    }
}

/// Serialize the given scan state to the JSON export format.
fn render(target: &ScanTarget, hosts: &[Host]) -> io::Result<String> {
    let document = ExportDocument::from_scan(target, hosts);
    Ok(serde_json::to_string_pretty(&document)?)
}

/// Export the scan state to a JSON file in `dir`, returning the path written.
///
/// The file name is chosen by [`next_export_path`], so existing exports in
/// `dir` are never overwritten.
pub fn export_to(dir: &Path, target: &ScanTarget, hosts: &[Host]) -> io::Result<PathBuf> {
    let path = next_export_path(dir)?;
    let json = render(target, hosts)?;
    fs::write(&path, json)?;
    Ok(path)
}

/// Export the scan state to a JSON file in the current directory, returning
/// the path written.
pub fn export(target: &ScanTarget, hosts: &[Host]) -> io::Result<PathBuf> {
    export_to(Path::new("."), target, hosts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::network::port::{Port, ProbedPort};

    /// A temp directory unique to this test process, created if missing.
    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("port-scanner-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn host_up(ip: &str, latency: Duration, ports: &[(u16, PortState)]) -> Host {
        let mut host = Host::up(ip.parse::<Ipv4Addr>().expect("valid ip"), latency);
        host.ports = ports
            .iter()
            .map(|&(number, state)| ProbedPort::new(Port::new(number).expect("valid port"), state))
            .collect();
        host
    }

    #[test]
    fn from_scan_converts_states_to_lowercase() {
        let target = ScanTarget::parse("192.168.1.10").expect("valid target");
        let host = host_up(
            "192.168.1.10",
            Duration::from_micros(1500),
            &[(22, PortState::Open), (80, PortState::Closed)],
        );
        let doc = ExportDocument::from_scan(&target, std::slice::from_ref(&host));

        assert_eq!(doc.target, "192.168.1.10");
        let exported = &doc.hosts[0];
        assert_eq!(exported.ip, "192.168.1.10");
        assert_eq!(exported.state, "up");
        assert_eq!(exported.latency_ms, Some(1.5));
        assert_eq!(
            exported.ports,
            vec![
                ExportPort {
                    port: 22,
                    protocol: "tcp",
                    state: "open",
                },
                ExportPort {
                    port: 80,
                    protocol: "tcp",
                    state: "closed",
                },
            ]
        );
    }

    #[test]
    fn from_scan_omits_latency_for_down_hosts() {
        let target = ScanTarget::parse("192.168.1.0/24").expect("valid target");
        let host = Host::down("192.168.1.55".parse::<Ipv4Addr>().unwrap());
        let doc = ExportDocument::from_scan(&target, std::slice::from_ref(&host));

        let exported = &doc.hosts[0];
        assert_eq!(exported.state, "down");
        assert_eq!(exported.latency_ms, None);
        assert!(exported.ports.is_empty());
    }

    #[test]
    fn json_shape_matches_the_export_format() {
        let target = ScanTarget::parse("192.168.1.10").expect("valid target");
        let host = host_up(
            "192.168.1.10",
            Duration::from_millis(3),
            &[(22, PortState::Open)],
        );
        let doc = ExportDocument::from_scan(&target, std::slice::from_ref(&host));

        let value = serde_json::to_value(&doc).expect("serialize");
        assert_eq!(
            value,
            serde_json::json!({
                "target": "192.168.1.10",
                "hosts": [
                    {
                        "ip": "192.168.1.10",
                        "state": "up",
                        "latency_ms": 3.0,
                        "ports": [
                            { "port": 22, "protocol": "tcp", "state": "open" }
                        ]
                    }
                ]
            })
        );
    }

    #[test]
    fn json_omits_latency_field_for_down_hosts() {
        let target = ScanTarget::parse("192.168.1.0/24").expect("valid target");
        let host = Host::down("192.168.1.55".parse::<Ipv4Addr>().unwrap());
        let doc = ExportDocument::from_scan(&target, std::slice::from_ref(&host));

        let value = serde_json::to_value(&doc).expect("serialize");
        assert!(value["hosts"][0].get("latency_ms").is_none());
    }

    #[test]
    fn next_export_path_increments_suffix_on_collision() {
        let dir = temp_dir("suffix");
        assert_eq!(
            next_export_path(&dir).expect("path"),
            dir.join(EXPORT_BASE_NAME)
        );

        fs::write(dir.join(EXPORT_BASE_NAME), "{}").expect("seed base name");
        assert_eq!(
            next_export_path(&dir).expect("path"),
            dir.join("port-scanner-export-2.json")
        );

        fs::write(dir.join("port-scanner-export-2.json"), "{}").expect("seed suffix 2");
        assert_eq!(
            next_export_path(&dir).expect("path"),
            dir.join("port-scanner-export-3.json")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_to_writes_valid_json_without_overwriting() {
        let dir = temp_dir("write");
        let target = ScanTarget::parse("192.168.1.10").expect("valid target");
        let host = host_up(
            "192.168.1.10",
            Duration::from_millis(3),
            &[(22, PortState::Open)],
        );
        let hosts = [host];

        let first = export_to(&dir, &target, &hosts).expect("first export");
        assert_eq!(first, dir.join(EXPORT_BASE_NAME));
        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&first).expect("read")).expect("valid json");
        assert_eq!(value["target"], "192.168.1.10");
        assert_eq!(value["hosts"][0]["ports"][0]["port"], 22);

        // A second export must not clobber the first file.
        let second = export_to(&dir, &target, &hosts).expect("second export");
        assert_eq!(second, dir.join("port-scanner-export-2.json"));
        let untouched: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&first).expect("read")).expect("valid json");
        assert_eq!(untouched["target"], "192.168.1.10");

        let _ = fs::remove_dir_all(&dir);
    }
}
