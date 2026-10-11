//! File-based persistence of completed scans (Phase 14) and listing of saved
//! scans for the history view (Phase 15).
//!
//! One completed scan is stored as a single JSON file in the XDG data
//! directory. The network model carries no `serde` derives (as with the export
//! document in Phase 11), so this module defines dedicated
//! [`Serialize`]/[`Deserialize`] record types ([`ScanRecord`]) that mirror the
//! scan state and are a superset of the export document: they additionally
//! carry the format `version`, the completion `timestamp`, the `target`, and
//! the scan `config`, and each port includes its detected service.
//!
//! This module performs file I/O but no network I/O, and it has no dependency
//! on the TUI.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::network::{Host, PortState, ServiceInfo};
use crate::scanner::ScanConfig;
use crate::target::ScanTarget;

/// Schema version of the record format written by this build.
pub const CURRENT_VERSION: u32 = 1;

/// Directory (relative to the XDG data root) that holds scan records.
const RECORD_DIR: &str = "port-scanner";

/// A stored scan: everything the TUI knows after a completed run.
///
/// The record is a superset of the Phase 11 export document. Field ordering is
/// part of the on-disk layout; keep it stable and additive for future
/// versions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanRecord {
    /// Format version, so a future reader can reject unknown layouts.
    pub version: u32,
    /// Completion instant as Unix seconds (dependency-free, sortable).
    pub timestamp: u64,
    /// The target that was scanned, in normalized form.
    pub target: String,
    /// The configuration the scan ran with.
    pub config: RecordConfig,
    /// Every discovered host, in discovery order.
    pub hosts: Vec<RecordHost>,
}

/// The configuration of a stored scan, flattened into primitive fields.
///
/// [`ScanConfig`] and its nested tunables carry no `serde` derives, so the
/// record stores the plain values a future run would need to reproduce the
/// scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordConfig {
    /// Host-discovery timeout in milliseconds.
    pub discovery_timeout_ms: u64,
    /// Host-discovery concurrency.
    pub discovery_concurrency: usize,
    /// The ports probed per host, in ascending order.
    pub ports: Vec<u16>,
    /// Per-port connection timeout in milliseconds.
    pub port_timeout_ms: u64,
    /// Per-host port-scan concurrency.
    pub port_concurrency: usize,
    /// Whether service detection was enabled.
    pub detect_services: bool,
    /// Whether host enrichment was enabled.
    pub enrich: bool,
}

/// A stored host, mirroring [`Host`] but with owned, serializable fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordHost {
    /// The host's IPv4 address.
    pub ip: String,
    /// Liveness: `"up"` or `"down"`.
    pub state: String,
    /// Round-trip latency in milliseconds, when measured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    /// Resolved hostname, when enrichment found one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// MAC address (uppercase colon form), when observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Vendor inferred from the MAC OUI, when observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// The ports probed on this host.
    pub ports: Vec<RecordPort>,
}

/// A stored probed port, including its detected service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordPort {
    /// The port number.
    pub port: u16,
    /// Protocol; always `"tcp"` for the current scanner.
    pub protocol: String,
    /// Result: `"open"` or `"closed"`.
    pub state: String,
    /// Detected service, when detection ran and identified one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<RecordService>,
}

/// A stored service description (a copy of [`ServiceInfo`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordService {
    /// Service name, e.g. `ssh`.
    pub name: String,
    /// Service version, when detected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Extra banner text, when captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<String>,
}

impl ScanRecord {
    /// Build a record from the current scan state.
    ///
    /// `target` is the scan's target (from the config, the canonical source),
    /// `hosts` the discovered hosts, `config` the configuration the scan ran
    /// with, and `timestamp` the completion instant in Unix seconds.
    pub fn from_scan(
        target: &ScanTarget,
        hosts: &[Host],
        config: &ScanConfig,
        timestamp: u64,
    ) -> Self {
        Self {
            version: CURRENT_VERSION,
            timestamp,
            target: target.to_string(),
            config: RecordConfig {
                discovery_timeout_ms: config.discovery.timeout.as_millis() as u64,
                discovery_concurrency: config.discovery.concurrency,
                ports: config
                    .ports
                    .ports
                    .iter()
                    .map(|port| port.as_u16())
                    .collect(),
                port_timeout_ms: config.ports.timeout.as_millis() as u64,
                port_concurrency: config.ports.concurrency,
                detect_services: config.detect_services,
                enrich: config.enrich,
            },
            hosts: hosts.iter().map(RecordHost::from_host).collect(),
        }
    }
}

impl RecordHost {
    /// Convert a live [`Host`] into its stored form.
    pub fn from_host(host: &Host) -> Self {
        Self {
            ip: host.ip.to_string(),
            state: match host.state {
                crate::network::HostState::Up => "up",
                crate::network::HostState::Down => "down",
            }
            .to_owned(),
            latency_ms: host.latency.map(|d| d.as_secs_f64() * 1000.0),
            hostname: host.hostname.clone(),
            mac: host.mac.map(|mac| mac.to_string()),
            vendor: host.vendor.clone(),
            ports: host
                .ports
                .iter()
                .map(|probed| RecordPort {
                    port: probed.port.as_u16(),
                    protocol: "tcp".to_owned(),
                    state: match probed.state {
                        PortState::Open => "open",
                        PortState::Closed => "closed",
                    }
                    .to_owned(),
                    service: probed.service.as_ref().map(RecordService::from_service),
                })
                .collect(),
        }
    }
}

impl RecordService {
    /// Copy a live [`ServiceInfo`] into its stored form.
    pub fn from_service(service: &ServiceInfo) -> Self {
        Self {
            name: service.name.clone(),
            version: service.version.clone(),
            extra: service.extra.clone(),
        }
    }
}

/// Resolve the XDG data directory for scan records from explicit environment
/// values.
///
/// Mirrors the XDG Base Directory spec: `$XDG_DATA_HOME/port-scanner` when
/// `xdg` is set to a non-empty absolute path, otherwise
/// `$HOME/.local/share/port-scanner`. Returns an error when `xdg` is set but
/// relative (or empty) and no `home` is available, since the spec forbids a
/// relative `XDG_DATA_HOME` and there is no sensible fallback.
///
/// Taking the values as parameters keeps the precedence logic pure and testable
/// without mutating the process environment; [`data_dir`] is the thin wrapper
/// that reads the real environment.
pub fn resolve_data_dir(xdg: Option<&str>, home: Option<&str>) -> io::Result<PathBuf> {
    match xdg {
        Some(dir) if !dir.is_empty() => {
            let path = Path::new(dir);
            if path.is_absolute() {
                Ok(path.join(RECORD_DIR))
            } else {
                Err(invalid_data_dir(format!(
                    "XDG_DATA_HOME is set to the relative path {dir:?}; it must be absolute"
                )))
            }
        }
        _ => match home {
            Some(home) => Ok(Path::new(home).join(".local/share").join(RECORD_DIR)),
            None => Err(invalid_data_dir(
                "neither XDG_DATA_HOME nor HOME is set; cannot locate the data directory",
            )),
        },
    }
}

fn invalid_data_dir(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// The data directory for scan records, creating it on demand.
///
/// Reads `XDG_DATA_HOME` and `HOME` from the process environment. A variable
/// that is set but not valid UTF-8 is treated as unset (falling back to `HOME`
/// when `XDG_DATA_HOME` is affected).
pub fn data_dir() -> io::Result<PathBuf> {
    let xdg = env_str("XDG_DATA_HOME");
    let home = env_str("HOME");
    let dir = resolve_data_dir(xdg.as_deref(), home.as_deref())?;
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Read an environment variable as a `String`, or `None` when it is unset or
/// not valid UTF-8.
fn env_str(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The file name (not full path) for a record: `<timestamp>_<target-slug>.json`.
fn record_file_name(record: &ScanRecord) -> String {
    format!("{}_{}.json", record.timestamp, target_slug(&record.target))
}

/// Reduce a target string to a safe file-name component.
///
/// Lowercases and replaces every character outside `[a-z0-9._-]` with `_`, so
/// e.g. `192.168.1.0/24` becomes `192.168.1.0_24` and `host.example.com` stays
/// unchanged.
pub fn target_slug(target: &str) -> String {
    target
        .to_ascii_lowercase()
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '_',
        })
        .collect()
}

/// The base record path for a record inside `dir` (no collision handling).
pub fn record_path(dir: &Path, record: &ScanRecord) -> PathBuf {
    dir.join(record_file_name(record))
}

/// Choose the next unused record path within `dir`.
///
/// Returns [`record_path`] while it is free, otherwise the first free suffixed
/// name `<stem>-<n>.json` (starting at `n = 2`), so two scans that complete in
/// the same second for the same target never overwrite each other.
pub fn next_record_path(dir: &Path, record: &ScanRecord) -> io::Result<PathBuf> {
    let base = record_path(dir, record);
    if !base.exists() {
        return Ok(base);
    }
    let stem = base
        .file_stem()
        .and_then(|name| name.to_str())
        .expect("record file name has a string stem");
    let extension = base
        .extension()
        .and_then(|name| name.to_str())
        .expect("record file name has a string extension");
    let mut suffix = 2u32;
    loop {
        let candidate = dir.join(format!("{stem}-{suffix}.{extension}"));
        if !candidate.exists() {
            return Ok(candidate);
        }
        suffix += 1;
    }
}

/// Write a record to disk as pretty JSON, returning the path it was written to.
pub fn save(dir: &Path, record: &ScanRecord) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let path = next_record_path(dir, record)?;
    let json = serde_json::to_string_pretty(record).map_err(io::Error::other)?;
    fs::write(&path, json)?;
    Ok(path)
}

/// Read a record from disk, validating it as JSON.
pub fn load(path: &Path) -> io::Result<ScanRecord> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

/// A saved scan's summary, enough for the history view to display it without
/// loading the full record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSummary {
    /// Path of the record file.
    pub path: PathBuf,
    /// Completion instant as Unix seconds.
    pub timestamp: u64,
    /// The target that was scanned, in normalized form.
    pub target: String,
    /// Number of hosts in the record.
    pub host_count: usize,
    /// Number of open ports across all hosts.
    pub open_port_count: usize,
}

/// List the saved scans in `dir`, newest first.
///
/// A missing directory is not an error and yields an empty list. Files that
/// are not `.json` or that fail to load are skipped rather than surfaced as
/// errors, so one corrupt record never hides the rest of the history.
pub fn list_records(dir: &Path) -> io::Result<Vec<RecordSummary>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let mut summaries = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let record = match load(&path) {
            Ok(record) => record,
            Err(_) => continue,
        };
        summaries.push(RecordSummary {
            path,
            timestamp: record.timestamp,
            target: record.target,
            host_count: record.hosts.len(),
            open_port_count: record
                .hosts
                .iter()
                .map(|host| {
                    host.ports
                        .iter()
                        .filter(|port| port.state == "open")
                        .count()
                })
                .sum(),
        });
    }
    // Newest first; break timestamp ties by path so the order is stable.
    summaries.sort_by(|a, b| {
        b.timestamp
            .cmp(&a.timestamp)
            .then_with(|| a.path.cmp(&b.path))
    });
    Ok(summaries)
}

/// The current instant as Unix seconds.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Convenience wrapper used by the TUI: resolve the data directory, build the
/// record for the finished scan, and persist it. Returns the written path.
pub fn save_scan(target: &ScanTarget, hosts: &[Host], config: &ScanConfig) -> io::Result<PathBuf> {
    let record = ScanRecord::from_scan(target, hosts, config, now_unix_secs());
    let dir = data_dir()?;
    save(&dir, &record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{Host, MacAddress, Port, PortState, ProbedPort, ServiceInfo};
    use crate::ports::{PortConfig, PortSpec};
    use crate::scanner::{DiscoveryConfig, ScanConfig};
    use std::time::Duration;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "port-scanner-storage-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn test_config() -> ScanConfig {
        ScanConfig {
            target: ScanTarget::parse("192.168.1.0/24").expect("valid subnet"),
            discovery: DiscoveryConfig {
                timeout: Duration::from_millis(350),
                concurrency: 64,
            },
            ports: PortConfig {
                ports: PortSpec::from_port_numbers([80u16, 443, 22]),
                timeout: Duration::from_millis(250),
                concurrency: 32,
            },
            detect_services: true,
            enrich: false,
        }
    }

    fn host_with_ports() -> Host {
        let mut host = Host::up("192.168.1.10".parse().unwrap(), Duration::from_millis(3));
        host.hostname = Some("router".to_owned());
        host.mac = Some(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        host.vendor = Some("Vendor Co".to_owned());
        host.ports = vec![
            ProbedPort {
                port: Port::new(80).unwrap(),
                state: PortState::Open,
                service: Some(ServiceInfo {
                    name: "http".to_owned(),
                    version: Some("nginx/1.18".to_owned()),
                    extra: None,
                }),
            },
            ProbedPort {
                port: Port::new(22).unwrap(),
                state: PortState::Open,
                service: Some(ServiceInfo {
                    name: "ssh".to_owned(),
                    version: None,
                    extra: Some("OpenSSH_8.4".to_owned()),
                }),
            },
            ProbedPort {
                port: Port::new(443).unwrap(),
                state: PortState::Closed,
                service: None,
            },
        ];
        host
    }

    #[test]
    fn record_round_trip() {
        let config = test_config();
        let hosts = vec![host_with_ports()];
        let record = ScanRecord::from_scan(&config.target, &hosts, &config, 1_700_000_000);
        let json = serde_json::to_string_pretty(&record).expect("serialize");
        let back: ScanRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, back);
    }

    #[test]
    fn from_scan_maps_fields() {
        let config = test_config();
        let hosts = vec![host_with_ports()];
        let record = ScanRecord::from_scan(&config.target, &hosts, &config, 123);
        assert_eq!(record.version, CURRENT_VERSION);
        assert_eq!(record.timestamp, 123);
        assert_eq!(record.target, "192.168.1.0/24");
        assert_eq!(record.config.discovery_timeout_ms, 350);
        assert_eq!(record.config.discovery_concurrency, 64);
        // Ports are stored in ascending order.
        assert_eq!(record.config.ports, vec![22, 80, 443]);
        assert_eq!(record.config.port_timeout_ms, 250);
        assert_eq!(record.config.port_concurrency, 32);
        assert!(record.config.detect_services);
        assert!(!record.config.enrich);

        let host = &record.hosts[0];
        assert_eq!(host.ip, "192.168.1.10");
        assert_eq!(host.state, "up");
        assert_eq!(host.latency_ms, Some(3.0));
        assert_eq!(host.hostname.as_deref(), Some("router"));
        assert_eq!(host.mac.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(host.vendor.as_deref(), Some("Vendor Co"));
        assert_eq!(host.ports.len(), 3);
        let open = &host.ports[0];
        assert_eq!(open.port, 80);
        assert_eq!(open.protocol, "tcp");
        assert_eq!(open.state, "open");
        assert_eq!(open.service.as_ref().unwrap().name, "http");
        assert_eq!(
            open.service.as_ref().unwrap().version.as_deref(),
            Some("nginx/1.18")
        );
        assert!(open.service.as_ref().unwrap().extra.is_none());
        let closed = &host.ports[2];
        assert_eq!(closed.state, "closed");
        assert!(closed.service.is_none());
    }

    #[test]
    fn save_load_round_trip() {
        let dir = temp_dir("save_load");
        let config = test_config();
        let hosts = vec![host_with_ports()];
        let record = ScanRecord::from_scan(&config.target, &hosts, &config, 1_700_000_000);
        let path = save(&dir, &record).expect("save");
        assert!(path.exists());
        let back = load(&path).expect("load");
        assert_eq!(record, back);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_path_uses_timestamp_and_slug() {
        let config = test_config();
        let record = ScanRecord::from_scan(&config.target, &[], &config, 42);
        let path = record_path(Path::new("/tmp/x"), &record);
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some("42_192.168.1.0_24.json")
        );
    }

    #[test]
    fn next_record_path_avoids_collision() {
        let dir = temp_dir("collision");
        let config = test_config();
        let record = ScanRecord::from_scan(&config.target, &[], &config, 42);
        let first = record_path(&dir, &record);
        fs::write(&first, "{}").expect("seed collision");
        let next = next_record_path(&dir, &record).expect("next path");
        assert_eq!(
            next.file_name().and_then(|s| s.to_str()),
            Some("42_192.168.1.0_24-2.json")
        );
        // A second collision bumps to the next suffix.
        fs::write(&next, "{}").expect("seed second collision");
        let next2 = next_record_path(&dir, &record).expect("next path");
        assert_eq!(
            next2.file_name().and_then(|s| s.to_str()),
            Some("42_192.168.1.0_24-3.json")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_file_errors() {
        let dir = temp_dir("missing");
        let err = load(&dir.join("nope.json")).expect_err("missing file");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_invalid_json_errors() {
        let dir = temp_dir("invalid");
        let path = dir.join("bad.json");
        fs::write(&path, "this is not json").expect("write");
        let err = load(&path).expect_err("invalid json");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_records_orders_newest_first() {
        let dir = temp_dir("list_order");
        let config = test_config();
        let hosts = vec![host_with_ports()];
        let older = ScanRecord::from_scan(&config.target, &hosts, &config, 1_700_000_000);
        let newer = ScanRecord::from_scan(&config.target, &hosts, &config, 1_700_000_900);
        save(&dir, &older).expect("save older");
        save(&dir, &newer).expect("save newer");

        let summaries = list_records(&dir).expect("list");
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].timestamp, 1_700_000_900);
        assert_eq!(summaries[1].timestamp, 1_700_000_000);
        for summary in &summaries {
            assert_eq!(summary.target, "192.168.1.0/24");
            assert_eq!(summary.host_count, 1);
            assert_eq!(summary.open_port_count, 2);
            assert!(summary.path.exists());
        }
        // The summaries point at the two distinct written files.
        assert_ne!(summaries[0].path, summaries[1].path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_records_counts_open_ports() {
        let dir = temp_dir("list_counts");
        let config = test_config();
        let mut host = Host::up("192.168.1.10".parse().unwrap(), Duration::from_millis(3));
        host.ports = vec![
            ProbedPort {
                port: Port::new(80).unwrap(),
                state: PortState::Open,
                service: None,
            },
            ProbedPort {
                port: Port::new(22).unwrap(),
                state: PortState::Closed,
                service: None,
            },
        ];
        let record = ScanRecord::from_scan(&config.target, &[host], &config, 1_700_000_000);
        save(&dir, &record).expect("save");

        let summaries = list_records(&dir).expect("list");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].host_count, 1);
        assert_eq!(summaries[0].open_port_count, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_records_skips_non_json_and_invalid_records() {
        let dir = temp_dir("list_skip");
        let config = test_config();
        let record =
            ScanRecord::from_scan(&config.target, &[host_with_ports()], &config, 1_700_000_000);
        save(&dir, &record).expect("save");
        fs::write(dir.join("notes.txt"), "not a record").expect("write");
        fs::write(dir.join("1699999999_bad.json"), "not json").expect("write");

        let summaries = list_records(&dir).expect("list");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].timestamp, 1_700_000_000);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_records_missing_dir_yields_empty() {
        let dir = temp_dir("list_missing").join("does-not-exist");
        let summaries = list_records(&dir).expect("list");
        assert!(summaries.is_empty());
    }

    #[test]
    fn resolve_data_dir_prefers_absolute_xdg() {
        let dir = resolve_data_dir(Some("/custom/data"), Some("/home/u")).expect("xdg");
        assert_eq!(dir, Path::new("/custom/data/port-scanner"));
    }

    #[test]
    fn resolve_data_dir_falls_back_to_home() {
        let dir = resolve_data_dir(None, Some("/home/u")).expect("home");
        assert_eq!(dir, Path::new("/home/u/.local/share/port-scanner"));
        // An empty XDG_DATA_HOME is treated as unset.
        let dir = resolve_data_dir(Some(""), Some("/home/u")).expect("home");
        assert_eq!(dir, Path::new("/home/u/.local/share/port-scanner"));
    }

    #[test]
    fn resolve_data_dir_rejects_relative_xdg() {
        let err = resolve_data_dir(Some("relative"), Some("/home/u")).expect_err("relative");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn resolve_data_dir_requires_home_when_no_xdg() {
        let err = resolve_data_dir(None, None).expect_err("no home");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn target_slug_normalizes() {
        assert_eq!(target_slug("192.168.1.0/24"), "192.168.1.0_24");
        assert_eq!(target_slug("Host.Example.COM"), "host.example.com");
        assert_eq!(target_slug("10.0.0.5"), "10.0.0.5");
        assert_eq!(target_slug("a b/c"), "a_b_c");
    }
}
