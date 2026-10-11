//! Compare two saved scans and structure the differences for display (Phase 15).
//!
//! The diff is computed over the storage record types ([`crate::storage`]) —
//! pure structured data, with no file I/O and no dependency on the TUI. The
//! result is a [`ScanDiff`]: a fixed set of categories that the TUI renders
//! readably.
//!
//! Comparison rules:
//! - A host present in one record and absent in the other is added or
//!   removed; its `open_ports` lists the ports open on the side where the
//!   host is present.
//! - Ports are compared over the union of port numbers; a port absent from a
//!   record is treated as closed there.
//! - A port open in both records with a different service label is a service
//!   change.
//! - Host state, hostname, MAC, and vendor are compared; latency is excluded
//!   because it is noisy and not a meaningful "change".

use std::collections::{BTreeMap, BTreeSet};

use crate::storage::{RecordHost, RecordPort, ScanRecord};

/// A host present in one scan but not the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostChange {
    /// The host's IPv4 address.
    pub ip: String,
    /// Ports open on the side where the host is present.
    pub open_ports: Vec<u16>,
}

/// A port whose open/closed state changed between two scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortChange {
    /// The host's IPv4 address.
    pub ip: String,
    /// The port number.
    pub port: u16,
    /// Service label on the open side, when the port is open there.
    pub service: Option<String>,
}

/// The host fields that are compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostField {
    /// Liveness (`up`/`down`).
    State,
    /// Resolved hostname.
    Hostname,
    /// MAC address.
    Mac,
    /// Vendor inferred from the MAC OUI.
    Vendor,
}

impl HostField {
    /// The field's display name.
    pub fn name(self) -> &'static str {
        match self {
            HostField::State => "state",
            HostField::Hostname => "hostname",
            HostField::Mac => "mac",
            HostField::Vendor => "vendor",
        }
    }
}

/// One host field that changed between two scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFieldChange {
    /// The field that changed.
    pub field: HostField,
    /// The value in the earlier record (missing data is `None`).
    pub before: Option<String>,
    /// The value in the later record (missing data is `None`).
    pub after: Option<String>,
}

/// A host whose non-port information changed between two scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInfoChange {
    /// The host's IPv4 address.
    pub ip: String,
    /// The individual field changes.
    pub changes: Vec<HostFieldChange>,
}

/// A port open in both scans whose detected service changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceChange {
    /// The host's IPv4 address.
    pub ip: String,
    /// The port number.
    pub port: u16,
    /// Service label in the earlier record.
    pub before: Option<String>,
    /// Service label in the later record.
    pub after: Option<String>,
}

/// The structured result of comparing two saved scans.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanDiff {
    /// Hosts present in the later scan but not the earlier one.
    pub hosts_added: Vec<HostChange>,
    /// Hosts present in the earlier scan but not the later one.
    pub hosts_removed: Vec<HostChange>,
    /// Ports that went from closed to open.
    pub ports_opened: Vec<PortChange>,
    /// Ports that went from open to closed.
    pub ports_closed: Vec<PortChange>,
    /// Hosts whose state, hostname, MAC, or vendor changed.
    pub hosts_changed: Vec<HostInfoChange>,
    /// Ports open in both scans whose service label changed.
    pub services_changed: Vec<ServiceChange>,
}

impl ScanDiff {
    /// Whether the two records are indistinguishable under the comparison
    /// rules.
    pub fn is_empty(&self) -> bool {
        self.hosts_added.is_empty()
            && self.hosts_removed.is_empty()
            && self.ports_opened.is_empty()
            && self.ports_closed.is_empty()
            && self.hosts_changed.is_empty()
            && self.services_changed.is_empty()
    }
}

/// Compare two saved scans, returning the structured differences.
///
/// `before` is the earlier scan and `after` the later one.
pub fn diff_records(before: &ScanRecord, after: &ScanRecord) -> ScanDiff {
    let before_hosts = hosts_by_ip(before);
    let after_hosts = hosts_by_ip(after);
    let mut diff = ScanDiff::default();

    // `after` first so added and per-host changes are emitted in IP order.
    for (ip, after_host) in &after_hosts {
        match before_hosts.get(ip) {
            None => diff.hosts_added.push(HostChange {
                ip: (*ip).to_string(),
                open_ports: open_ports(after_host),
            }),
            Some(before_host) => compare_host(&mut diff, before_host, after_host),
        }
    }
    for (ip, before_host) in &before_hosts {
        if !after_hosts.contains_key(ip) {
            diff.hosts_removed.push(HostChange {
                ip: (*ip).to_string(),
                open_ports: open_ports(before_host),
            });
        }
    }

    diff
}

/// Index a record's hosts by IP, in sorted IP order.
fn hosts_by_ip(record: &ScanRecord) -> BTreeMap<&str, &RecordHost> {
    record
        .hosts
        .iter()
        .map(|host| (host.ip.as_str(), host))
        .collect()
}

/// The ports open on a host, in ascending port order.
fn open_ports(host: &RecordHost) -> Vec<u16> {
    host.ports
        .iter()
        .filter(|port| port.state == "open")
        .map(|port| port.port)
        .collect::<BTreeSet<u16>>()
        .into_iter()
        .collect()
}

/// The display label for a detected service: `name`, or `name version` when a
/// version was detected.
fn service_label(port: &RecordPort) -> Option<String> {
    let service = port.service.as_ref()?;
    Some(match service.version.as_deref() {
        Some(version) => format!("{} {}", service.name, version),
        None => service.name.clone(),
    })
}

/// Compare the ports and host information of a host present in both records.
fn compare_host(diff: &mut ScanDiff, before: &RecordHost, after: &RecordHost) {
    let before_ports: BTreeMap<u16, &RecordPort> =
        before.ports.iter().map(|port| (port.port, port)).collect();
    let after_ports: BTreeMap<u16, &RecordPort> =
        after.ports.iter().map(|port| (port.port, port)).collect();
    let port_numbers: BTreeSet<u16> = before_ports
        .keys()
        .copied()
        .chain(after_ports.keys().copied())
        .collect();

    for port in port_numbers {
        let before_port = before_ports.get(&port).copied();
        let after_port = after_ports.get(&port).copied();
        let before_open = before_port.is_some_and(|port| port.state == "open");
        let after_open = after_port.is_some_and(|port| port.state == "open");
        match (before_open, after_open) {
            (false, true) => diff.ports_opened.push(PortChange {
                ip: after.ip.clone(),
                port,
                service: after_port.and_then(service_label),
            }),
            (true, false) => diff.ports_closed.push(PortChange {
                ip: after.ip.clone(),
                port,
                service: before_port.and_then(service_label),
            }),
            (true, true) => {
                let before_service = before_port.and_then(service_label);
                let after_service = after_port.and_then(service_label);
                if before_service != after_service {
                    diff.services_changed.push(ServiceChange {
                        ip: after.ip.clone(),
                        port,
                        before: before_service,
                        after: after_service,
                    });
                }
            }
            (false, false) => {}
        }
    }

    let mut changes = Vec::new();
    compare_field(
        &mut changes,
        HostField::State,
        Some(before.state.as_str()),
        Some(after.state.as_str()),
    );
    compare_field(
        &mut changes,
        HostField::Hostname,
        before.hostname.as_deref(),
        after.hostname.as_deref(),
    );
    compare_field(
        &mut changes,
        HostField::Mac,
        before.mac.as_deref(),
        after.mac.as_deref(),
    );
    compare_field(
        &mut changes,
        HostField::Vendor,
        before.vendor.as_deref(),
        after.vendor.as_deref(),
    );
    if !changes.is_empty() {
        diff.hosts_changed.push(HostInfoChange {
            ip: after.ip.clone(),
            changes,
        });
    }
}

/// Record a field change when the two values differ.
fn compare_field(
    changes: &mut Vec<HostFieldChange>,
    field: HostField,
    before: Option<&str>,
    after: Option<&str>,
) {
    if before != after {
        changes.push(HostFieldChange {
            field,
            before: before.map(str::to_owned),
            after: after.map(str::to_owned),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{RecordConfig, RecordService};

    fn config() -> RecordConfig {
        RecordConfig {
            discovery_timeout_ms: 350,
            discovery_concurrency: 64,
            ports: vec![22, 80],
            port_timeout_ms: 250,
            port_concurrency: 32,
            detect_services: true,
            enrich: false,
        }
    }

    fn record(timestamp: u64, hosts: Vec<RecordHost>) -> ScanRecord {
        ScanRecord {
            version: crate::storage::CURRENT_VERSION,
            timestamp,
            target: "192.168.1.0/24".to_string(),
            config: config(),
            hosts,
        }
    }

    fn host(ip: &str, ports: Vec<RecordPort>) -> RecordHost {
        RecordHost {
            ip: ip.to_string(),
            state: "up".to_string(),
            latency_ms: Some(3.0),
            hostname: None,
            mac: None,
            vendor: None,
            ports,
        }
    }

    fn port(port: u16, open: bool, service: Option<RecordService>) -> RecordPort {
        RecordPort {
            port,
            protocol: "tcp".to_string(),
            state: if open { "open" } else { "closed" }.to_string(),
            service,
        }
    }

    fn service(name: &str, version: Option<&str>) -> RecordService {
        RecordService {
            name: name.to_string(),
            version: version.map(str::to_owned),
            extra: None,
        }
    }

    #[test]
    fn identical_records_produce_empty_diff() {
        let before = record(
            1,
            vec![host(
                "192.168.1.10",
                vec![
                    port(80, true, Some(service("http", None))),
                    port(22, false, None),
                ],
            )],
        );
        let after = record(
            2,
            vec![host(
                "192.168.1.10",
                vec![
                    port(80, true, Some(service("http", None))),
                    port(22, false, None),
                ],
            )],
        );
        assert!(diff_records(&before, &after).is_empty());
    }

    #[test]
    fn host_added_and_removed() {
        let before = record(1, vec![host("192.168.1.10", vec![port(80, true, None)])]);
        let after = record(2, vec![host("192.168.1.11", vec![port(22, true, None)])]);

        let diff = diff_records(&before, &after);
        assert_eq!(
            diff.hosts_added,
            vec![HostChange {
                ip: "192.168.1.11".to_string(),
                open_ports: vec![22],
            }]
        );
        assert_eq!(
            diff.hosts_removed,
            vec![HostChange {
                ip: "192.168.1.10".to_string(),
                open_ports: vec![80],
            }]
        );
    }

    #[test]
    fn ports_opened_and_closed() {
        let before = record(
            1,
            vec![host(
                "192.168.1.10",
                vec![
                    port(80, true, Some(service("http", None))),
                    port(22, false, None),
                ],
            )],
        );
        let after = record(
            2,
            vec![host(
                "192.168.1.10",
                vec![
                    port(80, false, None),
                    port(22, true, Some(service("ssh", None))),
                ],
            )],
        );

        let diff = diff_records(&before, &after);
        assert_eq!(
            diff.ports_opened,
            vec![PortChange {
                ip: "192.168.1.10".to_string(),
                port: 22,
                service: Some("ssh".to_string()),
            }]
        );
        assert_eq!(
            diff.ports_closed,
            vec![PortChange {
                ip: "192.168.1.10".to_string(),
                port: 80,
                service: Some("http".to_string()),
            }]
        );
    }

    #[test]
    fn absent_port_is_treated_as_closed() {
        let before = record(1, vec![host("192.168.1.10", vec![port(80, true, None)])]);
        // The later record does not even contain port 80.
        let after = record(2, vec![host("192.168.1.10", vec![])]);

        let diff = diff_records(&before, &after);
        assert_eq!(
            diff.ports_closed,
            vec![PortChange {
                ip: "192.168.1.10".to_string(),
                port: 80,
                service: None,
            }]
        );
        assert!(diff.ports_opened.is_empty());
    }

    #[test]
    fn service_label_includes_version() {
        let before = record(
            1,
            vec![host(
                "192.168.1.10",
                vec![port(80, true, Some(service("http", None)))],
            )],
        );
        let after = record(
            2,
            vec![host(
                "192.168.1.10",
                vec![port(80, true, Some(service("http", Some("2.0"))))],
            )],
        );

        let diff = diff_records(&before, &after);
        assert_eq!(
            diff.services_changed,
            vec![ServiceChange {
                ip: "192.168.1.10".to_string(),
                port: 80,
                before: Some("http".to_string()),
                after: Some("http 2.0".to_string()),
            }]
        );
        assert!(diff.ports_opened.is_empty());
        assert!(diff.ports_closed.is_empty());
    }

    #[test]
    fn equal_services_are_not_changes() {
        let before = record(
            1,
            vec![host(
                "192.168.1.10",
                vec![port(80, true, Some(service("http", Some("2.0"))))],
            )],
        );
        let after = record(
            2,
            vec![host(
                "192.168.1.10",
                vec![port(80, true, Some(service("http", Some("2.0"))))],
            )],
        );
        assert!(diff_records(&before, &after).is_empty());
    }

    #[test]
    fn service_appearing_or_disappearing_is_a_change() {
        // Service detected later, where it was absent before.
        let before = record(1, vec![host("192.168.1.10", vec![port(22, true, None)])]);
        let after = record(
            2,
            vec![host(
                "192.168.1.10",
                vec![port(22, true, Some(service("ssh", None)))],
            )],
        );
        let diff = diff_records(&before, &after);
        assert_eq!(
            diff.services_changed,
            vec![ServiceChange {
                ip: "192.168.1.10".to_string(),
                port: 22,
                before: None,
                after: Some("ssh".to_string()),
            }]
        );

        // Service present before, absent later (detection failed).
        let diff = diff_records(&after, &before);
        assert_eq!(
            diff.services_changed,
            vec![ServiceChange {
                ip: "192.168.1.10".to_string(),
                port: 22,
                before: Some("ssh".to_string()),
                after: None,
            }]
        );
    }

    #[test]
    fn host_field_changes_are_reported_per_field() {
        let mut before_host = host("192.168.1.10", vec![port(80, true, None)]);
        before_host.hostname = Some("router".to_string());
        before_host.mac = Some("00:11:22:33:44:55".to_string());
        before_host.vendor = Some("Vendor Co".to_string());

        let mut after_host = host("192.168.1.10", vec![port(80, true, None)]);
        after_host.hostname = Some("gateway".to_string());
        after_host.mac = Some("00:11:22:33:44:55".to_string());
        after_host.vendor = Some("Vendor Co".to_string());

        let before = record(1, vec![before_host]);
        let after = record(2, vec![after_host]);

        let diff = diff_records(&before, &after);
        assert_eq!(diff.hosts_changed.len(), 1);
        assert_eq!(diff.hosts_changed[0].ip, "192.168.1.10");
        assert_eq!(
            diff.hosts_changed[0].changes,
            vec![HostFieldChange {
                field: HostField::Hostname,
                before: Some("router".to_string()),
                after: Some("gateway".to_string()),
            }]
        );
    }

    #[test]
    fn enrichment_appearing_is_a_field_change() {
        let before = record(1, vec![host("192.168.1.10", vec![port(80, true, None)])]);
        let mut after_host = host("192.168.1.10", vec![port(80, true, None)]);
        after_host.mac = Some("00:11:22:33:44:55".to_string());
        let after = record(2, vec![after_host]);

        let diff = diff_records(&before, &after);
        assert_eq!(
            diff.hosts_changed[0].changes,
            vec![HostFieldChange {
                field: HostField::Mac,
                before: None,
                after: Some("00:11:22:33:44:55".to_string()),
            }]
        );
    }

    #[test]
    fn state_change_is_reported() {
        let before_host = host("192.168.1.10", vec![]);
        let mut after_host = host("192.168.1.10", vec![]);
        after_host.state = "down".to_string();
        let before = record(1, vec![before_host]);
        let after = record(2, vec![after_host]);

        let diff = diff_records(&before, &after);
        assert_eq!(
            diff.hosts_changed[0].changes,
            vec![HostFieldChange {
                field: HostField::State,
                before: Some("up".to_string()),
                after: Some("down".to_string()),
            }]
        );
    }

    #[test]
    fn latency_changes_are_ignored() {
        let mut before_host = host("192.168.1.10", vec![]);
        before_host.latency_ms = Some(1.0);
        let mut after_host = host("192.168.1.10", vec![]);
        after_host.latency_ms = Some(9.0);
        let before = record(1, vec![before_host]);
        let after = record(2, vec![after_host]);

        assert!(diff_records(&before, &after).is_empty());
    }

    #[test]
    fn results_are_ordered_by_ip_and_port() {
        // Hosts out of order in the record; ports out of order per host.
        let before = record(
            1,
            vec![
                host(
                    "192.168.1.20",
                    vec![port(80, false, None), port(22, true, None)],
                ),
                host(
                    "192.168.1.10",
                    vec![port(443, true, None), port(80, true, None)],
                ),
            ],
        );
        let after = record(
            2,
            vec![
                host(
                    "192.168.1.20",
                    vec![port(80, true, None), port(22, false, None)],
                ),
                host(
                    "192.168.1.10",
                    vec![port(443, false, None), port(80, false, None)],
                ),
            ],
        );

        let diff = diff_records(&before, &after);
        let opened: Vec<(String, u16)> = diff
            .ports_opened
            .iter()
            .map(|c| (c.ip.clone(), c.port))
            .collect();
        assert_eq!(opened, vec![("192.168.1.20".to_string(), 80)]);
        let closed: Vec<(String, u16)> = diff
            .ports_closed
            .iter()
            .map(|c| (c.ip.clone(), c.port))
            .collect();
        // Hosts are in IP order; within a host, ports are ascending.
        assert_eq!(
            closed,
            vec![
                ("192.168.1.10".to_string(), 80),
                ("192.168.1.10".to_string(), 443),
                ("192.168.1.20".to_string(), 22),
            ]
        );
        assert!(diff.hosts_changed.is_empty());
    }
}
