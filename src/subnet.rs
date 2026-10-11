//! Grouping of discovered hosts by /24 subnet.
//!
//! Pure, presentation-level logic for the network view (`PLAN.md` Phase
//! 16). Hosts are grouped by /24 subnet (first three octets) for
//! organizational display only; this claims no topology and never expands
//! or changes the scan scope.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::network::Host;

/// A group of discovered hosts sharing the same /24 network address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubnetGroup<'a> {
    /// The /24 network address (last octet zeroed) that identifies the
    /// group.
    pub network: Ipv4Addr,
    /// The hosts in this group, sorted ascending by IP address.
    pub hosts: Vec<&'a Host>,
}

/// The /24 network address for the given IP (last octet zeroed).
pub fn network_of(ip: Ipv4Addr) -> Ipv4Addr {
    let octets = ip.octets();
    Ipv4Addr::new(octets[0], octets[1], octets[2], 0)
}

/// Group the given hosts by /24 subnet.
///
/// Groups are returned sorted ascending by network address and the hosts
/// within each group are sorted ascending by IP address, so the output is
/// independent of the input order. Every input host appears in exactly one
/// group.
pub fn group_by_subnet<'a>(hosts: &'a [Host]) -> Vec<SubnetGroup<'a>> {
    let mut by_network: BTreeMap<Ipv4Addr, Vec<&'a Host>> = BTreeMap::new();
    for host in hosts {
        by_network
            .entry(network_of(host.ip))
            .or_default()
            .push(host);
    }
    by_network
        .into_iter()
        .map(|(network, mut group_hosts)| {
            group_hosts.sort_by(|a, b| a.ip.cmp(&b.ip));
            SubnetGroup {
                network,
                hosts: group_hosts,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn host(ip: &str, up: bool) -> Host {
        if up {
            Host::up(ip.parse().unwrap(), Duration::from_millis(1))
        } else {
            Host::down(ip.parse().unwrap())
        }
    }

    #[test]
    fn network_of_zeros_last_octet() {
        assert_eq!(
            network_of("192.168.1.42".parse().unwrap()),
            "192.168.1.0".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            network_of("10.0.0.1".parse().unwrap()),
            "10.0.0.0".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            network_of("255.255.255.255".parse().unwrap()),
            "255.255.255.0".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn empty_input_yields_no_groups() {
        assert!(group_by_subnet(&[]).is_empty());
    }

    #[test]
    fn all_hosts_in_one_subnet_form_a_single_sorted_group() {
        let hosts = vec![
            host("192.168.1.10", true),
            host("192.168.1.20", true),
            host("192.168.1.1", false),
        ];
        let groups = group_by_subnet(&hosts);
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].network,
            "192.168.1.0".parse::<Ipv4Addr>().unwrap()
        );
        let ips: Vec<String> = groups[0].hosts.iter().map(|h| h.ip.to_string()).collect();
        assert_eq!(ips, vec!["192.168.1.1", "192.168.1.10", "192.168.1.20"]);
    }

    #[test]
    fn multiple_subnets_are_sorted_and_input_order_is_ignored() {
        // Deliberately unsorted input: out-of-order groups and hosts.
        let hosts = vec![
            host("192.168.3.50", true),
            host("10.0.0.7", false),
            host("192.168.1.200", true),
            host("192.168.3.2", true),
            host("10.0.0.100", true),
            host("192.168.1.42", true),
        ];
        let groups = group_by_subnet(&hosts);
        assert_eq!(groups.len(), 3);

        let networks: Vec<Ipv4Addr> = groups.iter().map(|g| g.network).collect();
        let expected_networks: Vec<Ipv4Addr> = ["10.0.0.0", "192.168.1.0", "192.168.3.0"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(networks, expected_networks);

        let group_ips: Vec<Vec<String>> = groups
            .iter()
            .map(|g| g.hosts.iter().map(|h| h.ip.to_string()).collect())
            .collect();
        assert_eq!(
            group_ips,
            vec![
                vec!["10.0.0.7", "10.0.0.100"],
                vec!["192.168.1.42", "192.168.1.200"],
                vec!["192.168.3.2", "192.168.3.50"],
            ]
        );
    }

    #[test]
    fn grouping_preserves_all_hosts() {
        let hosts = vec![
            host("172.16.5.1", true),
            host("172.16.5.2", true),
            host("172.17.0.9", false),
        ];
        let groups = group_by_subnet(&hosts);
        assert_eq!(groups.len(), 2);
        let total: usize = groups.iter().map(|g| g.hosts.len()).sum();
        assert_eq!(total, hosts.len());
    }
}
