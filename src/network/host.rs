//! Host data model.

use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

/// The liveness state of a host, as determined by the scanner.
///
/// Only states that the implemented discovery mechanism can actually
/// determine are represented. ICMP echo discovery resolves every probed
/// address to either [`Up`] (a reply was received) or [`Down`] (no reply
/// within the timeout).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostState {
    /// The host responded and is considered up.
    Up,
    /// The host did not respond and is considered down.
    Down,
}

impl fmt::Display for HostState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostState::Up => write!(f, "UP"),
            HostState::Down => write!(f, "DOWN"),
        }
    }
}

/// A host discovered by the scanner and its current state.
///
/// Fields whose functionality has not yet been implemented (hostname, MAC
/// address, vendor, open ports) are intentionally omitted; see `PLAN.md` for
/// the full conceptual model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// The host's IPv4 address.
    pub ip: Ipv4Addr,
    /// Whether the host is up or down.
    pub state: HostState,
    /// Round-trip time of the probe, present only when the host is [`Up`].
    pub latency: Option<Duration>,
}

impl Host {
    /// Create a host that responded to the probe with the given round-trip
    /// time.
    pub fn up(ip: Ipv4Addr, latency: Duration) -> Self {
        Self {
            ip,
            state: HostState::Up,
            latency: Some(latency),
        }
    }

    /// Create a host that did not respond to the probe.
    pub fn down(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            state: HostState::Down,
            latency: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn up_host_carries_latency() {
        let host = Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(5));
        assert_eq!(host.state, HostState::Up);
        assert_eq!(host.latency, Some(Duration::from_millis(5)));
        assert_eq!(host.ip, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn down_host_has_no_latency() {
        let host = Host::down("10.0.0.2".parse().unwrap());
        assert_eq!(host.state, HostState::Down);
        assert_eq!(host.latency, None);
        assert_eq!(host.ip, "10.0.0.2".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn state_displays_uppercase() {
        assert_eq!(HostState::Up.to_string(), "UP");
        assert_eq!(HostState::Down.to_string(), "DOWN");
    }

    #[test]
    fn hosts_with_same_fields_are_equal() {
        let a = Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(5));
        let b = Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(5));
        let c = Host::down("10.0.0.1".parse().unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
