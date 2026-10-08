//! Parsing and validation of scan targets.
//!
//! A [`ScanTarget`] is the structured form of what the user asks port-scanner to
//! scan: either a single IPv4 host or an IPv4 CIDR subnet. Parsing is the
//! single gate through which CLI input enters the application, so invalid
//! input is rejected here with a clear error instead of panicking later.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;

/// Maximum number of addresses a single target may contain.
///
/// Subnets larger than this (smaller prefix than `/16`) are rejected to
/// prevent accidental unbounded scans. The limit can become configurable
/// once scan configuration exists (Phase 5).
pub const MAX_SUBNET_SIZE: u64 = 65_536;

/// A validated scan target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScanTarget {
    /// A single IPv4 address, e.g. `192.168.1.1`.
    Host(Ipv4Addr),
    /// An IPv4 CIDR subnet, e.g. `192.168.1.0/24`.
    ///
    /// The stored network is normalized: host bits are truncated, so
    /// `192.168.1.1/24` is stored as `192.168.1.0/24`.
    Subnet(Ipv4Net),
}

impl ScanTarget {
    /// Parse a user-supplied target string.
    ///
    /// Accepted forms: a single IPv4 address (`10.0.0.1`) or an IPv4 CIDR
    /// range (`10.0.0.0/28`). Surrounding whitespace is ignored.
    pub fn parse(input: &str) -> Result<Self, TargetError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(TargetError::Empty);
        }

        let target = if let Some((addr_part, prefix_part)) = input.split_once('/') {
            Self::parse_subnet(input, addr_part, prefix_part)?
        } else {
            Self::parse_host(input)?
        };

        let hosts = target.len();
        if hosts > MAX_SUBNET_SIZE {
            return Err(TargetError::TooManyHosts {
                input: input.to_owned(),
                hosts,
                max: MAX_SUBNET_SIZE,
            });
        }

        Ok(target)
    }

    fn parse_host(input: &str) -> Result<Self, TargetError> {
        let ip: IpAddr = input.parse().map_err(|_| TargetError::Parse {
            input: input.to_owned(),
            reason: "not a valid IPv4 address".to_owned(),
        })?;

        match ip {
            IpAddr::V4(v4) => Ok(ScanTarget::Host(v4)),
            IpAddr::V6(_) => Err(TargetError::Ipv6NotSupported {
                input: input.to_owned(),
            }),
        }
    }

    fn parse_subnet(input: &str, addr_part: &str, prefix_part: &str) -> Result<Self, TargetError> {
        let ip: IpAddr = addr_part.parse().map_err(|_| TargetError::Parse {
            input: input.to_owned(),
            reason: format!("'{addr_part}' is not a valid IPv4 address"),
        })?;

        let v4 = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return Err(TargetError::Ipv6NotSupported {
                    input: input.to_owned(),
                })
            }
        };

        let prefix: u8 = prefix_part.parse().map_err(|_| TargetError::Parse {
            input: input.to_owned(),
            reason: format!("'{prefix_part}' is not a valid prefix length (expected 0-32)"),
        })?;

        let net = Ipv4Net::new(v4, prefix).map_err(|_| TargetError::Parse {
            input: input.to_owned(),
            reason: format!("prefix length {prefix} is out of range (expected 0-32)"),
        })?;

        Ok(ScanTarget::Subnet(net.trunc()))
    }

    /// Number of addresses in the target (a single host counts as 1).
    ///
    /// There is deliberately no `is_empty()`: every valid target contains at
    /// least one address, so it would always return `false`.
    pub fn len(&self) -> u64 {
        match self {
            ScanTarget::Host(_) => 1,
            ScanTarget::Subnet(net) => (u32::from(net.hostmask()) as u64) + 1,
        }
    }

    /// Iterate over every address in the target, in ascending order.
    ///
    /// Unlike [`Ipv4Net::hosts`], this yields *all* addresses in the range,
    /// including the network and broadcast addresses. That matches the scan
    /// scope contract: the user asked for a range, so every address in it is
    /// probed. The count of items yielded is always [`ScanTarget::len`].
    pub fn iter(&self) -> ScanTargetIter {
        let (start, end) = match self {
            ScanTarget::Host(ip) => (*ip, *ip),
            ScanTarget::Subnet(net) => (net.network(), net.broadcast()),
        };
        ScanTargetIter {
            current: Some(start),
            end,
        }
    }
}

/// Iterator over the addresses of a [`ScanTarget`].
///
/// Yielded in ascending numeric order and always terminates after exactly
/// [`ScanTarget::len`] items, even for the largest possible address
/// (`255.255.255.255/32`), because the range never wraps.
#[derive(Debug, Clone)]
pub struct ScanTargetIter {
    current: Option<Ipv4Addr>,
    end: Ipv4Addr,
}

impl Iterator for ScanTargetIter {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Ipv4Addr> {
        let cur = self.current?;
        // Yield the current address; stop once it is the last in the range.
        // Because we only advance while `cur < end`, `cur + 1` can never
        // overflow past `u32::MAX`.
        if u32::from(cur) >= u32::from(self.end) {
            self.current = None;
        } else {
            self.current = Some(Ipv4Addr::from(u32::from(cur) + 1));
        }
        Some(cur)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = match self.current {
            None => 0,
            Some(cur) => (u32::from(self.end) - u32::from(cur)) as usize + 1,
        };
        (remaining, Some(remaining))
    }
}

// Discovery only ever iterates forward, so the iterator is intentionally
// not double-ended.
impl ExactSizeIterator for ScanTargetIter {}

impl fmt::Display for ScanTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanTarget::Host(ip) => write!(f, "{ip}"),
            ScanTarget::Subnet(net) => write!(f, "{}/{}", net.network(), net.prefix_len()),
        }
    }
}

/// Errors that can occur while parsing a scan target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    /// The input was empty or whitespace-only.
    Empty,
    /// The input could not be parsed as an IPv4 address or CIDR range.
    Parse {
        /// The original (trimmed) input.
        input: String,
        /// A short, human-readable explanation.
        reason: String,
    },
    /// The input is IPv6, which is not supported yet.
    Ipv6NotSupported {
        /// The original (trimmed) input.
        input: String,
    },
    /// The target contains more addresses than [`MAX_SUBNET_SIZE`].
    TooManyHosts {
        /// The original (trimmed) input.
        input: String,
        /// How many addresses the target contains.
        hosts: u64,
        /// The maximum allowed number of addresses.
        max: u64,
    },
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetError::Empty => write!(f, "invalid scan target: input is empty"),
            TargetError::Parse { input, reason } => {
                write!(f, "invalid scan target '{input}': {reason}")
            }
            TargetError::Ipv6NotSupported { input } => write!(
                f,
                "invalid scan target '{input}': IPv6 is not supported yet; \
                 use an IPv4 address or CIDR range"
            ),
            TargetError::TooManyHosts { input, hosts, max } => write!(
                f,
                "invalid scan target '{input}': contains {} addresses, \
                 which exceeds the maximum of {}; use a smaller subnet",
                group_digits(*hosts),
                group_digits(*max)
            ),
        }
    }
}

impl std::error::Error for TargetError {}

/// Format a non-negative integer with thousands separators for use in
/// human-facing messages, e.g. `65_536` becomes `"65,536"`.
fn group_digits(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(input: &str) -> ScanTarget {
        ScanTarget::parse(input).unwrap_or_else(|err| panic!("expected '{input}' to parse: {err}"))
    }

    fn parse_err(input: &str) -> TargetError {
        match ScanTarget::parse(input) {
            Ok(_) => panic!("expected '{input}' to be rejected"),
            Err(err) => err,
        }
    }

    // --- valid single hosts -------------------------------------------------

    #[test]
    fn parses_single_ipv4_addresses() {
        let host = parse_ok("192.168.1.1");
        assert_eq!(
            host,
            ScanTarget::Host("192.168.1.1".parse::<Ipv4Addr>().unwrap())
        );
        assert_eq!(host.len(), 1);
        assert_eq!(host.to_string(), "192.168.1.1");
    }

    #[test]
    fn parses_boundary_addresses() {
        assert_eq!(parse_ok("0.0.0.0").to_string(), "0.0.0.0");
        assert_eq!(parse_ok("255.255.255.255").to_string(), "255.255.255.255");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(parse_ok("  192.168.1.1\t").to_string(), "192.168.1.1");
    }

    // --- valid CIDR subnets -------------------------------------------------

    #[test]
    fn parses_cidr_subnets() {
        let subnet = parse_ok("192.168.1.0/24");
        assert_eq!(subnet.len(), 256);
        assert_eq!(subnet.to_string(), "192.168.1.0/24");

        let subnet = parse_ok("10.0.0.0/28");
        assert_eq!(subnet.len(), 16);
        assert_eq!(subnet.to_string(), "10.0.0.0/28");
    }

    #[test]
    fn truncates_host_bits_in_subnet() {
        let subnet = parse_ok("192.168.1.1/24");
        assert_eq!(subnet.to_string(), "192.168.1.0/24");
        assert_eq!(subnet.len(), 256);
    }

    #[test]
    fn parses_slash_32_as_subnet() {
        let subnet = parse_ok("10.0.0.1/32");
        assert_eq!(subnet, ScanTarget::Subnet("10.0.0.1/32".parse().unwrap()));
        assert_eq!(subnet.len(), 1);
    }

    #[test]
    fn parses_slash_16_boundary() {
        let subnet = parse_ok("10.0.0.0/16");
        assert_eq!(subnet.len(), 65_536);
    }

    // --- address enumeration --------------------------------------------------

    #[test]
    fn iter_single_host_yields_one_address() {
        let host = parse_ok("192.168.1.1");
        let addrs: Vec<Ipv4Addr> = host.iter().collect();
        let expected: Vec<Ipv4Addr> = vec!["192.168.1.1".parse().unwrap()];
        assert_eq!(addrs, expected);
    }

    #[test]
    fn iter_subnet_yields_all_addresses_in_ascending_order() {
        let subnet = parse_ok("10.0.0.0/28");
        let addrs: Vec<Ipv4Addr> = subnet.iter().collect();
        assert_eq!(addrs.len(), 16);
        assert_eq!(addrs[0], "10.0.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            addrs.last().unwrap(),
            &"10.0.0.15".parse::<Ipv4Addr>().unwrap()
        );
        for pair in addrs.windows(2) {
            assert!(pair[0] < pair[1], "addresses must be ascending");
        }
    }

    #[test]
    fn iter_includes_network_and_broadcast_addresses() {
        // Unlike Ipv4Net::hosts(), every address in the range is yielded.
        let subnet = parse_ok("192.168.1.0/30");
        let addrs: Vec<Ipv4Addr> = subnet.iter().collect();
        let expected: Vec<Ipv4Addr> = vec![
            "192.168.1.0".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
            "192.168.1.3".parse().unwrap(),
        ];
        assert_eq!(addrs, expected);
    }

    #[test]
    fn iter_count_matches_len() {
        for input in ["192.168.1.1", "192.168.1.0/24", "10.0.0.0/16"] {
            let target = parse_ok(input);
            let count = target.iter().count() as u64;
            assert_eq!(count, target.len(), "count mismatch for {input}");
        }
    }

    #[test]
    fn iter_handles_slash_32_and_max_address() {
        let slash32 = parse_ok("10.0.0.1/32");
        assert_eq!(
            slash32.iter().collect::<Vec<_>>(),
            vec!["10.0.0.1".parse::<Ipv4Addr>().unwrap()]
        );

        // The largest possible address must terminate without wrapping.
        let max = parse_ok("255.255.255.255/32");
        assert_eq!(
            max.iter().collect::<Vec<_>>(),
            vec!["255.255.255.255".parse::<Ipv4Addr>().unwrap()]
        );
    }

    #[test]
    fn iter_size_hint_is_exact() {
        let subnet = parse_ok("192.168.1.0/30");
        let mut it = subnet.iter();
        assert_eq!(it.size_hint(), (4, Some(4)));
        it.next();
        assert_eq!(it.size_hint(), (3, Some(3)));
        it.next();
        it.next();
        it.next();
        assert_eq!(it.size_hint(), (0, Some(0)));
        assert!(it.next().is_none());
    }

    // --- invalid input -------------------------------------------------------

    #[test]
    fn rejects_empty_input() {
        assert_eq!(parse_err(""), TargetError::Empty);
        assert_eq!(parse_err("   "), TargetError::Empty);
    }

    #[test]
    fn rejects_invalid_ipv4_addresses() {
        for input in [
            "192.168.1.999",
            "hello",
            "192.168.1",
            "192.168.1.1.1",
            "256.0.0.1",
        ] {
            let err = parse_err(input);
            assert!(
                matches!(err, TargetError::Parse { .. }),
                "expected Parse error for '{input}', got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_prefixes() {
        for input in [
            "192.168.1.0/99",
            "192.168.1.0/33",
            "192.168.1.0/",
            "192.168.1.0/x",
        ] {
            let err = parse_err(input);
            assert!(
                matches!(err, TargetError::Parse { .. }),
                "expected Parse error for '{input}', got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_ipv6() {
        for input in ["::1", "fe80::1", "fe80::1/64"] {
            let err = parse_err(input);
            assert!(
                matches!(err, TargetError::Ipv6NotSupported { .. }),
                "expected Ipv6NotSupported for '{input}', got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_subnets_larger_than_max() {
        let err = parse_err("10.0.0.0/8");
        assert_eq!(
            err,
            TargetError::TooManyHosts {
                input: "10.0.0.0/8".to_owned(),
                hosts: 16_777_216,
                max: MAX_SUBNET_SIZE,
            }
        );

        let err = parse_err("0.0.0.0/0");
        assert!(matches!(
            err,
            TargetError::TooManyHosts {
                hosts: 4_294_967_296,
                ..
            }
        ));
    }

    // --- error messages ------------------------------------------------------

    #[test]
    fn error_messages_are_helpful() {
        assert_eq!(
            TargetError::Empty.to_string(),
            "invalid scan target: input is empty"
        );

        let err = parse_err("192.168.1.0/99");
        assert!(
            err.to_string().contains("192.168.1.0/99"),
            "message should echo the input: {err}"
        );

        let err = parse_err("10.0.0.0/8");
        let msg = err.to_string();
        assert!(
            msg.contains("16,777,216"),
            "message should show the host count: {msg}"
        );
        assert!(
            msg.contains("65,536"),
            "message should show the limit: {msg}"
        );
    }
}
