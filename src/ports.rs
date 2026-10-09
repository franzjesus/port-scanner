//! Parsing and validation of port specifications.
//!
//! A [`PortSpec`] is the structured form of the set of TCP ports the user asks
//! port-scanner to probe. Parsing is the single gate through which `--ports`
//! input enters the application, so invalid input is rejected here with a clear
//! error instead of failing later.

use std::collections::BTreeSet;
use std::fmt;

use crate::network::Port;

/// The set of TCP ports to probe, stored sorted and unique.
///
/// Built from user input by [`PortSpec::parse`] (and, in a later task, from
/// predefined profiles). The wrapped [`BTreeSet`] keeps the ports in ascending
/// order with duplicates removed, so iterating a spec always yields a
/// deterministic, de-duplicated list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PortSpec(BTreeSet<Port>);

impl PortSpec {
    /// Parse a user-supplied port specification.
    ///
    /// Accepted forms: a single port (`22`), a comma-separated list of ports
    /// (`22,80,443`), an inclusive range (`8000-8100`), and any mix of the
    /// three (`22,80,8000-8100`). Surrounding whitespace around each item is
    /// ignored, duplicate ports are collapsed, and a reversed range
    /// (`8100-8000`) is normalized to ascending order.
    pub fn parse(input: &str) -> Result<Self, PortSpecError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(PortSpecError::Empty);
        }

        let mut ports = BTreeSet::new();
        for item in input.split(',') {
            for port in Self::parse_item(input, item)? {
                ports.insert(port);
            }
        }

        Ok(Self(ports))
    }

    /// Parse one comma-separated item: a single port (`22`) or an inclusive
    /// range (`8000-8100`), returning the ports it denotes.
    fn parse_item(input: &str, item: &str) -> Result<Vec<Port>, PortSpecError> {
        let item = item.trim();
        if item.is_empty() {
            return Err(PortSpecError::Parse {
                input: input.to_owned(),
                reason: "contains an empty port entry (stray comma)".to_owned(),
            });
        }

        // A single port has no dash; a range has exactly one dash with two
        // non-empty ends. Two or more dashes (or an empty end) is malformed.
        let mut parts = item.splitn(3, '-');
        let low = parts.next().expect("splitn always yields a first part");
        let high = parts.next();
        let extra = parts.next();

        match (high, extra) {
            (None, None) => Ok(vec![Self::parse_port_value(input, low)?]),
            (Some(high), None) if !low.trim().is_empty() && !high.trim().is_empty() => {
                let low = Self::parse_port_value(input, low)?;
                let high = Self::parse_port_value(input, high)?;
                Ok(Self::expand_range(low, high))
            }
            _ => Err(PortSpecError::Parse {
                input: input.to_owned(),
                reason: format!(
                    "'{item}' is not a valid port or range (expected e.g. 22 or 8000-8100)"
                ),
            }),
        }
    }

    /// Parse a single numeric token into a [`Port`].
    ///
    /// A value that is either not a `u16` or outside 1–65535 is reported with
    /// the same message: in either case it is "not a valid port".
    fn parse_port_value(input: &str, token: &str) -> Result<Port, PortSpecError> {
        let token = token.trim();
        token
            .parse::<u16>()
            .ok()
            .and_then(|value| Port::new(value).ok())
            .ok_or_else(|| PortSpecError::Parse {
                input: input.to_owned(),
                reason: format!("'{token}' is not a valid port (expected 1-65535)"),
            })
    }

    /// Expand an inclusive `[low, high]` pair into the ports it covers.
    ///
    /// A reversed range is normalized so the result is always ascending:
    /// `8100-8000` yields the same ports as `8000-8100`. Both ends are already
    /// validated to lie in 1–65535, so every value in between is a valid port.
    fn expand_range(mut low: Port, mut high: Port) -> Vec<Port> {
        if low.as_u16() > high.as_u16() {
            std::mem::swap(&mut low, &mut high);
        }
        (low.as_u16()..=high.as_u16())
            .map(|value| Port::new(value).expect("both ends were validated to 1-65535"))
            .collect()
    }

    /// Number of distinct ports in the spec.
    ///
    /// There is deliberately no `is_empty()`: a parsed spec always contains at
    /// least one port, so it would always return `false`.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate over the ports in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = Port> + '_ {
        self.0.iter().copied()
    }

    /// Whether the spec covers every TCP port (1–65535).
    ///
    /// Because every stored port lies in 1–65535, there are at most 65535
    /// distinct values a spec can hold; a spec whose length is 65535 therefore
    /// necessarily contains the entire range.
    pub fn is_full(&self) -> bool {
        self.0.len() == 65535
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let joined = self
            .0
            .iter()
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(",");
        f.write_str(&joined)
    }
}

/// Errors that can occur while parsing a port specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSpecError {
    /// The input was empty or whitespace-only.
    Empty,
    /// The input could not be parsed into a valid set of ports.
    Parse {
        /// The original (trimmed) input.
        input: String,
        /// A short, human-readable explanation.
        reason: String,
    },
}

impl fmt::Display for PortSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortSpecError::Empty => write!(f, "invalid port spec: input is empty"),
            PortSpecError::Parse { input, reason } => {
                write!(f, "invalid port spec '{input}': {reason}")
            }
        }
    }
}

impl std::error::Error for PortSpecError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(input: &str) -> PortSpec {
        PortSpec::parse(input).unwrap_or_else(|err| panic!("expected '{input}' to parse: {err}"))
    }

    fn parse_err(input: &str) -> PortSpecError {
        match PortSpec::parse(input) {
            Ok(_) => panic!("expected '{input}' to be rejected"),
            Err(err) => err,
        }
    }

    fn port(value: u16) -> Port {
        Port::new(value).unwrap()
    }

    fn ports_of(spec: &PortSpec) -> Vec<u16> {
        spec.iter().map(|p| p.as_u16()).collect()
    }

    // --- valid specs --------------------------------------------------------

    #[test]
    fn parses_a_single_port() {
        let spec = parse_ok("22");
        assert_eq!(spec.len(), 1);
        assert_eq!(ports_of(&spec), vec![22]);
        assert_eq!(spec.to_string(), "22");
    }

    #[test]
    fn parses_a_comma_separated_list() {
        let spec = parse_ok("22,80,443");
        assert_eq!(spec.len(), 3);
        assert_eq!(ports_of(&spec), vec![22, 80, 443]);
    }

    #[test]
    fn trims_whitespace_around_items() {
        let spec = parse_ok("  22 , 80  ,443\t");
        assert_eq!(ports_of(&spec), vec![22, 80, 443]);
    }

    #[test]
    fn sorts_ports_ascending() {
        let spec = parse_ok("443,22,80");
        assert_eq!(ports_of(&spec), vec![22, 80, 443]);
    }

    #[test]
    fn removes_duplicate_ports() {
        let spec = parse_ok("22,80,22,80,443");
        assert_eq!(spec.len(), 3);
        assert_eq!(ports_of(&spec), vec![22, 80, 443]);
    }

    #[test]
    fn parses_boundary_ports() {
        assert_eq!(ports_of(&parse_ok("1")), vec![1]);
        assert_eq!(ports_of(&parse_ok("65535")), vec![65535]);
    }

    #[test]
    fn iter_yields_ports_in_order() {
        let spec = parse_ok("80,22");
        let collected: Vec<Port> = spec.iter().collect();
        assert_eq!(collected, vec![port(22), port(80)]);
    }

    #[test]
    fn display_round_trips_a_sorted_list() {
        assert_eq!(parse_ok("443,22,80").to_string(), "22,80,443");
    }

    // --- invalid input ------------------------------------------------------

    #[test]
    fn rejects_empty_input() {
        assert_eq!(parse_err(""), PortSpecError::Empty);
        assert_eq!(parse_err("   "), PortSpecError::Empty);
    }

    #[test]
    fn rejects_empty_items_from_stray_commas() {
        for input in ["22,,443", ",", "22,", ",443"] {
            let err = parse_err(input);
            assert!(
                matches!(err, PortSpecError::Parse { .. }),
                "expected Parse error for '{input}', got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_non_numeric_items() {
        for input in ["abc", "22,abc", "http"] {
            let err = parse_err(input);
            assert!(
                matches!(err, PortSpecError::Parse { .. }),
                "expected Parse error for '{input}', got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_out_of_range_ports() {
        for input in ["0", "65536", "70000", "22,0"] {
            let err = parse_err(input);
            assert!(
                matches!(err, PortSpecError::Parse { .. }),
                "expected Parse error for '{input}', got {err:?}"
            );
        }
    }

    // --- ranges -------------------------------------------------------------

    #[test]
    fn parses_a_range() {
        let spec = parse_ok("8000-8002");
        assert_eq!(ports_of(&spec), vec![8000, 8001, 8002]);
    }

    #[test]
    fn parses_a_range_with_whitespace_around_the_dash() {
        let spec = parse_ok("8000 - 8002");
        assert_eq!(ports_of(&spec), vec![8000, 8001, 8002]);
    }

    #[test]
    fn parses_a_degenerate_range_as_a_single_port() {
        let spec = parse_ok("8000-8000");
        assert_eq!(ports_of(&spec), vec![8000]);
    }

    #[test]
    fn normalizes_a_reversed_range() {
        let spec = parse_ok("8002-8000");
        assert_eq!(ports_of(&spec), vec![8000, 8001, 8002]);
    }

    #[test]
    fn parses_a_mixed_list_and_range() {
        let spec = parse_ok("22,80,8000-8001,443");
        assert_eq!(ports_of(&spec), vec![22, 80, 443, 8000, 8001]);
    }

    #[test]
    fn dedupes_overlap_between_a_port_and_a_range() {
        let spec = parse_ok("22,22-24");
        assert_eq!(ports_of(&spec), vec![22, 23, 24]);
    }

    #[test]
    fn is_full_for_the_entire_range() {
        assert!(!parse_ok("1-65534").is_full());
        assert!(parse_ok("1-65535").is_full());
        assert!(!parse_ok("22,443").is_full());
    }

    #[test]
    fn rejects_malformed_ranges() {
        for input in ["8000-", "-8000", "8000-8001-8002", "8000--8001"] {
            let err = parse_err(input);
            assert!(
                matches!(err, PortSpecError::Parse { .. }),
                "expected Parse error for '{input}', got {err:?}"
            );
        }
    }

    // --- error messages -----------------------------------------------------

    #[test]
    fn error_messages_are_helpful() {
        assert_eq!(
            PortSpecError::Empty.to_string(),
            "invalid port spec: input is empty"
        );

        let err = parse_err("70000");
        assert!(
            err.to_string().contains("70000"),
            "message should echo the offending item: {err}"
        );

        let err = parse_err("22,,443");
        assert!(
            err.to_string().contains("stray comma"),
            "message should explain the stray comma: {err}"
        );

        let err = parse_err("8000-");
        assert!(
            err.to_string().contains("8000-"),
            "message should echo the malformed range: {err}"
        );
    }
}
