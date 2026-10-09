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
    /// Accepted forms: a single port (`22`) or a comma-separated list of single
    /// ports (`22,80,443`). Surrounding whitespace around each item is ignored
    /// and duplicate ports are collapsed. Ranges (`8000-8100`) are not accepted
    /// yet (see `PLAN.md`, Phase 4).
    pub fn parse(input: &str) -> Result<Self, PortSpecError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(PortSpecError::Empty);
        }

        let mut ports = BTreeSet::new();
        for item in input.split(',') {
            ports.insert(Self::parse_single(input, item)?);
        }

        Ok(Self(ports))
    }

    /// Parse a single port item (a run of digits) into a [`Port`].
    fn parse_single(input: &str, item: &str) -> Result<Port, PortSpecError> {
        let item = item.trim();
        if item.is_empty() {
            return Err(PortSpecError::Parse {
                input: input.to_owned(),
                reason: "contains an empty port entry (stray comma)".to_owned(),
            });
        }

        // A value that is either not a `u16` or outside 1–65535 is reported
        // with the same message: in either case it is "not a valid port".
        let port = item
            .parse::<u16>()
            .ok()
            .and_then(|value| Port::new(value).ok())
            .ok_or_else(|| PortSpecError::Parse {
                input: input.to_owned(),
                reason: format!("'{item}' is not a valid port (expected 1-65535)"),
            })?;

        Ok(port)
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

    #[test]
    fn rejects_ranges_not_supported_yet() {
        // Range syntax is introduced in Phase 4, task 4.3.
        let err = parse_err("8000-8100");
        assert!(matches!(err, PortSpecError::Parse { .. }));
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
    }
}
