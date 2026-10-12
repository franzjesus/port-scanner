//! Port selection for the TCP scanning stage.
//!
//! A [`PortSpec`] is the structured form of the set of TCP ports the user asks
//! port-scanner to probe. Parsing is the single gate through which `--ports`
//! input enters the application, so invalid input is rejected here with a clear
//! error instead of failing later.
//!
//! The module also defines the higher-level configuration the scanner consumes:
//! named [`PortProfile`]s (Quick, Common, Full) and the [`PortConfig`] that
//! bundles the port set with a connection timeout and a concurrency bound.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

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

    /// Build a spec from a list of raw port numbers.
    ///
    /// This is the construction path used by the predefined profiles (see
    /// [`PortProfile`]), which are authored as plain `u16` lists. Values
    /// outside 1–65535 are dropped and duplicates are collapsed, so an
    /// unsorted, possibly-oversized list always yields a valid, sorted,
    /// unique spec.
    pub fn from_port_numbers(numbers: impl IntoIterator<Item = u16>) -> Self {
        let ports = numbers
            .into_iter()
            .filter_map(|value| Port::new(value).ok())
            .collect();
        Self(ports)
    }

    /// A spec covering every TCP port, 1–65535.
    ///
    /// Used by [`PortProfile::Full`]. Every value in 1–65535 is a valid
    /// [`Port`], so the construction cannot fail.
    pub fn full() -> Self {
        let ports = (Port::MIN..=Port::MAX)
            .map(|value| Port::new(value).expect("1..=65535 are all valid ports"))
            .collect();
        Self(ports)
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

/// Default per-port connection timeout.
///
/// Chosen to match [`DiscoveryConfig`](crate::scanner::DiscoveryConfig) so the
/// two scanning stages feel consistent out of the box.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(300);

/// Default number of ports probed concurrently per host.
///
/// Bounded so a large profile does not spawn an uncontrolled number of
/// connections; see the concurrency rule in `PLAN.md`.
pub const DEFAULT_CONCURRENCY: usize = 128;

/// A predefined, named set of ports.
///
/// Profiles give the user quick access to sensible port selections without
/// typing them out. `Quick` is a small, fast probe; `Common` is a curated set
/// of well-known service ports; `Full` covers every TCP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PortProfile {
    /// A small, fast set of the most commonly exposed services.
    #[default]
    Quick,
    /// A curated set of well-known service ports.
    Common,
    /// Every TCP port (1–65535).
    Full,
}

impl PortProfile {
    /// The [`PortSpec`] this profile probes.
    pub fn ports(&self) -> PortSpec {
        match self {
            PortProfile::Quick => PortSpec::from_port_numbers(QUICK_PORTS),
            PortProfile::Common => PortSpec::from_port_numbers(common_ports()),
            PortProfile::Full => PortSpec::full(),
        }
    }
}

/// Errors that can occur while parsing a [`PortProfile`] name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortProfileError {
    /// The input did not name a known profile.
    UnknownProfile {
        /// The original (trimmed) input, for a helpful error message.
        input: String,
    },
}

impl fmt::Display for PortProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortProfileError::UnknownProfile { input } => write!(
                f,
                "unknown port profile '{input}' (expected quick, common, or full)"
            ),
        }
    }
}

impl std::error::Error for PortProfileError {}

impl FromStr for PortProfile {
    type Err = PortProfileError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        match trimmed.to_ascii_lowercase().as_str() {
            "quick" => Ok(Self::Quick),
            "common" => Ok(Self::Common),
            "full" => Ok(Self::Full),
            _ => Err(PortProfileError::UnknownProfile {
                input: trimmed.to_owned(),
            }),
        }
    }
}

/// Ports probed by [`PortProfile::Quick`]: a small, fast set of the most
/// commonly exposed services.
const QUICK_PORTS: [u16; 18] = [
    22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080,
];

/// The full list of ports probed by [`PortProfile::Common`].
///
/// Authored as small thematic groups (see the `COMMON_*` constants below) and
/// concatenated here, rather than a single near-sequential dump. Duplicates
/// between groups are harmless: `PortSpec` de-duplicates.
fn common_ports() -> Vec<u16> {
    let mut ports = Vec::new();
    ports.extend_from_slice(&COMMON_CORE);
    ports.extend_from_slice(&COMMON_DB);
    ports.extend_from_slice(&COMMON_WEB);
    ports.extend_from_slice(&COMMON_DESKTOP);
    ports.extend_from_slice(&COMMON_MESSAGING);
    ports.extend_from_slice(&COMMON_MISC);
    ports
}

/// Common group 1: remote access, mail, and directory services (low ports).
const COMMON_CORE: [u16; 36] = [
    21, 22, 23, 25, 53, 80, 110, 111, 113, 135, 137, 138, 139, 143, 161, 162, 179, 389, 443, 445,
    465, 500, 514, 515, 548, 554, 563, 587, 623, 631, 636, 990, 992, 993, 994, 995,
];

/// Common group 2: databases and data stores.
const COMMON_DB: [u16; 11] = [
    1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 9300, 11211, 27017,
];

/// Common group 3: web, HTTP, and common application high ports.
const COMMON_WEB: [u16; 15] = [
    3000, 3128, 5000, 5001, 6443, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 15672, 2375, 2376,
];

/// Common group 4: remote desktop, VNC, X11, and file transfer.
///
/// VNC and X11 are represented by small sets rather than full sequential
/// blocks, per the plan.
const COMMON_DESKTOP: [u16; 7] = [20, 221, 5900, 5901, 5902, 6000, 6001];

/// Common group 5: messaging, VoIP, and network discovery.
const COMMON_MESSAGING: [u16; 10] = [69, 123, 1194, 5060, 5061, 5353, 5355, 1900, 5222, 5223];

/// Common group 6: additional well-known services (proxies, monitoring,
/// hosting control panels, LDAP, printing, and a few high-port standouts).
const COMMON_MISC: [u16; 22] = [
    1080, 1337, 1414, 1720, 1723, 1755, 2049, 2082, 2083, 2095, 2096, 2222, 2625, 3268, 3269, 6660,
    6661, 7443, 9100, 17500, 50000, 6881,
];

/// The complete configuration for the TCP port-scanning stage.
///
/// Bundles which ports to probe ([`PortConfig::ports`]), how long to wait for
/// each connection ([`PortConfig::timeout`]), and how many to probe in
/// parallel per host ([`PortConfig::concurrency`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortConfig {
    /// The set of ports to probe on each live host.
    pub ports: PortSpec,
    /// How long to wait for a single port connection before calling it closed.
    pub timeout: Duration,
    /// Maximum number of ports probed concurrently per host.
    pub concurrency: usize,
}

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            ports: PortProfile::Quick.ports(),
            timeout: DEFAULT_TIMEOUT,
            concurrency: DEFAULT_CONCURRENCY,
        }
    }
}

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

    // --- profiles -----------------------------------------------------------

    #[test]
    fn quick_profile_is_the_documented_set() {
        let ports = ports_of(&PortProfile::Quick.ports());
        assert_eq!(
            ports,
            vec![
                22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5900,
                8080,
            ]
        );
    }

    #[test]
    fn common_profile_is_a_sized_sorted_set() {
        let ports = ports_of(&PortProfile::Common.ports());
        // The curated list should sit comfortably in the planned range.
        assert!(
            (100..=130).contains(&ports.len()),
            "Common should have 100-130 ports, got {}",
            ports.len()
        );
        // Sorted ascending and unique (de-duplicated).
        let mut sorted = ports.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(ports, sorted);
    }

    #[test]
    fn common_profile_contains_well_known_ports() {
        let ports = ports_of(&PortProfile::Common.ports());
        for expected in [22, 80, 443, 3306, 5432, 8080, 27017] {
            assert!(ports.contains(&expected), "Common missing port {expected}");
        }
    }

    #[test]
    fn full_profile_covers_every_port() {
        let spec = PortProfile::Full.ports();
        assert_eq!(spec.len(), 65535);
    }

    #[test]
    fn profile_sizes_are_ordered() {
        let quick = PortProfile::Quick.ports().len();
        let common = PortProfile::Common.ports().len();
        let full = PortProfile::Full.ports().len();
        assert!(
            quick < common,
            "Quick ({quick}) should be < Common ({common})"
        );
        assert!(common < full, "Common ({common}) should be < Full ({full})");
    }

    // --- profile name parsing ------------------------------------------------

    #[test]
    fn profile_names_parse_case_insensitively() {
        assert_eq!("quick".parse::<PortProfile>().unwrap(), PortProfile::Quick);
        assert_eq!("Quick".parse::<PortProfile>().unwrap(), PortProfile::Quick);
        assert_eq!("QUICK".parse::<PortProfile>().unwrap(), PortProfile::Quick);
        assert_eq!(
            "common".parse::<PortProfile>().unwrap(),
            PortProfile::Common
        );
        assert_eq!("FULL".parse::<PortProfile>().unwrap(), PortProfile::Full);
    }

    #[test]
    fn profile_names_trimm_surrounding_whitespace() {
        assert_eq!(
            "  common  ".parse::<PortProfile>().unwrap(),
            PortProfile::Common
        );
    }

    #[test]
    fn unknown_profile_name_is_rejected() {
        let err = "turbo".parse::<PortProfile>().unwrap_err();
        assert!(matches!(
            err,
            PortProfileError::UnknownProfile { ref input } if input == "turbo"
        ));
        assert_eq!(
            err.to_string(),
            "unknown port profile 'turbo' (expected quick, common, or full)"
        );
    }

    #[test]
    fn empty_profile_name_is_rejected() {
        assert!(matches!(
            " ".parse::<PortProfile>(),
            Err(PortProfileError::UnknownProfile { .. })
        ));
    }

    // --- configuration ------------------------------------------------------

    #[test]
    fn default_config_uses_quick_and_defaults() {
        let config = PortConfig::default();
        assert_eq!(config.ports, PortProfile::Quick.ports());
        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
        assert_eq!(config.concurrency, DEFAULT_CONCURRENCY);
    }
}
