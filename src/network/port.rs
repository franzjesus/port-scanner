//! Port data model.

use std::fmt;

/// A TCP port number, validated to the 1–65535 range.
///
/// A newtype over `u16` so a port value cannot be confused with a plain
/// integer at the type level. Port `0` is invalid — it is an "unspecified"
/// value, not a real destination port — and is rejected by [`Port::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Port(u16);

impl Port {
    /// The smallest valid port number.
    pub const MIN: u16 = 1;
    /// The largest valid port number.
    pub const MAX: u16 = 65535;

    /// Create a [`Port`] from a `u16`, rejecting values outside 1–65535.
    pub fn new(value: u16) -> Result<Self, PortError> {
        if !(Self::MIN..=Self::MAX).contains(&value) {
            Err(PortError::InvalidPort(value))
        } else {
            Ok(Self(value))
        }
    }

    /// The underlying port number.
    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A failure to construct a valid [`Port`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortError {
    /// A port value outside the valid 1–65535 range.
    InvalidPort(u16),
}

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortError::InvalidPort(value) => {
                write!(f, "invalid port {value}: must be in the range 1–65535")
            }
        }
    }
}

impl std::error::Error for PortError {}

/// The state of a port as determined by a TCP connect scan.
///
/// Only the states a connect scan can actually establish are represented:
/// [`Open`] when a connection was accepted, [`Closed`] when it was refused or
/// timed out. (A `filtered` state, which would require raw-packet analysis, is
/// deliberately not represented yet — see `PLAN.md`.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortState {
    /// A TCP connection to the port succeeded.
    Open,
    /// A TCP connection could not be made (refused or timed out).
    Closed,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accepts_valid_ports() {
        assert_eq!(Port::new(1), Ok(Port(1)));
        assert_eq!(Port::new(80), Ok(Port(80)));
        assert_eq!(Port::new(65535), Ok(Port(65535)));
    }

    #[test]
    fn new_rejects_port_zero() {
        assert_eq!(Port::new(0), Err(PortError::InvalidPort(0)));
    }

    #[test]
    fn as_u16_round_trips() {
        let port = Port::new(443).unwrap();
        assert_eq!(port.as_u16(), 443);
    }

    #[test]
    fn display_is_the_number() {
        assert_eq!(Port::new(80).unwrap().to_string(), "80");
        assert_eq!(Port::new(65535).unwrap().to_string(), "65535");
    }

    #[test]
    fn ports_order_numerically() {
        let (a, b, c) = (
            Port::new(22).unwrap(),
            Port::new(80).unwrap(),
            Port::new(443).unwrap(),
        );
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
        assert_eq!(b, Port::new(80).unwrap());
    }

    #[test]
    fn state_displays_lowercase() {
        assert_eq!(PortState::Open.to_string(), "open");
        assert_eq!(PortState::Closed.to_string(), "closed");
    }

    #[test]
    fn invalid_port_error_is_descriptive() {
        let err = PortError::InvalidPort(0);
        assert_eq!(
            err.to_string(),
            "invalid port 0: must be in the range 1–65535"
        );
    }
}
