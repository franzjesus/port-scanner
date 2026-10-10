//! MAC (hardware) address data model.

use std::fmt;
use std::str::FromStr;

/// A hardware (MAC) address: six bytes of link-layer identity.
///
/// Displayed in the conventional colon-separated, uppercase hexadecimal form
/// (`AA:BB:CC:DD:EE:FF`). The first three octets form the OUI (organizationally
/// unique identifier) that maps to a vendor; see `PLAN.md` Phase 13.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// The all-zero address, used by the kernel's ARP table to mark an entry
    /// that has not yet been resolved (and which therefore carries no hardware
    /// address to report).
    pub const ZERO: MacAddress = MacAddress([0; 6]);

    /// Create a [`MacAddress`] from its six octets.
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// The six octets of the address.
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// The first three octets — the OUI (organizationally unique identifier).
    pub const fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    /// Whether every octet is zero, i.e. an unresolved ARP entry.
    pub const fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// A failure to parse a [`MacAddress`] from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacAddressError {
    /// The string was not a colon- or dash-separated six-octet address.
    Invalid(String),
}

impl fmt::Display for MacAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacAddressError::Invalid(input) => {
                write!(f, "invalid MAC address {input:?}")
            }
        }
    }
}

impl std::error::Error for MacAddressError {}

impl FromStr for MacAddress {
    type Err = MacAddressError;

    /// Parse an address from `AA:BB:CC:DD:EE:FF` (case-insensitive) or the
    /// dash-separated `AA-BB-CC-DD-EE-FF` form.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.replace('-', ":");
        let octets = normalized
            .split(':')
            .map(|field| u8::from_str_radix(field, 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| MacAddressError::Invalid(s.to_string()))?;
        let mut bytes = [0u8; 6];
        if octets.len() != 6 {
            return Err(MacAddressError::Invalid(s.to_string()));
        }
        bytes.copy_from_slice(&octets);
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_and_octets_round_trip() {
        let mac = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(mac.octets(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn display_is_uppercase_colon_separated() {
        let mac = MacAddress::new([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        assert_eq!(mac.to_string(), "00:1A:2B:3C:4D:5E");
    }

    #[test]
    fn oui_is_the_first_three_octets() {
        let mac = MacAddress::new([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        assert_eq!(mac.oui(), [0x00, 0x1a, 0x2b]);
    }

    #[test]
    fn from_str_parses_colon_form() {
        let mac = "00:1a:2b:3c:4d:5e".parse::<MacAddress>().unwrap();
        assert_eq!(mac, MacAddress::new([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]));
    }

    #[test]
    fn from_str_accepts_dash_form_and_is_case_insensitive() {
        let mac = "AA-BB-CC-DD-EE-FF".parse::<MacAddress>().unwrap();
        assert_eq!(
            mac,
            MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    fn from_str_rejects_malformed_input() {
        assert!("not-a-mac".parse::<MacAddress>().is_err());
        assert!("00:1a:2b:3c:4d".parse::<MacAddress>().is_err());
        assert!("00:1a:2b:3c:4d:5e:6f".parse::<MacAddress>().is_err());
        assert!("00:1g:2b:3c:4d:5e".parse::<MacAddress>().is_err());
    }

    #[test]
    fn zero_address_reports_is_zero() {
        assert!(MacAddress::ZERO.is_zero());
        assert!(!MacAddress::new([0, 0, 0, 0, 0, 1]).is_zero());
    }

    #[test]
    fn display_and_fromstr_round_trip() {
        let mac = MacAddress::new([0xde, 0xad, 0xbe, 0xef, 0x01, 0x23]);
        assert_eq!(mac.to_string().parse::<MacAddress>().unwrap(), mac);
    }
}
