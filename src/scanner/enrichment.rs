//! Per-host enrichment: hostname (reverse DNS), MAC address (ARP table),
//! and vendor (OUI database lookup derived from the MAC).
//!
//! Enrichers run for discovered hosts after their port scan, mirroring the
//! service-detection stage. Each enricher is independent and its failure is
//! never fatal: enrichment is a best-effort presentation detail, so a
//! failing or slow enricher is dropped rather than propagated.

use crate::network::MacAddress;
use std::fmt;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_ARP_PATH: &str = "/proc/net/arp";
const DEFAULT_REVERSE_DNS_TIMEOUT: Duration = Duration::from_millis(500);

/// Errors returned by a [`HostEnricher`] when it cannot produce a result.
///
/// A failed enricher is dropped by the scan; these errors never abort a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrichmentError {
    /// The enricher did not finish within its timeout.
    Timeout,
    /// The lookup failed (unreadable source, malformed data, resolver error).
    Lookup(String),
}

impl fmt::Display for EnrichmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "enrichment timed out"),
            Self::Lookup(msg) => write!(f, "enrichment lookup failed: {msg}"),
        }
    }
}

impl std::error::Error for EnrichmentError {}

/// The enrichment data an enricher can contribute for a host.
///
/// Enrichers may fill in any subset of the fields; the scan merges the
/// contributions of all enrichers for a host.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostEnrichment {
    /// Reverse-DNS hostname, when one resolves.
    pub hostname: Option<String>,
    /// MAC address read from the ARP table.
    pub mac: Option<MacAddress>,
}

impl HostEnrichment {
    /// Returns `true` when the enrichment carries no data at all.
    pub fn is_empty(&self) -> bool {
        self.hostname.is_none() && self.mac.is_none()
    }
}

/// A trait implemented by per-host enrichment sources.
///
/// Implementations must be `Send + Sync` because they are shared across
/// scanner workers.
pub trait HostEnricher: Send + Sync {
    /// Produce the enrichment for `ip`.
    ///
    /// Return `Ok(None)` when the enricher has no data for this host (for
    /// example, no reverse-DNS record or no ARP entry). Return `Err` when the
    /// lookup itself failed; the caller treats both as "no enrichment" for
    /// this enricher.
    fn enrich(&self, ip: Ipv4Addr) -> Result<Option<HostEnrichment>, EnrichmentError>;
}

/// Resolves the reverse-DNS hostname for a host via `getnameinfo`.
///
/// The lookup blocks inside a short-lived worker thread and is bounded by a
/// channel timeout, so a stalled resolver can never stall the scan.
pub struct ReverseDnsEnricher {
    timeout: Duration,
}

impl ReverseDnsEnricher {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for ReverseDnsEnricher {
    fn default() -> Self {
        Self::new(DEFAULT_REVERSE_DNS_TIMEOUT)
    }
}

impl HostEnricher for ReverseDnsEnricher {
    fn enrich(&self, ip: Ipv4Addr) -> Result<Option<HostEnrichment>, EnrichmentError> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = reverse_resolve(ip);
            let _ = tx.send(result);
        });
        match rx.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(EnrichmentError::Timeout),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(EnrichmentError::Lookup("resolver thread terminated".into()))
            }
        }
    }
}

fn reverse_resolve(ip: Ipv4Addr) -> Result<Option<HostEnrichment>, EnrichmentError> {
    let mut host = [0u8; libc::NI_MAXHOST as usize];
    let addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addr = addr;
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = 0;
    addr.sin_addr = libc::in_addr {
        s_addr: u32::from(ip).to_be(),
    };

    // `NI_NAMEREQD` makes "no name" surface as EAI_NONAME rather than an
    // empty string, so the two cases cannot be confused.
    let rc = unsafe {
        libc::getnameinfo(
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            host.as_mut_ptr() as *mut libc::c_char,
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };

    if rc == 0 {
        // `getnameinfo` NUL-terminates the buffer, so reading through the
        // first NUL is well defined.
        let name = unsafe { std::ffi::CStr::from_ptr(host.as_ptr() as *const libc::c_char) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        return Ok(name.map(|hostname| HostEnrichment {
            hostname: Some(hostname),
            mac: None,
        }));
    }
    if rc == libc::EAI_NONAME {
        return Ok(None);
    }
    Err(EnrichmentError::Lookup(format!(
        "getnameinfo failed with error code {rc}"
    )))
}

/// Reads the kernel ARP table (`/proc/net/arp`) and reports the hardware
/// address for a host.
///
/// The path is injectable so tests can point at a fixture file.
pub struct ArpEnricher {
    path: PathBuf,
}

impl ArpEnricher {
    pub fn new() -> Self {
        Self::with_path(Path::new(DEFAULT_ARP_PATH))
    }

    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl Default for ArpEnricher {
    fn default() -> Self {
        Self::new()
    }
}

impl HostEnricher for ArpEnricher {
    fn enrich(&self, ip: Ipv4Addr) -> Result<Option<HostEnrichment>, EnrichmentError> {
        let content = std::fs::read_to_string(&self.path).map_err(|err| {
            EnrichmentError::Lookup(format!("cannot read {}: {err}", self.path.display()))
        })?;

        for line in content.lines().skip(1) {
            // `/proc/net/arp` columns: IP, HW type, Flags, HW address (MAC),
            // Mask, Device. The MAC is the fourth column (index 3).
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }
            let Some(entry_ip) = fields[0].parse::<Ipv4Addr>().ok() else {
                continue;
            };
            if entry_ip != ip {
                continue;
            }
            let Ok(mac) = fields[3].parse::<MacAddress>() else {
                continue;
            };
            // `00:00:00:00:00:00` is the kernel's placeholder for an
            // incomplete entry; it is not a discovered address.
            if mac.is_zero() {
                continue;
            }
            return Ok(Some(HostEnrichment {
                hostname: None,
                mac: Some(mac),
            }));
        }
        Ok(None)
    }
}

/// Looks up the vendor for a MAC address in the OUI database.
///
/// Returns `None` for the zero address, for addresses without a registered
/// OUI, and for the database's literal `"unknown"` result. The vendor is
/// inferred from the MAC, not discovered on the wire, so callers should
/// present it as inferred.
pub fn vendor_for(mac: &MacAddress) -> Option<String> {
    if mac.is_zero() {
        return None;
    }
    match rsmanuf::lookup(mac.to_string()) {
        Ok(name) if !name.is_empty() && name != "unknown" => Some(name),
        _ => None,
    }
}

/// The default set of enrichers: reverse DNS plus the local ARP table.
pub fn default_enrichers() -> Vec<Box<dyn HostEnricher>> {
    vec![
        Box::new(ReverseDnsEnricher::default()),
        Box::new(ArpEnricher::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arp_fixture(dir: &Path, name: &str, lines: &[&str]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        path
    }

    fn temp_dir() -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("port-scanner-enrichment-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn arp_enricher_reads_matching_entry() {
        let dir = temp_dir();
        let path = arp_fixture(
            &dir,
            "arp-match",
            &[
                "IP address       HW type     Flags       HW address            Mask     Device",
                "192.168.1.10     0x1         0x2         3c:52:82:aa:bb:cc     *        eth0",
                "192.168.1.11     0x1         0x2         00:1b:63:dd:ee:ff     *        eth0",
            ],
        );
        let enricher = ArpEnricher::with_path(&path);

        let enrichment = enricher.enrich("192.168.1.10".parse().unwrap()).unwrap();
        assert_eq!(
            enrichment,
            Some(HostEnrichment {
                hostname: None,
                mac: Some("3c:52:82:aa:bb:cc".parse().unwrap()),
            })
        );

        let enrichment = enricher.enrich("192.168.1.11".parse().unwrap()).unwrap();
        assert_eq!(
            enrichment,
            Some(HostEnrichment {
                hostname: None,
                mac: Some("00:1b:63:dd:ee:ff".parse().unwrap()),
            })
        );

        // No entry for this host.
        assert_eq!(enricher.enrich("10.0.0.1".parse().unwrap()).unwrap(), None);
    }

    #[test]
    fn arp_enricher_skips_incomplete_entries() {
        let dir = temp_dir();
        let path = arp_fixture(
            &dir,
            "arp-incomplete",
            &[
                "IP address       HW type     Flags       HW address            Mask     Device",
                "192.168.1.10     0x1         0x0         00:00:00:00:00:00     *        eth0",
            ],
        );
        let enricher = ArpEnricher::with_path(&path);

        assert_eq!(
            enricher.enrich("192.168.1.10".parse().unwrap()).unwrap(),
            None
        );
    }

    #[test]
    fn arp_enricher_errors_when_file_missing() {
        let dir = temp_dir();
        let path = dir.join("arp-missing");
        let enricher = ArpEnricher::with_path(&path);

        let err = enricher
            .enrich("192.168.1.10".parse().unwrap())
            .unwrap_err();
        assert!(matches!(err, EnrichmentError::Lookup(msg) if msg.contains("cannot read")));
    }

    #[test]
    fn host_enrichment_is_empty() {
        assert!(HostEnrichment::default().is_empty());
        assert!(HostEnrichment {
            hostname: None,
            mac: None,
        }
        .is_empty());
        assert!(!HostEnrichment {
            hostname: Some("host".into()),
            mac: None,
        }
        .is_empty());
        assert!(!HostEnrichment {
            hostname: None,
            mac: Some("3c:52:82:aa:bb:cc".parse().unwrap()),
        }
        .is_empty());
    }

    #[test]
    fn vendor_for_registered_oui() {
        // 3C:52:82 is a well-known Hewlett-Packard OUI.
        let mac: MacAddress = "3c:52:82:aa:bb:cc".parse().unwrap();
        let vendor = vendor_for(&mac).expect("Hewlett-Packard OUI should be in the database");
        assert!(!vendor.is_empty());
        assert_ne!(vendor, "unknown");
    }

    #[test]
    fn vendor_for_zero_mac_is_none() {
        assert_eq!(vendor_for(&MacAddress::ZERO), None);
    }

    #[test]
    fn reverse_dns_bounded_by_timeout() {
        // 192.0.2.1 is TEST-NET-1 (RFC 5737): guaranteed non-routable, so the
        // lookup must fail or time out quickly rather than stall the scan.
        // The important property is that the call is bounded by the timeout
        // plumbing, not the specific result in a given environment.
        let enricher = ReverseDnsEnricher::new(Duration::from_millis(250));
        let started = std::time::Instant::now();
        let _ = enricher.enrich("192.0.2.1".parse().unwrap());
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "reverse DNS lookup must not stall past its timeout plumbing"
        );
    }
}
