//! Service detection results.

/// Information about the service detected on an open port.
///
/// A service is only recorded when a detector has actually identified it
/// (see the `ServiceDetector` trait in `src/scanner/services.rs`). A port
/// whose service was not detected keeps `None` rather than a guess — the
/// application never fabricates network information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInfo {
    /// The detected service name, lowercase (e.g. `"http"`, `"ssh"`).
    pub name: String,
    /// The service or software version, when the detector can determine it
    /// (e.g. the software token from an SSH banner).
    pub version: Option<String>,
    /// Extra detector-specific detail, when there is any (e.g. the HTTP
    /// status line).
    pub extra: Option<String>,
}

impl ServiceInfo {
    /// A service with only a name; no version or extra detail.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            version: None,
            extra: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_name_and_leaves_the_rest_none() {
        let service = ServiceInfo::new("http");
        assert_eq!(service.name, "http");
        assert_eq!(service.version, None);
        assert_eq!(service.extra, None);
    }

    #[test]
    fn fields_can_carry_version_and_extra() {
        let mut service = ServiceInfo::new("ssh");
        service.version = Some("OpenSSH_9.6p1".to_string());
        service.extra = Some("protocol 2.0".to_string());
        assert_eq!(service.version.as_deref(), Some("OpenSSH_9.6p1"));
        assert_eq!(service.extra.as_deref(), Some("protocol 2.0"));
    }

    #[test]
    fn services_with_same_fields_are_equal() {
        let a = ServiceInfo::new("http");
        let b = ServiceInfo::new("http");
        let c = ServiceInfo::new("https");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
