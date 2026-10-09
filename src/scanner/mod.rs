//! Scanning engine.
//!
//! This module owns the scanner's event model and the discovery mechanisms
//! that produce it. It depends only on the structured network data models
//! (see the `network` module), never on the TUI, so the scanner can be used
//! and tested independently of terminal rendering.
//!
//! The scanner runs on a background thread and reports progress by sending
//! [`ScanEvent`]s to the TUI through a channel. Cancellation is signalled
//! out-of-band (see Phase 3 in `PLAN.md`).

use std::fmt;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{SendError, Sender};
use std::sync::Arc;
use std::time::Duration;

use crate::network::Host;
use crate::target::ScanTarget;

/// ICMP echo (ping) primitives used by host discovery.
///
/// Kept private to the scanner module: it exposes only the low-level socket
/// mechanics, while the discovery layer decides how those probes are scheduled.
mod icmp;

/// A structured message produced by the scanner as a scan progresses.
///
/// Events flow from the scanner (on a background thread) to the TUI through a
/// channel so results appear incrementally without blocking the UI thread. They
/// carry no TUI-specific types, which keeps the scanner decoupled from the
/// presentation layer.
#[derive(Debug)]
pub enum ScanEvent {
    /// A scan has started. `total` is the number of addresses that will be
    /// probed, used to drive the progress display.
    Started { total: u64 },
    /// A host has been resolved to a terminal state (up or down).
    HostDiscovered(Host),
    /// Progress update: `completed` hosts resolved out of `total`.
    Progress { completed: u64, total: u64 },
    /// The scan completed normally.
    Finished,
    /// The scan was cancelled by the user.
    Cancelled,
    /// A fatal error stopped the scan.
    Error(ScanError),
}

/// A fatal error that stops a scan.
///
/// Ordinary network conditions (a host not responding, a port refusing a
/// connection, a timeout) are not errors and never surface here; they are
/// represented by host/port state instead. Only conditions that prevent the
/// scan from continuing are reported as a [`ScanError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// A socket-level failure (creating the socket or sending a probe).
    Socket(String),
    /// A failure sending an event to the TUI, usually because the receiver was
    /// dropped (for example the TUI closed).
    Channel(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Socket(msg) => write!(f, "socket error: {msg}"),
            ScanError::Channel(msg) => write!(f, "channel error: {msg}"),
        }
    }
}

impl std::error::Error for ScanError {}

/// Allow `sender.send(event)?` in code that returns `Result<_, ScanError>`.
impl From<SendError<ScanEvent>> for ScanError {
    fn from(err: SendError<ScanEvent>) -> Self {
        ScanError::Channel(err.to_string())
    }
}

/// Tunables for a host-discovery run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryConfig {
    /// How long to wait for an ICMP reply before marking a host down.
    pub timeout: Duration,
    /// Maximum number of hosts probed concurrently.
    pub concurrency: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(300),
            concurrency: 128,
        }
    }
}

/// A mechanism for discovering which hosts in a target are up.
///
/// Implementations probe the target's addresses concurrently and report
/// results as [`ScanEvent`]s through the provided channel. Discovery is
/// blocking: the call returns once the target has been fully probed, the
/// scan was cancelled, or a fatal error occurred.
pub trait HostDiscovery {
    /// Probe `target`, reporting discovered hosts and progress through
    /// `events`.
    ///
    /// `cancel` is checked periodically; when set, discovery stops promptly
    /// without marking in-flight hosts down.
    fn discover(
        &self,
        target: &ScanTarget,
        config: &DiscoveryConfig,
        events: &Sender<ScanEvent>,
        cancel: &Arc<AtomicBool>,
    ) -> Result<(), ScanError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn events_carry_their_payload() {
        let started = ScanEvent::Started { total: 256 };
        let total = match started {
            ScanEvent::Started { total } => total,
            other => panic!("expected Started, got {other:?}"),
        };
        assert_eq!(total, 256);

        let host = Host::up(Ipv4Addr::new(10, 0, 0, 1), Duration::from_millis(5));
        let discovered = ScanEvent::HostDiscovered(host);
        let found = match discovered {
            ScanEvent::HostDiscovered(found) => found,
            other => panic!("expected HostDiscovered, got {other:?}"),
        };
        assert_eq!(found.ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(found.latency, Some(Duration::from_millis(5)));

        let progress = ScanEvent::Progress {
            completed: 3,
            total: 256,
        };
        let (completed, total) = match progress {
            ScanEvent::Progress { completed, total } => (completed, total),
            other => panic!("expected Progress, got {other:?}"),
        };
        assert_eq!(completed, 3);
        assert_eq!(total, 256);

        assert!(matches!(ScanEvent::Finished, ScanEvent::Finished));
        assert!(matches!(ScanEvent::Cancelled, ScanEvent::Cancelled));

        let error = ScanEvent::Error(ScanError::Socket("boom".to_string()));
        let cause = match error {
            ScanEvent::Error(cause) => cause,
            other => panic!("expected Error, got {other:?}"),
        };
        assert_eq!(cause, ScanError::Socket("boom".to_string()));
    }

    #[test]
    fn error_display_is_descriptive() {
        let socket = ScanError::Socket("cannot open socket".to_string());
        assert_eq!(socket.to_string(), "socket error: cannot open socket");

        let channel = ScanError::Channel("channel closed".to_string());
        assert_eq!(channel.to_string(), "channel error: channel closed");
    }

    #[test]
    fn send_error_converts_to_channel_error() {
        use std::sync::mpsc;
        let (tx, rx) = mpsc::channel::<ScanEvent>();
        drop(rx);
        let err = tx.send(ScanEvent::Finished).unwrap_err();
        let scan_error = ScanError::from(err);
        assert!(matches!(scan_error, ScanError::Channel(_)));
    }

    #[test]
    fn default_discovery_config() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.timeout, Duration::from_millis(300));
        assert_eq!(config.concurrency, 128);
    }
}
