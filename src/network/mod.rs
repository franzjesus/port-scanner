//! Network data models.
//!
//! These types represent the structured results of scanning, independent of
//! the TUI. Formatting for display is the responsibility of the presentation
//! layer, not these types.

pub mod host;
pub mod mac;
pub mod port;
pub mod service;

pub use host::{Host, HostState};
pub use mac::{MacAddress, MacAddressError};
pub use port::{Port, PortState, ProbedPort};
pub use service::ServiceInfo;
