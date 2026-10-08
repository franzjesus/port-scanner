//! Network data models.
//!
//! These types represent the structured results of scanning, independent of
//! the TUI. Formatting for display is the responsibility of the presentation
//! layer, not these types.

pub mod host;

pub use host::{Host, HostState};
