//! Terminal user interface layer.
//!
//! The TUI consumes scanner events and renders application state. It must
//! never perform network operations directly (see AGENTS.md).

pub mod app;
