//! Application state and the main TUI event loop.
//!
//! The TUI renders application state and handles keyboard input. It consumes
//! scanner events from a channel but never performs network operations itself
//! (see AGENTS.md).
//!
//! Filtering (`/`) is applied in the presentation layer only: it changes which
//! hosts are visible and how navigation works, without modifying the stored
//! results or triggering new scans (see AGENTS.md: "filtering operates on the
//! UI model").

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Styled},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table},
    Frame, Terminal,
};

use crate::diff::ScanDiff;
use crate::network::{Host, HostState, PortState, ProbedPort, ServiceInfo};
use crate::ports::PortProfile;
use crate::scanner::{Discovery, ScanConfig, ScanEvent, ScanSpawner};
use crate::storage::RecordSummary;
use crate::subnet::group_by_subnet;
use crate::target::ScanTarget;

/// The phase of the scan, as tracked by the TUI.
///
/// Transitions happen exclusively in [`App::apply_event`] and
/// [`App::handle_key`].
#[derive(Debug, Clone, PartialEq, Default)]
pub enum ScanState {
    /// No scan has been started yet.
    #[default]
    Idle,
    /// A scan was requested and the worker has not reported back yet.
    Starting,
    /// Host discovery is running; counts come from progress events.
    Discovering { completed: u64, total: u64 },
    /// Discovery is done and TCP ports are being probed.
    ScanningPorts,
    /// The scan completed normally.
    Completed,
    /// The user cancelled the scan; the TUI stays open.
    Cancelled,
    /// The scan failed; the message lives in [`App::scan_error`].
    Error,
}

impl ScanState {
    /// Short label shown on the right side of the title row. Empty while
    /// idle so the row only shows the title and target.
    pub fn label(&self) -> String {
        match self {
            ScanState::Idle => String::new(),
            ScanState::Starting => "STARTING".to_owned(),
            ScanState::Discovering { .. } => "DISCOVERING".to_owned(),
            ScanState::ScanningPorts => "SCANNING PORTS".to_owned(),
            ScanState::Completed => "COMPLETED".to_owned(),
            ScanState::Cancelled => "CANCELLED".to_owned(),
            ScanState::Error => "ERROR".to_owned(),
        }
    }

    /// True while a scan is actively running (starting, discovering, or
    /// scanning ports). Terminal states (`Completed`, `Cancelled`, `Error`)
    /// and `Idle` are not active.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            ScanState::Starting | ScanState::Discovering { .. } | ScanState::ScanningPorts
        )
    }
}

/// The top-level view the TUI is showing.
///
/// `Overview` is the main scan screen; `History` lists the saved scan records,
/// `Diff` shows the comparison of two of them, and `Network` groups the
/// discovered hosts by /24 subnet (organization only, no topology claim).
///
/// The derived `Default` is `Overview`, the first variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum View {
    /// The main scan screen (progress, hosts, details).
    #[default]
    Overview,
    /// The saved-scan browser.
    History,
    /// The comparison of two saved scans.
    Diff,
    /// Discovered hosts grouped by /24 subnet.
    Network,
}

/// Two saved records chosen for comparison, together with their computed diff
/// (Phase 15).
///
/// Created when the user marks a second record with `d` on the history screen
/// and displayed while [`View::Diff`] is active.
#[derive(Debug)]
pub struct DiffSelection {
    /// The earlier record (ordered by timestamp at selection time).
    pub before: RecordSummary,
    /// The later record.
    pub after: RecordSummary,
    /// The differences between the two records.
    pub result: ScanDiff,
}

/// A focusable field of the new-scan dialog (Phase 19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum NewScanField {
    /// The target input line.
    #[default]
    Target,
    /// The discovery strategy selector.
    Strategy,
    /// The port profile selector.
    Profile,
}

/// A new scan committed from the dialog (Phase 19), waiting to be built into
/// a [`ScanConfig`] and started by the event loop.
// Consumed by the run loop in the next step of Phase 19; drop the attribute
// then.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct NewScanRequest {
    /// The parsed scan target.
    target: ScanTarget,
    /// The discovery strategy selected in the dialog.
    discovery: Discovery,
    /// The port profile selected in the dialog.
    profile: PortProfile,
}

/// Central application state.
#[derive(Debug, Default)]
pub struct App {
    pub should_quit: bool,
    /// The validated scan target, if the user provided one.
    pub target: Option<ScanTarget>,
    /// Hosts reported by the scanner, in the order their events arrived.
    pub hosts: Vec<Host>,
    /// The current phase of the scan.
    pub scan: ScanState,
    /// The error message for the most recent failed scan, if any.
    ///
    /// Set when a `ScanEvent::Error` arrives (Phase 10) and cleared whenever a
    /// new scan is started.
    pub scan_error: Option<String>,
    /// Warning message from the most recent scan, if any.
    ///
    /// Set when a `ScanEvent::Warning` arrives (for example, the scanner fell
    /// back to TCP discovery because the ICMP socket could not be opened) and
    /// cleared whenever a new scan is started.
    pub warning: Option<String>,
    /// Number of TCP ports to probe on each up host, from the resolved port
    /// configuration. Drives the live port-progress display.
    pub ports_per_host: usize,
    /// Number of ports probed so far, one per `PortDiscovered` event.
    pub ports_probed: u64,
    /// Index into [`App::hosts`] of the host the user has selected, if any.
    ///
    /// Written by keyboard navigation (Phase 7) and read by the host detail
    /// screen (Phase 8). An out-of-range index is treated as no selection by
    /// [`App::selected`].
    pub selected_host: Option<usize>,
    /// The committed filter text for the host list, if any.
    ///
    /// Set when the user commits the filter input with `Enter` (Phase 9) and
    /// cleared by `Esc` on the overview screen. While the filter input is
    /// active, the typed text takes precedence (see
    /// [`App::effective_filter`]).
    pub filter: Option<String>,
    /// When the current scan started, set on `ScanEvent::Started`.
    started_at: Option<Instant>,
    /// Total duration of the most recently ended scan (finished, cancelled,
    /// or failed); captured when the scan ends and `started_at` is taken.
    scan_duration: Option<Duration>,
    /// Whether the help overlay is open.
    show_help: bool,
    /// Whether the host detail screen is open for the selected host.
    ///
    /// Set by `Enter` on the overview screen (only when a host is selected)
    /// and cleared by `Esc`. While open, only `Esc` (back) and `q` (quit) act.
    show_detail: bool,
    /// Text typed into the filter input since `/` was pressed.
    ///
    /// While non-empty it takes precedence over the committed
    /// [`App::filter`] (live preview); committed on `Enter`, discarded on
    /// `Esc` (Phase 9).
    filter_input: String,
    /// Whether the filter input is active (the user is typing a filter).
    ///
    /// Set by `/` on the overview screen, cleared by `Enter` (commit) or
    /// `Esc` (cancel). While set, every key goes to [`App::handle_filter_input`]
    /// instead of the overview handlers.
    filter_mode: bool,
    /// Whether a rescan has been requested with `r` and is waiting to be
    /// started by the event loop (Phase 10).
    ///
    /// Set by `r` when no scan is active; the event loop consumes the flag and
    /// starts a new scan on the next iteration.
    rescan_requested: bool,
    /// A short message about the most recent export attempt (Phase 11), shown
    /// on the status line until a new scan is started.
    export_status: Option<String>,
    /// A short message about the most recent persistence attempt (Phase 14),
    /// shown on the status line until a new scan is started. Set when a scan
    /// completes and its record is saved (or when saving fails).
    save_status: Option<String>,
    /// The top-level view: overview, saved-scan history, or diff (Phase 15).
    view: View,
    /// Summaries of the saved scan records in the data directory (Phase 15),
    /// newest first.
    ///
    /// Loaded when the history view is opened with `h`.
    history_summaries: Vec<RecordSummary>,
    /// Index into [`App::history_summaries`] of the highlighted record.
    history_selected: usize,
    /// Index into [`App::history_summaries`] of the record marked as a diff
    /// candidate, if any.
    ///
    /// Set by `d` on the history screen: the first press marks the selected
    /// record, a second press on another record opens the diff and clears the
    /// mark, and a press on the already-marked record deselects it.
    history_marked: Option<usize>,
    /// A message about a failed history/diff attempt (Phase 15), shown on the
    /// history screen.
    history_error: Option<String>,
    /// The two saved records being compared and their diff (Phase 15).
    ///
    /// Set when `d` picks a second record on the history screen; cleared by
    /// `Esc` on the diff screen.
    diff_selection: Option<DiffSelection>,
    /// Whether the new-scan dialog is open (Phase 19).
    ///
    /// Opened by `s` when no scan is active; closed by `Enter` (commit) or
    /// `Esc` (cancel). While open, every key goes to
    /// [`App::handle_new_scan_key`] instead of the overview handlers.
    new_scan_mode: bool,
    /// The target text the user is editing in the new-scan dialog.
    ///
    /// Prefilled with the current target's string when the dialog opens
    /// (empty when the app was launched without a target).
    new_scan_target: String,
    /// The discovery strategy selected in the new-scan dialog.
    new_scan_discovery: Discovery,
    /// The port profile selected in the new-scan dialog.
    new_scan_profile: PortProfile,
    /// The focused field in the new-scan dialog.
    new_scan_focus: NewScanField,
    /// The error message for the most recent failed dialog submit (Phase 19),
    /// if any.
    ///
    /// Set when `Enter` cannot parse the target; cleared by typing,
    /// backspacing, or cancelling the dialog.
    new_scan_error: Option<String>,
    /// A new scan committed from the dialog and waiting to be started by the
    /// event loop (Phase 19).
    ///
    /// Set by `Enter` on a valid target; the event loop consumes the request,
    /// builds the scan configuration, and starts the scan.
    new_scan_requested: Option<NewScanRequest>,
}

impl App {
    /// Number of discovered hosts currently in the up state.
    pub fn up_count(&self) -> usize {
        self.hosts
            .iter()
            .filter(|host| host.state == HostState::Up)
            .count()
    }

    /// Number of discovered hosts currently in the down state.
    pub fn down_count(&self) -> usize {
        self.hosts
            .iter()
            .filter(|host| host.state == HostState::Down)
            .count()
    }

    /// Total number of TCP ports to probe across all up hosts: the up-host
    /// count times the per-host port count. Stable once discovery has
    /// finished, i.e. before the first port is probed.
    pub fn ports_total(&self) -> u64 {
        self.up_count() as u64 * self.ports_per_host as u64
    }

    /// Live port-progress text, present once at least one port has been
    /// probed and there is a non-zero total to report against.
    pub fn port_progress(&self) -> Option<String> {
        let total = self.ports_total();
        if self.ports_probed > 0 && total > 0 {
            Some(format!("Ports: {}/{}", self.ports_probed, total))
        } else {
            None
        }
    }

    /// Live scan progress for the overview gauge: a 0–1 ratio plus a label
    /// describing the current phase.
    ///
    /// `Some` while a scan is active (`Starting`, `Discovering`, or
    /// `ScanningPorts`), `None` in every other state so the summary line falls
    /// back to its plain-text parts. The elapsed time is appended only when it
    /// is known; before `ScanEvent::Started` it is not, which also keeps the
    /// label deterministic for a given scan state.
    pub fn scan_progress(&self) -> Option<(f64, String)> {
        let (ratio, label) = match &self.scan {
            ScanState::Starting => (0.0, "Starting…".to_owned()),
            ScanState::Discovering { completed, total } => {
                let ratio = if *total > 0 {
                    *completed as f64 / *total as f64
                } else {
                    0.0
                };
                (
                    ratio,
                    format!("Discovering {completed}/{total} · {} up", self.up_count()),
                )
            }
            ScanState::ScanningPorts => {
                let total = self.ports_total();
                let probed = self.ports_probed;
                let ratio = if total > 0 {
                    probed as f64 / total as f64
                } else {
                    0.0
                };
                (
                    ratio,
                    format!("Probing ports {probed}/{total} · {} up", self.up_count()),
                )
            }
            _ => return None,
        };
        let label = match self.elapsed(Instant::now()) {
            Some(elapsed) => format!("{label} · {}", format_duration(elapsed)),
            None => label,
        };
        Some((ratio, label))
    }

    /// The host at the [`App::selected_host`] index, if a host is selected
    /// and the index is in range.
    ///
    /// This is what the host detail screen (Phase 8) renders; `None` when no
    /// host is selected or the index is out of range.
    pub fn selected(&self) -> Option<&Host> {
        self.selected_host.and_then(|index| self.hosts.get(index))
    }

    /// The filter text currently in effect for the host list, if any.
    ///
    /// While the filter input is active, the typed text takes precedence so
    /// the list updates as the user types; otherwise the committed filter
    /// (if any) is used. Empty text is treated as no filter (see
    /// [`App::visible_indices`]).
    pub fn effective_filter(&self) -> Option<&str> {
        if !self.filter_input.is_empty() {
            Some(&self.filter_input)
        } else {
            self.filter.as_deref()
        }
    }

    /// Indices into [`App::hosts`] of the hosts that match the effective
    /// filter, in their original order.
    ///
    /// With no effective filter every host is visible. Matching is a
    /// case-insensitive substring test over the IP, the state, and the port
    /// numbers (Phase 9: simple filtering, no query language).
    pub fn visible_indices(&self) -> Vec<usize> {
        let Some(filter) = self.effective_filter() else {
            return (0..self.hosts.len()).collect();
        };
        self.hosts
            .iter()
            .enumerate()
            .filter(|(_, host)| host_matches(host, filter))
            .map(|(index, _)| index)
            .collect()
    }

    /// Elapsed time of the current or most recent scan.
    ///
    /// While a scan is running (from `ScanEvent::Started` until it ends), this
    /// is the time since the scan started, measured at `now`. After the scan
    /// ends, the frozen total duration is returned regardless of `now`.
    /// `None` when no scan has ever started.
    pub fn elapsed(&self, now: Instant) -> Option<Duration> {
        self.started_at
            .map(|start| now.duration_since(start))
            .or(self.scan_duration)
    }

    /// Apply one scanner event to the application state.
    ///
    /// This is the single place scan-state transitions happen (Phase 10):
    /// `Starting` (set by the TUI when a scan is spawned) advances to
    /// `Discovering` on `Started`, then to `ScanningPorts` on the first
    /// `PortDiscovered`, and finally to a terminal state on `Finished`,
    /// `Cancelled`, or `Error`.
    pub fn apply_event(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Started { total } => {
                // Discovery begins: record the total host count and the start
                // instant for elapsed/duration tracking, and drop any stale
                // warning from a previous scan.
                self.warning = None;
                self.scan = ScanState::Discovering {
                    completed: 0,
                    total,
                };
                self.started_at = Some(Instant::now());
            }
            ScanEvent::HostDiscovered(host) => {
                self.hosts.push(host);
            }
            ScanEvent::Progress { completed, total } => {
                // Discovery progress only updates the `Discovering` counts; once
                // port scanning has started the progress is derived from
                // `ports_probed` instead.
                if matches!(self.scan, ScanState::Discovering { .. }) {
                    self.scan = ScanState::Discovering { completed, total };
                }
            }
            ScanEvent::Finished => self.end_scan(ScanState::Completed),
            ScanEvent::Cancelled => self.end_scan(ScanState::Cancelled),
            ScanEvent::PortDiscovered { ip, port, state } => {
                // The first probed port marks the transition from discovery to
                // port scanning.
                if matches!(self.scan, ScanState::Discovering { .. }) {
                    self.scan = ScanState::ScanningPorts;
                }
                // The scanner emits this for every probed port (open or closed);
                // count each one for live port progress and record each probed
                // port with its state on the matching host. A host is always
                // discovered before its ports are probed, so it is already
                // present here; a miss is simply ignored.
                self.ports_probed += 1;
                if let Some(host) = self.hosts.iter_mut().find(|h| h.ip == ip) {
                    host.add_probed_port(port, state);
                }
            }
            ScanEvent::ServiceDiscovered { ip, port, service } => {
                // Attach the detected service to the probed-port record. The
                // port was already reported open before any service event, so
                // neither the scan state nor the progress counts change here;
                // a missing host or port entry is simply ignored.
                if let Some(host) = self.hosts.iter_mut().find(|h| h.ip == ip) {
                    if let Some(probed) = host.ports.iter_mut().find(|p| p.port == port) {
                        probed.service = Some(service);
                    }
                }
            }
            ScanEvent::HostEnriched {
                ip,
                hostname,
                mac,
                vendor,
            } => {
                // Attach the enrichment to the host. The host was already
                // discovered before its enrichment ran, so neither the scan
                // state nor the progress counts change here; a missing host is
                // simply ignored. Only fields the enrichers actually produced
                // are `Some`, so `None` fields leave the host unchanged.
                if let Some(host) = self.hosts.iter_mut().find(|h| h.ip == ip) {
                    if let Some(hostname) = hostname {
                        host.hostname = Some(hostname);
                    }
                    if let Some(mac) = mac {
                        host.mac = Some(mac);
                    }
                    if let Some(vendor) = vendor {
                        host.vendor = Some(vendor);
                    }
                }
            }
            // Non-fatal: show the message on the status line but do not
            // change the scan state or progress.
            ScanEvent::Warning(message) => {
                self.warning = Some(message);
            }
            ScanEvent::Error(err) => {
                // Keep the message for the status line; the state only records
                // that an error occurred.
                self.scan_error = Some(err.to_string());
                self.end_scan(ScanState::Error);
            }
        }
    }

    /// Handle a keypress, updating application state.
    ///
    /// `cancel` is the shared cancellation flag the scanner polls; pressing
    /// `c` or `q` sets it so in-flight probes stop.
    ///
    /// While the help overlay is open, only `?` and `Esc` dismiss it and `q`
    /// still quits; every other key is ignored until it is closed.
    ///
    /// While the host detail screen is open, only `Esc` (back) and `q` (quit)
    /// act; every other key is ignored until it is closed. On the overview
    /// screen, `Enter` opens the detail screen for the selected host.
    ///
    /// While filter input is active (started with `/` on the overview
    /// screen), every key is routed to `handle_filter_input` instead of the
    /// overview handlers (Phase 9): characters and backspace edit the filter,
    /// `Enter` commits it, and `Esc` discards the buffer and leaves input
    /// mode.
    ///
    /// On the history screen (Phase 15), `Up`/`k` and `Down`/`j` move through
    /// the saved records, `d` marks the selected record for comparison (a
    /// second mark on another record opens the diff), and `Esc` returns to the
    /// overview. On the diff screen, only `Esc` (back to history) and `q`
    /// (quit) act.
    ///
    /// While the new-scan dialog is open (started with `s` on the overview
    /// screen), every key is routed to [`App::handle_new_scan_key`] instead of
    /// the overview handlers (Phase 19).
    pub fn handle_key(&mut self, key: KeyCode, cancel: &AtomicBool) {
        if self.new_scan_mode {
            self.handle_new_scan_key(key);
            return;
        }
        if self.show_help {
            match key {
                KeyCode::Char('?') | KeyCode::Esc => self.show_help = false,
                KeyCode::Char('q') => self.quit(cancel),
                _ => {}
            }
            return;
        }
        if self.show_detail {
            match key {
                KeyCode::Esc => self.show_detail = false,
                KeyCode::Char('q') => self.quit(cancel),
                _ => {}
            }
            return;
        }
        if self.filter_mode {
            self.handle_filter_input(key);
            return;
        }
        if self.view == View::History {
            self.handle_history_key(key, cancel);
            return;
        }
        if self.view == View::Diff {
            self.handle_diff_key(key, cancel);
            return;
        }
        if self.view == View::Network {
            self.handle_network_key(key, cancel);
            return;
        }
        match key {
            KeyCode::Char('q') => self.quit(cancel),
            KeyCode::Char('c') if self.scan.is_active() => {
                // Only raise the flag; the scanner's `Cancelled` event performs
                // the terminal state transition (Phase 10).
                cancel.store(true, Ordering::SeqCst);
            }
            KeyCode::Char('r') if !self.scan.is_active() => {
                self.rescan_requested = true;
            }
            KeyCode::Char('s') if !self.scan.is_active() => {
                self.open_new_scan();
            }
            KeyCode::Char('e') => self.export_results(),
            KeyCode::Char('h') => self.open_history(),
            KeyCode::Char('n') => self.view = View::Network,
            KeyCode::Char('/') => {
                self.filter_input.clear();
                self.filter_mode = true;
            }
            KeyCode::Esc => self.filter = None,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Enter if self.selected().is_some() => self.show_detail = true,
            _ => {}
        }
    }

    /// Open the new-scan dialog (Phase 19), prefilled from the current target.
    ///
    /// Called from the `s` binding on the overview screen when no scan is
    /// active. The target field starts with the current target's string (empty
    /// when the app was launched without one), and the strategy and profile
    /// start at their defaults ([`Discovery::Auto`] and
    /// [`PortProfile::Quick`]).
    fn open_new_scan(&mut self) {
        self.new_scan_target = self
            .target
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();
        self.new_scan_discovery = Discovery::Auto;
        self.new_scan_profile = PortProfile::Quick;
        self.new_scan_focus = NewScanField::Target;
        self.new_scan_error = None;
        self.new_scan_mode = true;
    }

    /// Handle a keypress while the new-scan dialog is open (Phase 19).
    ///
    /// `Tab` moves focus Target → Strategy → Profile, wrapping around;
    /// `Left`/`Right` cycle the focused strategy or profile value. Printable
    /// characters append to the target and move focus back to it; `Backspace`
    /// removes the last character. Typing and backspacing also clear a pending
    /// error. `Enter` parses the target: on success it records a
    /// [`NewScanRequest`] for the event loop and closes the dialog; on failure
    /// it shows the error and keeps the dialog open. `Esc` cancels and clears
    /// the error.
    fn handle_new_scan_key(&mut self, key: KeyCode) {
        const DISCOVERIES: [Discovery; 3] = [Discovery::Auto, Discovery::Icmp, Discovery::Tcp];
        const PROFILES: [PortProfile; 3] =
            [PortProfile::Quick, PortProfile::Common, PortProfile::Full];

        match key {
            KeyCode::Tab => {
                self.new_scan_focus = match self.new_scan_focus {
                    NewScanField::Target => NewScanField::Strategy,
                    NewScanField::Strategy => NewScanField::Profile,
                    NewScanField::Profile => NewScanField::Target,
                };
            }
            KeyCode::Left | KeyCode::Right => {
                let forward = key == KeyCode::Right;
                match self.new_scan_focus {
                    NewScanField::Strategy => {
                        self.new_scan_discovery =
                            cycle_variant(self.new_scan_discovery, &DISCOVERIES, forward);
                    }
                    NewScanField::Profile => {
                        self.new_scan_profile =
                            cycle_variant(self.new_scan_profile, &PROFILES, forward);
                    }
                    NewScanField::Target => {}
                }
            }
            KeyCode::Char(c) => {
                self.new_scan_target.push(c);
                self.new_scan_focus = NewScanField::Target;
                self.new_scan_error = None;
            }
            KeyCode::Backspace => {
                self.new_scan_target.pop();
                self.new_scan_error = None;
            }
            KeyCode::Enter => match ScanTarget::parse(&self.new_scan_target) {
                Ok(target) => {
                    self.new_scan_requested = Some(NewScanRequest {
                        target,
                        discovery: self.new_scan_discovery,
                        profile: self.new_scan_profile,
                    });
                    self.new_scan_mode = false;
                }
                Err(error) => self.new_scan_error = Some(error.to_string()),
            },
            KeyCode::Esc => {
                self.new_scan_mode = false;
                self.new_scan_error = None;
            }
            _ => {}
        }
    }

    /// Move the host selection by `direction` (-1 up, +1 down) among the
    /// hosts that are currently visible (not hidden by the filter).
    ///
    /// With no visible hosts the selection is cleared. With no visible
    /// selection, down anchors on the first visible host and up on the last.
    /// Otherwise the selection steps to the adjacent visible host, clamped at
    /// the visible ends; a stale (out-of-range) or hidden index is treated as
    /// no selection.
    fn move_selection(&mut self, direction: i8) {
        self.move_within(&self.visible_indices(), direction)
    }

    /// Move the selection by `direction` (-1 up, +1 down) within an explicit
    /// display order.
    ///
    /// `order` is a list of `hosts` indices in display order (for example
    /// the overview's filtered list or the network view's grouped order).
    /// With an empty order the selection is cleared. With no selection in the
    /// order, down anchors on the first entry and up on the last. Otherwise
    /// the selection steps to the adjacent entry, clamped at the ends; a
    /// stale (out-of-range) or out-of-order index is treated as no selection.
    fn move_within(&mut self, order: &[usize], direction: i8) {
        if direction == 0 {
            return;
        }
        if order.is_empty() {
            // Nothing to select.
            self.selected_host = None;
            return;
        }
        let first = order[0];
        let last = *order.last().expect("order checked non-empty");
        let next = match self.selected_host {
            // A selection that is in the order steps to the adjacent entry,
            // clamped at the order's ends.
            Some(index) if order.contains(&index) => {
                let position = order
                    .iter()
                    .position(|&order_index| order_index == index)
                    .expect("selection is an order index");
                if direction > 0 {
                    *order.get(position + 1).unwrap_or(&last)
                } else {
                    *order.get(position.saturating_sub(1)).unwrap_or(&first)
                }
            }
            // No selection, or a stale/out-of-order index: anchor at the end
            // we are moving towards, so the first down selects the first
            // entry and the first up selects the last.
            _ if direction > 0 => first,
            _ => last,
        };
        self.selected_host = Some(next);
    }

    /// The display order of host indices in the network view (Phase 16):
    /// hosts grouped by /24 subnet, groups sorted by network address, hosts
    /// sorted by IP within each group.
    ///
    /// Duplicate IPs (the TUI does not dedupe hosts) map to their last index.
    fn network_order(&self) -> Vec<usize> {
        let mut index_of: HashMap<Ipv4Addr, usize> = HashMap::new();
        for (index, host) in self.hosts.iter().enumerate() {
            index_of.insert(host.ip, index);
        }
        let mut order = Vec::new();
        for group in group_by_subnet(&self.hosts) {
            for host in group.hosts {
                if let Some(&index) = index_of.get(&host.ip) {
                    order.push(index);
                }
            }
        }
        order
    }

    /// Drop the current selection if its host is hidden by the effective
    /// filter, so the selection always refers to a visible host.
    ///
    /// Called while the filter input is being edited.
    fn sync_selection(&mut self) {
        if let Some(index) = self.selected_host {
            if !self.visible_indices().contains(&index) {
                self.selected_host = None;
            }
        }
    }

    /// Handle a keypress while the filter input is active (Phase 9).
    ///
    /// Characters and backspace edit the filter text (with a live preview in
    /// the host list); `Enter` commits the text as the filter (an empty
    /// commit clears it) and `Esc` cancels the edit, keeping the previously
    /// committed filter. Every other key is consumed as input.
    fn handle_filter_input(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char(c) => {
                self.filter_input.push(c);
                self.sync_selection();
            }
            KeyCode::Backspace => {
                self.filter_input.pop();
                self.sync_selection();
            }
            KeyCode::Enter => {
                self.filter = if self.filter_input.is_empty() {
                    None
                } else {
                    Some(std::mem::take(&mut self.filter_input))
                };
                self.filter_mode = false;
            }
            KeyCode::Esc => {
                self.filter_input.clear();
                self.filter_mode = false;
            }
            _ => {}
        }
    }

    /// Open the saved-scan history (Phase 15).
    ///
    /// Loads the record summaries from the data directory and switches to
    /// [`View::History`]. A data-directory resolution failure is reported on
    /// the history screen via [`App::history_error`] instead of blocking the
    /// view.
    pub fn open_history(&mut self) {
        self.view = View::History;
        self.history_error = None;
        self.history_marked = None;
        self.history_selected = 0;
        match crate::storage::data_dir() {
            Ok(dir) => self.load_history(&dir),
            Err(err) => {
                self.history_summaries.clear();
                self.history_error = Some(format!("Could not determine the data directory: {err}"));
            }
        }
    }

    /// Load saved scan records from `dir` into [`App::history_summaries`]
    /// (Phase 15).
    ///
    /// Used by [`App::open_history`] and by the tests, which pass a temporary
    /// directory instead of the real data directory.
    fn load_history(&mut self, dir: &std::path::Path) {
        match crate::storage::list_records(dir) {
            Ok(summaries) => {
                self.history_summaries = summaries;
                self.history_error = None;
            }
            Err(err) => {
                self.history_summaries.clear();
                self.history_error = Some(format!("Could not read saved scans: {err}"));
            }
        }
        // Keep the highlight within range once the list is known.
        if self.history_summaries.is_empty() {
            self.history_selected = 0;
        } else if self.history_selected >= self.history_summaries.len() {
            self.history_selected = self.history_summaries.len() - 1;
        }
    }

    /// Handle a keypress on the history screen (Phase 15).
    fn handle_history_key(&mut self, key: KeyCode, cancel: &AtomicBool) {
        match key {
            KeyCode::Char('q') => self.quit(cancel),
            KeyCode::Up | KeyCode::Char('k') => {
                self.history_selected = self.history_selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.history_selected < self.history_summaries.len().saturating_sub(1) {
                    self.history_selected += 1;
                }
            }
            KeyCode::Char('d') => self.toggle_diff_mark(),
            KeyCode::Esc => {
                self.history_marked = None;
                self.view = View::Overview;
            }
            _ => {}
        }
    }

    /// Mark or unmark the selected record as a diff candidate (Phase 15).
    ///
    /// The first press marks the highlighted record; a second press on a
    /// different record compares the two and switches to [`View::Diff`]; a
    /// press on the already-marked record clears the mark.
    fn toggle_diff_mark(&mut self) {
        // Clone the summaries so they do not borrow the list while
        // `open_diff` mutates the app state.
        let Some(selected) = self.history_summaries.get(self.history_selected).cloned() else {
            return;
        };
        match self.history_marked {
            None => self.history_marked = Some(self.history_selected),
            Some(index) if index == self.history_selected => {
                self.history_marked = None;
            }
            Some(index) => {
                let Some(other) = self.history_summaries.get(index).cloned() else {
                    self.history_marked = None;
                    return;
                };
                self.open_diff(&other, &selected);
            }
        }
    }

    /// Compare two saved records and switch to [`View::Diff`] (Phase 15).
    ///
    /// The records are ordered by timestamp so the earlier scan is always the
    /// "before" side; records with equal timestamps keep the order in which
    /// they were selected (the first-marked record is "before"). A record that
    /// fails to load is reported via [`App::history_error`] and the view stays
    /// on the history screen.
    pub fn open_diff(&mut self, first: &RecordSummary, second: &RecordSummary) {
        let (before, after) = if first.timestamp <= second.timestamp {
            (first, second)
        } else {
            (second, first)
        };
        let (Ok(before_record), Ok(after_record)) = (
            crate::storage::load(&before.path),
            crate::storage::load(&after.path),
        ) else {
            self.history_error = Some("A selected record could not be loaded.".to_owned());
            self.history_marked = None;
            return;
        };
        self.history_marked = None;
        self.diff_selection = Some(DiffSelection {
            before: before.clone(),
            after: after.clone(),
            result: crate::diff::diff_records(&before_record, &after_record),
        });
        self.view = View::Diff;
    }

    /// Handle a keypress on the diff screen (Phase 15).
    fn handle_diff_key(&mut self, key: KeyCode, cancel: &AtomicBool) {
        match key {
            KeyCode::Char('q') => self.quit(cancel),
            KeyCode::Esc => {
                self.diff_selection = None;
                self.view = View::History;
            }
            _ => {}
        }
    }

    /// Handle a key pressed in the network view (Phase 16).
    ///
    /// `Esc` returns to the overview, `j`/`k`/`Up`/`Down` move the selection
    /// through the grouped display order, and `Enter` opens the host detail.
    /// The detail screen itself is handled by the top-level `show_detail`
    /// branch in [`App::handle_key`].
    fn handle_network_key(&mut self, key: KeyCode, cancel: &AtomicBool) {
        match key {
            KeyCode::Char('q') => self.quit(cancel),
            KeyCode::Esc => self.view = View::Overview,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Up | KeyCode::Char('k') => self.move_within(&self.network_order(), -1),
            KeyCode::Down | KeyCode::Char('j') => self.move_within(&self.network_order(), 1),
            KeyCode::Enter if self.selected().is_some() => self.show_detail = true,
            _ => {}
        }
    }

    /// Export the current scan results to a JSON file (Phase 11).
    ///
    /// Only acts when a target exists; otherwise it is a no-op. The results of
    /// the current scan state (however far the scan has progressed) are
    /// written to a file in the current directory, and the outcome is reported
    /// on the status line via [`App::export_status`].
    fn export_results(&mut self) {
        let Some(target) = &self.target else {
            return;
        };
        match crate::export::export(target, &self.hosts) {
            Ok(path) => self.export_status = Some(format!("Exported {}", path.display())),
            Err(err) => self.export_status = Some(format!("Export failed: {err}")),
        }
    }

    /// Transition to a terminal scan state, freezing the elapsed time.
    ///
    /// The start instant recorded on `ScanEvent::Started` is captured as the
    /// total scan duration; a later terminal event does not change it.
    fn end_scan(&mut self, state: ScanState) {
        if let Some(start) = self.started_at.take() {
            self.scan_duration = Some(start.elapsed());
        }
        self.scan = state;
    }

    /// Quit: mark the app for exit and stop any in-flight scan.
    fn quit(&mut self, cancel: &AtomicBool) {
        self.should_quit = true;
        cancel.store(true, Ordering::SeqCst);
    }

    /// Start a new scan: reset per-scan state and launch the worker through the
    /// provided spawner (Phase 10).
    ///
    /// Called for the first scan at the start of the event loop and again for
    /// each rescan requested with `r`. The spawner, configuration, master
    /// sender, and cancellation flag are owned by the caller rather than the
    /// [`App`], so the app remains a plain, `Debug`/`Default` data container.
    /// A fresh scan clears hosts, selection, error text, and the port count,
    /// and re-raises the cancellation flag to a clean slate.
    fn start_scan(
        &mut self,
        config: &ScanConfig,
        spawner: &ScanSpawner,
        master_tx: &Sender<ScanEvent>,
        cancel: &Arc<AtomicBool>,
    ) {
        self.scan = ScanState::Starting;
        self.hosts.clear();
        self.selected_host = None;
        self.scan_error = None;
        self.export_status = None;
        self.save_status = None;
        self.ports_probed = 0;
        self.started_at = None;
        self.scan_duration = None;
        // A prior scan may have left the flag raised (e.g. after a cancel);
        // start from a clean slate.
        cancel.store(false, Ordering::SeqCst);
        spawner(config.clone(), master_tx.clone(), cancel.clone());
    }
}

/// Return the next (or previous) value in a closed list of variants, wrapping
/// around at the ends.
///
/// Used by the new-scan dialog to cycle the discovery strategy and port
/// profile selectors (Phase 19).
fn cycle_variant<T: Copy + PartialEq>(value: T, variants: &[T], forward: bool) -> T {
    let current = variants
        .iter()
        .position(|variant| *variant == value)
        .expect("the current value must be one of the variants");
    let next = if forward {
        (current + 1) % variants.len()
    } else {
        (variants.len() - 1 + current) % variants.len()
    };
    variants[next]
}

/// Build the [`ScanConfig`] for a new scan requested from the in-TUI dialog.
///
/// When a `template` is given (the configuration the TUI was launched with),
/// its per-stage tunables — timeouts, concurrency, and the
/// `detect_services`/`enrich` toggles — are carried over so the user does not
/// have to re-enter them. With no template (the TUI was started without a
/// target) a fresh [`ScanConfig::new`] provides the defaults. The target,
/// discovery strategy, and port profile chosen in the dialog always win.
// Wired into the run loop in the next step of Phase 19; drop the attribute then.
#[allow(dead_code)]
fn build_new_scan_config(
    template: Option<&ScanConfig>,
    target: ScanTarget,
    discovery: Discovery,
    profile: PortProfile,
) -> ScanConfig {
    let mut config = match template {
        Some(template) => template.clone(),
        None => ScanConfig::new(target.clone()),
    };
    config.target = target;
    config.discovery_strategy = discovery;
    config.ports.ports = profile.ports();
    config
}

/// Run the terminal UI until the user quits, then restore the terminal.
///
/// `ports_per_host` is the number of TCP ports the scanner will probe on each
/// up host, used to derive the live port-progress display. `config` together
/// with `spawner` lets the event loop launch the first scan and any rescans;
/// `config` is `None` (and scanning is unavailable) when no target was given.
pub fn run(
    target: Option<ScanTarget>,
    ports_per_host: usize,
    config: Option<ScanConfig>,
    spawner: ScanSpawner,
    master_tx: Sender<ScanEvent>,
    events: Receiver<ScanEvent>,
    cancel: Arc<AtomicBool>,
) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App {
        target,
        ports_per_host,
        ..Default::default()
    };
    let result = run_loop(
        &mut terminal,
        &mut app,
        config,
        &spawner,
        &master_tx,
        &events,
        &cancel,
    );

    // Restore the terminal even if the event loop failed.
    let restore = restore_terminal(&mut terminal);

    match (result, restore) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// The event loop owns the configuration of the scan currently in flight as
/// `current_config`. Launching a scan and persisting its results both read it,
/// so a scan started with a changed configuration (e.g. a later new-scan
/// request) is also persisted with the configuration that was actually used.
fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    current_config: Option<ScanConfig>,
    spawner: &ScanSpawner,
    master_tx: &Sender<ScanEvent>,
    events: &Receiver<ScanEvent>,
    cancel: &Arc<AtomicBool>,
) -> io::Result<()> {
    // Launch the first scan if a target and its configuration are present.
    if let Some(config) = current_config.as_ref() {
        app.start_scan(config, spawner, master_tx, cancel);
    }
    // Whether the current scan has already been persisted (Phase 14). Reset
    // whenever a new scan starts so each completed scan is saved exactly once.
    let mut persisted = false;

    loop {
        // Drain scanner events first so new results appear on the next frame.
        // A disconnected channel simply means the scanner is done (or never
        // started); there is nothing more to apply.
        while let Ok(event) = events.try_recv() {
            app.apply_event(event);
        }

        // Persist the scan exactly once, the moment it transitions to
        // `Completed` (not on cancel or error). Saving is a file-I/O concern
        // of the event loop, kept out of the pure state transition in
        // [`App::apply_event`].
        if !persisted && matches!(app.scan, ScanState::Completed) {
            persisted = true;
            if let Some(config) = current_config.as_ref() {
                match crate::storage::save_scan(&config.target, &app.hosts, config) {
                    Ok(path) => app.save_status = Some(format!("Saved {}", path.display())),
                    Err(err) => app.save_status = Some(format!("Save failed: {err}")),
                }
            }
        }

        terminal.draw(|f| draw(f, app))?;

        if app.should_quit {
            return Ok(());
        }

        if event::poll(Duration::from_millis(100))? {
            // Resize and other events are reflected on the next draw,
            // which re-queries the terminal size.
            if let Event::Key(key) = event::read()? {
                app.handle_key(key.code, cancel);
            }
        }

        // A rescan was requested with `r` while no scan was active; start it
        // now (Phase 10). With no configuration (no target) the request is
        // simply discarded.
        if app.rescan_requested {
            app.rescan_requested = false;
            if let Some(config) = current_config.as_ref() {
                app.start_scan(config, spawner, master_tx, cancel);
                persisted = false;
            }
        }
    }
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()
}

/// Draw the top-level view: the overview, the saved-scan history, the scan
/// diff (Phase 15), or the network view (Phase 16). The help overlay and the
/// new-scan dialog (Phase 19) render on top of the active view.
fn draw(frame: &mut Frame, app: &App) {
    match app.view {
        View::Overview => draw_overview(frame, app),
        View::History => draw_history(frame, app),
        View::Diff => draw_diff(frame, app),
        View::Network => draw_network(frame, app),
    }

    if app.show_help {
        draw_help_overlay(frame);
    }

    if app.new_scan_mode {
        draw_new_scan_dialog(frame, app);
    }
}

/// Draw the network view (Phase 16): discovered hosts grouped by /24 subnet,
/// clearly labeled as organization only — no topology is claimed.
///
/// Every discovered host is listed, grouped into /24 subnets (see
/// [`crate::subnet::group_by_subnet`]). Groups are ordered by network address
/// and the hosts within each group are ordered by IP. The grouping is purely
/// organizational: it makes a long list easier to read and asserts no routing
/// or topology relationship between the hosts. Pressing `Enter` on a selected
/// host opens the shared host detail screen (Phase 8); `Esc` returns here.
fn draw_network(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let title = Paragraph::new("Network").style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(title, chunks[0]);

    let subtitle =
        Paragraph::new("Grouped by /24 subnet — organization only; no topology is claimed.");
    frame.render_widget(subtitle, chunks[1]);

    if app.show_detail {
        draw_host_detail(frame, app, chunks[2]);
    } else {
        draw_network_list(frame, app, chunks[2]);
    }

    let hint = if app.show_detail {
        "Esc Back  q Quit".to_string()
    } else {
        "↑/k Up  ↓/j Down  Enter Detail  Esc Back  ? Help  q Quit".to_string()
    };
    frame.render_widget(Paragraph::new(hint), chunks[3]);
}

/// Build and render the grouped host list for the network view.
///
/// Each /24 group is introduced by a bold header line followed by one line per
/// host in IP order. The currently selected host is drawn reversed, and the
/// list is scrolled so the selection stays visible (see [`window_start`]).
fn draw_network_list(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title("Hosts by /24");
    let inner = block.inner(area);
    if app.hosts.is_empty() {
        frame.render_widget(Paragraph::new("No hosts discovered.").block(block), area);
        return;
    }

    let groups = group_by_subnet(&app.hosts);
    let selected_ip = app.selected().map(|host| host.ip);

    let mut lines: Vec<Line<'_>> = Vec::new();
    let mut selected_position: Option<usize> = None;
    for group in &groups {
        let host_count = group.hosts.len();
        lines.push(
            Line::from(format!(
                "{}/24  ({} host{})",
                group.network,
                host_count,
                if host_count == 1 { "" } else { "s" }
            ))
            .style(Style::default().add_modifier(Modifier::BOLD)),
        );
        for host in &group.hosts {
            let selected = selected_ip.is_some_and(|ip| host.ip == ip);
            if selected {
                selected_position = Some(lines.len());
            }
            // The state span carries the state color; a selected line is
            // reversed as a whole, which composes with the span color.
            let mut line = Line::from(vec![
                Span::raw(format!("  {}", host.ip)),
                Span::styled(
                    format!("{:<4}", host.state),
                    Style::default().fg(state_color(host.state)),
                ),
                Span::raw(format!("  {}", format_open_ports(&host.ports))),
            ]);
            if selected {
                line = line.style(Modifier::REVERSED);
            }
            lines.push(line);
        }
    }

    let start = window_start(lines.len(), selected_position, inner.height as usize);
    let visible: Vec<Line<'_>> = lines
        .iter()
        .skip(start)
        .take(inner.height as usize)
        .cloned()
        .collect();
    frame.render_widget(Paragraph::new(visible).block(block), area);
}

/// Draw the main scan screen: title row, status line, host list (or detail
/// screen), and the hint line.
fn draw_overview(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(frame.area());

    // Title row: `PORT-SCANNER  <target>` on the left, scan phase on the
    // right, mirroring the plan's UI mockup.
    let title = match &app.target {
        Some(target) => format!("PORT-SCANNER  {target}"),
        None => "PORT-SCANNER".to_owned(),
    };
    let title_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(chunks[0]);
    let title = Paragraph::new(title).style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(title, title_chunks[0]);
    let status = Paragraph::new(app.scan.label()).alignment(Alignment::Right);
    frame.render_widget(status, title_chunks[1]);

    // Summary line: while a scan is active it is a live gauge (0–1 ratio plus
    // a phase label that already carries the counts and elapsed time); in
    // every other state it is plain text — host counts, port progress, and
    // elapsed time (frozen after the scan ends), plus any
    // error/warning/export/save status.
    match app.scan_progress() {
        Some((ratio, label)) => {
            let gauge = Gauge::default().ratio(ratio).label(label);
            frame.render_widget(gauge, chunks[1]);
        }
        None => {
            let mut parts = vec![format!(
                "Hosts: {} up / {} down",
                app.up_count(),
                app.down_count()
            )];
            if let Some(progress) = app.port_progress() {
                parts.push(progress);
            }
            if let Some(elapsed) = app.elapsed(Instant::now()) {
                parts.push(format!("Elapsed: {}", format_duration(elapsed)));
            }
            if let Some(err) = &app.scan_error {
                parts.push(format!("Error: {err}"));
            }
            if let Some(warning) = &app.warning {
                parts.push(format!("Warning: {warning}"));
            }
            if let Some(status) = &app.export_status {
                parts.push(status.clone());
            }
            if let Some(status) = &app.save_status {
                parts.push(status.clone());
            }
            let status_line = Paragraph::new(parts.join("  "));
            frame.render_widget(status_line, chunks[1]);
        }
    }

    if app.target.is_some() {
        if app.show_detail {
            draw_host_detail(frame, app, chunks[2]);
        } else {
            let visible = app.visible_indices();
            let title = hosts_frame_title(
                app.effective_filter().map(|_| visible.len()),
                app.hosts.len(),
            );
            if app.effective_filter().is_some() && visible.is_empty() {
                let block = Block::default().borders(Borders::ALL).title(title);
                frame.render_widget(
                    Paragraph::new("No hosts match the filter.").block(block),
                    chunks[2],
                );
            } else {
                let block = Block::default().borders(Borders::ALL).title(title);
                let table = host_table(app, &visible, block.inner(chunks[2]));
                frame.render_widget(table.block(block), chunks[2]);
            }
        }
    } else {
        let hint =
            Paragraph::new("No target. Run port-scanner with an IPv4 address or CIDR range.");
        frame.render_widget(hint, chunks[2]);
    }

    let hint = if app.show_detail {
        "Esc Back  q Quit".to_string()
    } else if app.filter_mode {
        format!("Filter: {}", app.filter_input)
    } else if let Some(filter) = app.filter.as_deref() {
        format!("Filter: {filter}  / Edit  Esc Clear  ? Help  q Quit")
    } else {
        "↑/k Up  ↓/j Down  Enter Detail  / Filter  e Export  h History  n Network  s New Scan  ? Help  c Cancel  q Quit"
            .to_string()
    };
    frame.render_widget(Paragraph::new(hint), chunks[3]);
}

/// Draw the saved-scan history view (Phase 15): a table of the records in
/// the data directory, newest first, with the selected row highlighted and
/// the diff-marked row starred.
fn draw_history(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let title = Paragraph::new("PORT-SCANNER  Saved Scans")
        .style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(title, chunks[0]);

    let block = Block::default().borders(Borders::ALL).title("Saved Scans");
    let inner = block.inner(chunks[1]);

    if let Some(err) = &app.history_error {
        frame.render_widget(Paragraph::new(err.as_str()).block(block.clone()), chunks[1]);
    } else if app.history_summaries.is_empty() {
        frame.render_widget(
            Paragraph::new("No saved scans yet. Complete a scan to save one.").block(block.clone()),
            chunks[1],
        );
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let header = Row::new(vec!["", "AGE", "TARGET", "HOSTS", "OPEN PORTS"])
            .style(Style::default().add_modifier(Modifier::BOLD));
        let row_space = inner.height as usize;
        let start = window_start(
            app.history_summaries.len(),
            Some(app.history_selected),
            row_space,
        );
        let rows: Vec<Row> = app
            .history_summaries
            .iter()
            .enumerate()
            .skip(start)
            .take(row_space)
            .map(|(index, record)| {
                let selected = app.history_selected == index;
                let marked = app.history_marked == Some(index);
                let style = if selected {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                };
                let cells: Vec<Cell<'_>> = vec![
                    Cell::from(if marked { "* " } else { "  " }),
                    Cell::from(format_age(record.timestamp, now)),
                    Cell::from(record.target.clone()),
                    Cell::from(record.host_count.to_string()),
                    Cell::from(record.open_port_count.to_string()),
                ]
                .into_iter()
                .map(|cell| cell.set_style(style))
                .collect();
                Row::new(cells)
            })
            .collect();
        frame.render_widget(
            Table::new(
                [header].into_iter().chain(rows),
                [
                    Constraint::Length(2),
                    Constraint::Length(10),
                    Constraint::Min(10),
                    Constraint::Length(8),
                    Constraint::Length(12),
                ],
            )
            .block(block),
            chunks[1],
        );
    }

    let hint = "↑/k Up  ↓/j Down  d Mark/Compare  Esc Back  q Quit";
    frame.render_widget(Paragraph::new(hint), chunks[2]);
}

/// Draw the scan-diff view (Phase 15): the two selected records and the
/// differences between them, with added items in green, removed items in red,
/// and changed items in yellow.
fn draw_diff(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let title = Paragraph::new("PORT-SCANNER  Scan Diff")
        .style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(title, chunks[0]);

    let block = Block::default().borders(Borders::ALL).title("Diff");

    let Some(selection) = &app.diff_selection else {
        frame.render_widget(
            Paragraph::new("No diff selected.").block(block.clone()),
            chunks[1],
        );
        frame.render_widget(Paragraph::new("Esc Back to history  q Quit"), chunks[2]);
        return;
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut lines = vec![
        Line::from(format!(
            "Before: {}  {}  ({} hosts, {} open ports)",
            format_age(selection.before.timestamp, now),
            selection.before.target,
            selection.before.host_count,
            selection.before.open_port_count
        )),
        Line::from(format!(
            "After:  {}  {}  ({} hosts, {} open ports)",
            format_age(selection.after.timestamp, now),
            selection.after.target,
            selection.after.host_count,
            selection.after.open_port_count
        )),
        Line::from(""),
    ];

    let diff = &selection.result;
    if diff.is_empty() {
        lines.push(Line::from("No changes between the two scans."));
    } else {
        for host in &diff.hosts_added {
            lines.push(diff_line(
                format!(
                    "+ host {}  open: {}",
                    host.ip,
                    open_port_list(&host.open_ports)
                ),
                Color::Green,
            ));
        }
        for host in &diff.hosts_removed {
            lines.push(diff_line(
                format!(
                    "- host {}  open: {}",
                    host.ip,
                    open_port_list(&host.open_ports)
                ),
                Color::Red,
            ));
        }
        for port in &diff.ports_opened {
            lines.push(diff_line(
                format!(
                    "+ port {}:{}  {}",
                    port.ip,
                    port.port,
                    present_or_none(port.service.as_deref())
                ),
                Color::Green,
            ));
        }
        for port in &diff.ports_closed {
            lines.push(diff_line(
                format!(
                    "- port {}:{}  {}",
                    port.ip,
                    port.port,
                    present_or_none(port.service.as_deref())
                ),
                Color::Red,
            ));
        }
        for host in &diff.hosts_changed {
            lines.push(diff_line(
                format!("~ host {}  information changed", host.ip),
                Color::Yellow,
            ));
            for change in &host.changes {
                lines.push(Line::from(format!(
                    "    {}: {} -> {}",
                    change.field.name(),
                    present_or_none(change.before.as_deref()),
                    present_or_none(change.after.as_deref())
                )));
            }
        }
        for service in &diff.services_changed {
            lines.push(diff_line(
                format!(
                    "~ service {}:{}  {} -> {}",
                    service.ip,
                    service.port,
                    present_or_none(service.before.as_deref()),
                    present_or_none(service.after.as_deref())
                ),
                Color::Yellow,
            ));
        }
    }

    frame.render_widget(Paragraph::new(lines).block(block), chunks[1]);

    let hint = "Esc Back to history  q Quit";
    frame.render_widget(Paragraph::new(hint), chunks[2]);
}

/// A diff line with the given color.
fn diff_line(text: String, color: Color) -> Line<'static> {
    Line::from(text).style(Style::default().fg(color))
}

/// Render a list of open port numbers for diff lines: `22, 443`, or `none`
/// when the host had no open ports.
fn open_port_list(ports: &[u16]) -> String {
    if ports.is_empty() {
        "none".to_owned()
    } else {
        ports
            .iter()
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Render an optional value for diff lines, showing `none` when absent.
fn present_or_none(value: Option<&str>) -> String {
    match value {
        Some(value) => value.to_owned(),
        None => "none".to_owned(),
    }
}

/// Render a Unix timestamp as a short relative age: `42s ago`, `5m ago`,
/// `3h ago`, or `2d ago`. Future timestamps saturate to `0s ago`.
fn format_age(timestamp: u64, now: u64) -> String {
    let age = now.saturating_sub(timestamp);
    if age < 60 {
        format!("{age}s ago")
    } else if age < 3600 {
        format!("{}m ago", age / 60)
    } else if age < 86_400 {
        format!("{}h ago", age / 3600)
    } else {
        format!("{}d ago", age / 86_400)
    }
}

/// The foreground color for a host's liveness state: up hosts stand out in
/// green, down hosts are dimmed so they recede in the list.
fn state_color(state: HostState) -> Color {
    match state {
        HostState::Up => Color::Green,
        HostState::Down => Color::DarkGray,
    }
}

fn host_table<'a>(app: &'a App, visible: &'a [usize], area: Rect) -> Table<'a> {
    let header = Row::new(vec!["", "IP", "STATE", "LATENCY", "OPEN PORTS"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    // Only render the rows that fit in the visible area, keeping the selected
    // host in view. `area.height` includes the header row, so one row of data
    // is visible per remaining line.
    let row_space = area.height.saturating_sub(1) as usize;
    let selected_position = app.selected_host.and_then(|index| {
        visible
            .iter()
            .position(|&visible_index| visible_index == index)
    });
    let start = window_start(visible.len(), selected_position, row_space);
    let rows: Vec<Row> = visible
        .iter()
        .copied()
        .skip(start)
        .take(row_space)
        .map(|index| {
            let host = &app.hosts[index];
            let selected = app.selected_host == Some(index);
            let style = if selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            // The state cell gets the row style patched with the state color
            // (not replaced) so a selected row keeps its reversed background.
            let state_style = style.patch(state_color(host.state));
            let cells = vec![
                Cell::from(if selected { "▸ " } else { "  " }).set_style(style),
                Cell::from(host.ip.to_string()).set_style(style),
                Cell::from(host.state.to_string()).set_style(state_style),
                Cell::from(format_latency(host.latency)).set_style(style),
                Cell::from(format_open_ports(&host.ports)).set_style(style),
            ];
            Row::new(cells)
        })
        .collect();
    Table::new(
        [header].into_iter().chain(rows),
        [
            Constraint::Length(2),
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Min(10),
        ],
    )
}

/// Whether a host matches a case-insensitive filter needle.
///
/// An empty needle matches every host. Otherwise the needle is matched as a
/// substring against the IP address, the state name, each probed port number
/// (Phase 9), each detected service name (Phase 12), and the discovered
/// hostname and vendor (Phase 13). Matching is done on the display form of
/// each field, so the needle never needs to know about the underlying types.
fn host_matches(host: &Host, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let needle = needle.to_ascii_lowercase();
    host.ip.to_string().to_ascii_lowercase().contains(&needle)
        || host
            .state
            .to_string()
            .to_ascii_lowercase()
            .contains(&needle)
        || host
            .ports
            .iter()
            .any(|probed| probed.port.to_string().contains(&needle))
        || host.ports.iter().any(|probed| {
            probed
                .service
                .as_ref()
                .is_some_and(|service| service.name.to_ascii_lowercase().contains(&needle))
        })
        || host
            .hostname
            .as_ref()
            .is_some_and(|hostname| hostname.to_ascii_lowercase().contains(&needle))
        || host
            .vendor
            .as_ref()
            .is_some_and(|vendor| vendor.to_ascii_lowercase().contains(&needle))
}

/// First visible row index for a scrollable host list.
///
/// Returns `0` when there is no selection, no room to show rows, or the
/// selection is already within the top of the window; otherwise the window is
/// shifted down so the selected row remains the last visible row.
fn window_start(total: usize, selected: Option<usize>, visible: usize) -> usize {
    let Some(selected) = selected else {
        return 0;
    };
    if visible == 0 || selected >= total {
        return 0;
    }
    if selected < visible {
        0
    } else {
        selected - visible + 1
    }
}

/// Render a duration as a human-readable elapsed time: `12.4s` under a minute
/// and `1m 5.3s` at a minute or more.
fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs < 60.0 {
        format!("{secs:.1}s")
    } else {
        let mins = (secs / 60.0) as u64;
        let rest = secs - (mins as f64 * 60.0);
        format!("{mins}m {rest:.1}s")
    }
}

/// Frame title for the host list.
///
/// Plain "Hosts" when no filter is active; otherwise the match count and the
/// total number of discovered hosts, so filtering shows how much it matched.
fn hosts_frame_title(shown: Option<usize>, total: usize) -> String {
    match shown {
        Some(shown) => format!("Hosts  {shown} of {total}"),
        None => "Hosts".to_string(),
    }
}

/// Draw the static key-binding help overlay, centered over the whole screen.
fn draw_help_overlay(frame: &mut Frame) {
    let area = frame.area();
    let width = 26u16.min(area.width);
    let height = 13u16.min(area.height);
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    let overlay_area = Rect {
        x,
        y,
        width,
        height,
    };

    let keys = [
        "  ↑/k    Up",
        "  ↓/j    Down",
        "  /      Filter",
        "  e      Export",
        "  h      History",
        "  n      Network",
        "  ?      Help",
        "  r      Rescan",
        "  s      New Scan",
        "  c      Cancel",
        "  q      Quit",
    ];
    let block = Block::default().borders(Borders::ALL).title("Keys");
    let content = Paragraph::new(keys.iter().map(|key| Line::from(*key)).collect::<Vec<_>>())
        .alignment(Alignment::Center);
    frame.render_widget(content, block.inner(overlay_area));
    frame.render_widget(block, overlay_area);
}

/// The display name of a discovery strategy in the new-scan dialog (Phase 19).
fn discovery_name(discovery: Discovery) -> &'static str {
    match discovery {
        Discovery::Auto => "Auto",
        Discovery::Icmp => "ICMP",
        Discovery::Tcp => "TCP",
    }
}

/// The display name of a port profile in the new-scan dialog (Phase 19).
fn profile_name(profile: PortProfile) -> &'static str {
    match profile {
        PortProfile::Quick => "Quick",
        PortProfile::Common => "Common",
        PortProfile::Full => "Full",
    }
}

/// Draw the new-scan dialog (Phase 19) as a centered bordered panel on top
/// of the current view.
///
/// The dialog lists its three fields — target, discovery strategy, and port
/// profile — one per line, with the focused field's label in bold. An empty
/// target shows a dim placeholder, two hint lines document the dialog keys,
/// and the target parse error raised by `Enter` is shown in red.
fn draw_new_scan_dialog(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let width = 40u16.min(area.width);
    let inner_height = 6u16 + if app.new_scan_error.is_some() { 1 } else { 0 };
    let height = inner_height.saturating_add(2).min(area.height);
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    let dialog_area = Rect {
        x,
        y,
        width,
        height,
    };

    let label = |focused: bool, name: &str| {
        let style = if focused {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        Span::styled(format!("{name:<9}"), style)
    };
    let target_value = if app.new_scan_target.is_empty() {
        Span::styled("IPv4 address or CIDR", Style::default().fg(Color::DarkGray))
    } else {
        Span::raw(app.new_scan_target.clone())
    };

    let mut lines = vec![
        Line::from(vec![
            label(app.new_scan_focus == NewScanField::Target, "Target"),
            target_value,
        ]),
        Line::from(vec![
            label(app.new_scan_focus == NewScanField::Strategy, "Strategy"),
            Span::raw(discovery_name(app.new_scan_discovery)),
        ]),
        Line::from(vec![
            label(app.new_scan_focus == NewScanField::Profile, "Profile"),
            Span::raw(profile_name(app.new_scan_profile)),
        ]),
        Line::raw(""),
        Line::raw(" Tab Field   ←/→ Choose"),
        Line::raw(" Enter Start  Esc Cancel"),
    ];
    if let Some(error) = &app.new_scan_error {
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(Color::Red),
        )));
    }

    let block = Block::default().borders(Borders::ALL).title("New Scan");
    let content = Paragraph::new(lines);
    frame.render_widget(content, block.inner(dialog_area));
    frame.render_widget(block, dialog_area);
}

/// Draw the detail screen for the selected host.
///
/// A "Host" block shows the IP, state, and latency, plus one line for each
/// enrichment field that was actually discovered for the host (hostname,
/// MAC, vendor); a "Ports" block lists every probed port with the state its
/// probe found. Only information that was actually discovered is shown
/// (Phase 8); vendor is derived from the MAC's OUI and labelled as inferred.
fn draw_host_detail(frame: &mut Frame, app: &App, area: Rect) {
    let (host_lines, port_lines) = match app.selected() {
        Some(host) => (
            host_detail_lines(host),
            if host.ports.is_empty() {
                vec!["-".to_owned()]
            } else {
                host.ports
                    .iter()
                    .map(|p| {
                        let mut line = format!(
                            "{:<12}{}",
                            format!("{}/tcp", p.port),
                            p.state.to_string().to_uppercase()
                        );
                        if let Some(service) = &p.service {
                            line.push(' ');
                            line.push_str(&service_label(service));
                        }
                        line
                    })
                    .collect()
            },
        ),
        None => (vec!["No host selected.".to_owned()], vec!["-".to_owned()]),
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(host_lines.len() as u16 + 2),
            Constraint::Min(1),
        ])
        .split(area);

    let host_block = Block::default().borders(Borders::ALL).title("Host");
    let host_content = Paragraph::new(host_lines.into_iter().map(Line::from).collect::<Vec<_>>());
    frame.render_widget(host_content, host_block.inner(chunks[0]));
    frame.render_widget(host_block, chunks[0]);

    let ports_block = Block::default().borders(Borders::ALL).title("Ports");
    let ports_content = Paragraph::new(port_lines.into_iter().map(Line::from).collect::<Vec<_>>());
    frame.render_widget(ports_content, ports_block.inner(chunks[1]));
    frame.render_widget(ports_block, chunks[1]);
}

fn format_latency(latency: Option<Duration>) -> String {
    match latency {
        Some(latency) => format!("{:.1} ms", latency.as_secs_f64() * 1000.0),
        None => "-".to_owned(),
    }
}

/// The display lines for the "Host" block of the detail screen: the basic
/// IP/state/latency lines, plus one line for each enrichment field that was
/// actually discovered for the host (Phase 13). The vendor is derived from
/// the MAC's OUI rather than observed, so it is labelled as inferred.
fn host_detail_lines(host: &Host) -> Vec<String> {
    let mut lines = vec![
        format!("{:<12}{}", "IP", host.ip),
        format!("{:<12}{}", "State", host.state),
        format!("{:<12}{}", "Latency", format_latency(host.latency)),
    ];
    if let Some(hostname) = &host.hostname {
        lines.push(format!("{:<12}{}", "Hostname", hostname));
    }
    if let Some(mac) = &host.mac {
        lines.push(format!("{:<12}{}", "MAC", mac));
    }
    if let Some(vendor) = &host.vendor {
        lines.push(format!("{:<12}{} (inferred)", "Vendor", vendor));
    }
    lines
}

/// The display label for a detected service: its name, with the version
/// appended when known (for example `ssh 9.0`). Only detected information is
/// shown; a port without a detected service is not labelled (Phase 12).
fn service_label(service: &ServiceInfo) -> String {
    match &service.version {
        Some(version) => format!("{} {}", service.name, version),
        None => service.name.clone(),
    }
}

/// Render a host's open ports as a comma-separated list (`22,80,443`), or a
/// dash when none have been found open yet. Only ports whose probe found them
/// open are shown; the structured data is the host's sorted probed-port list.
fn format_open_ports(ports: &[ProbedPort]) -> String {
    let open: Vec<String> = ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .map(|p| p.port.to_string())
        .collect();
    if open.is_empty() {
        "-".to_owned()
    } else {
        open.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{MacAddress, Port};
    use crate::ports::PortConfig;
    use crate::scanner::{DiscoveryConfig, ScanError};
    use std::net::Ipv4Addr;

    fn app_with_target() -> App {
        App {
            target: Some(ScanTarget::parse("127.0.0.1").unwrap()),
            ..Default::default()
        }
    }

    #[test]
    fn quit_key_sets_should_quit_and_cancel() {
        let mut app = App::default();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('q'), &cancel);
        assert!(app.should_quit);
        assert!(cancel.load(Ordering::SeqCst));
    }

    #[test]
    fn cancel_key_sets_flag_but_leaves_active_state() {
        let mut app = App {
            scan: ScanState::Discovering {
                completed: 1,
                total: 4,
            },
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('c'), &cancel);
        assert!(!app.should_quit);
        // Only the flag is raised here; the scanner's `Cancelled` event performs
        // the terminal transition, so the state is still active (Phase 10).
        assert!(cancel.load(Ordering::SeqCst));
        assert_eq!(
            app.scan,
            ScanState::Discovering {
                completed: 1,
                total: 4
            }
        );
    }

    #[test]
    fn cancel_key_ignored_when_not_scanning() {
        let mut app = App::default();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('c'), &cancel);
        assert_eq!(app.scan, ScanState::Idle);
        assert!(!cancel.load(Ordering::SeqCst));
        assert!(!app.should_quit);
    }

    #[test]
    fn other_keys_do_not_quit() {
        let mut app = App::default();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('x'), &cancel);
        app.handle_key(KeyCode::Enter, &cancel);
        assert!(!app.should_quit);
        assert!(!cancel.load(Ordering::SeqCst));
    }

    #[test]
    fn app_holds_optional_target() {
        let app = App::default();
        assert!(app.target.is_none());

        let app = App {
            target: Some(ScanTarget::parse("192.168.1.0/24").unwrap()),
            ..Default::default()
        };
        assert_eq!(
            app.target.as_ref().map(|t| t.to_string()),
            Some("192.168.1.0/24".to_owned())
        );
    }

    #[test]
    fn new_scan_config_uses_defaults_without_template() {
        let target = ScanTarget::parse("10.0.0.5").unwrap();
        let config =
            build_new_scan_config(None, target.clone(), Discovery::Tcp, PortProfile::Common);

        assert_eq!(config.target, target);
        assert_eq!(config.discovery_strategy, Discovery::Tcp);
        assert_eq!(config.ports.ports, PortProfile::Common.ports());
        // Unselected tunables fall back to the defaults.
        assert_eq!(config.discovery, DiscoveryConfig::default());
        assert_eq!(config.ports.timeout, PortConfig::default().timeout);
        assert_eq!(config.ports.concurrency, PortConfig::default().concurrency);
        assert!(config.detect_services);
        assert!(config.enrich);
    }

    #[test]
    fn new_scan_config_carries_template_tunables() {
        let template = ScanConfig {
            target: ScanTarget::parse("192.168.1.10").unwrap(),
            discovery_strategy: Discovery::Icmp,
            discovery: DiscoveryConfig {
                timeout: Duration::from_millis(1234),
                concurrency: 7,
            },
            ports: PortConfig {
                ports: PortProfile::Full.ports(),
                timeout: Duration::from_millis(5678),
                concurrency: 3,
            },
            detect_services: false,
            enrich: false,
        };
        let target = ScanTarget::parse("10.1.0.0/28").unwrap();
        let config = build_new_scan_config(
            Some(&template),
            target.clone(),
            Discovery::Tcp,
            PortProfile::Quick,
        );

        assert_eq!(config.target, target);
        assert_eq!(config.discovery_strategy, Discovery::Tcp);
        assert_eq!(config.ports.ports, PortProfile::Quick.ports());
        // Tunables are inherited from the template.
        assert_eq!(config.discovery, template.discovery);
        assert_eq!(config.ports.timeout, Duration::from_millis(5678));
        assert_eq!(config.ports.concurrency, 3);
        assert!(!config.detect_services);
        assert!(!config.enrich);
    }

    #[test]
    fn started_event_sets_discovering() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Started { total: 4 });
        assert_eq!(
            app.scan,
            ScanState::Discovering {
                completed: 0,
                total: 4
            }
        );
    }

    #[test]
    fn warning_event_stores_the_message() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Warning(
            "ICMP unavailable; falling back to TCP discovery".to_owned(),
        ));
        assert_eq!(
            app.warning.as_deref(),
            Some("ICMP unavailable; falling back to TCP discovery")
        );
        // A warning does not change the scan state or progress.
        assert_eq!(app.scan, ScanState::Idle);
    }

    #[test]
    fn started_event_clears_a_previous_warning() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Warning("stale warning".to_owned()));
        assert!(app.warning.is_some());
        app.apply_event(ScanEvent::Started { total: 4 });
        assert!(app.warning.is_none());
    }

    #[test]
    fn progress_event_updates_counts() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Started { total: 4 });
        app.apply_event(ScanEvent::Progress {
            completed: 2,
            total: 4,
        });
        assert_eq!(
            app.scan,
            ScanState::Discovering {
                completed: 2,
                total: 4
            }
        );
    }

    #[test]
    fn progress_event_ignored_when_not_scanning() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Progress {
            completed: 2,
            total: 4,
        });
        assert_eq!(app.scan, ScanState::Idle);
    }

    #[test]
    fn first_port_discovered_transitions_to_scanning_ports() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Started { total: 1 });
        app.apply_event(ScanEvent::HostDiscovered(Host::up(
            "10.0.0.1".parse::<Ipv4Addr>().unwrap(),
            Duration::from_millis(1),
        )));
        app.apply_event(ScanEvent::PortDiscovered {
            ip: "10.0.0.1".parse().unwrap(),
            port: Port::new(22).unwrap(),
            state: PortState::Open,
        });
        assert_eq!(app.scan, ScanState::ScanningPorts);
    }

    #[test]
    fn port_discovered_keeps_scanning_ports_state() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Started { total: 1 });
        app.apply_event(ScanEvent::HostDiscovered(Host::up(
            "10.0.0.1".parse::<Ipv4Addr>().unwrap(),
            Duration::from_millis(1),
        )));
        let ip = "10.0.0.1".parse::<Ipv4Addr>().unwrap();
        app.apply_event(ScanEvent::PortDiscovered {
            ip,
            port: Port::new(22).unwrap(),
            state: PortState::Open,
        });
        app.apply_event(ScanEvent::PortDiscovered {
            ip,
            port: Port::new(23).unwrap(),
            state: PortState::Closed,
        });
        assert_eq!(app.scan, ScanState::ScanningPorts);
        assert_eq!(app.ports_probed, 2);
    }

    #[test]
    fn progress_event_ignored_during_port_scanning() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Started { total: 1 });
        app.apply_event(ScanEvent::HostDiscovered(Host::up(
            "10.0.0.1".parse::<Ipv4Addr>().unwrap(),
            Duration::from_millis(1),
        )));
        let ip = "10.0.0.1".parse::<Ipv4Addr>().unwrap();
        app.apply_event(ScanEvent::PortDiscovered {
            ip,
            port: Port::new(22).unwrap(),
            state: PortState::Open,
        });
        app.apply_event(ScanEvent::Progress {
            completed: 1,
            total: 1,
        });
        assert_eq!(app.scan, ScanState::ScanningPorts);
    }

    #[test]
    fn rescan_key_sets_flag_when_idle() {
        let mut app = App::default();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('r'), &cancel);
        assert!(app.rescan_requested);
        assert!(!app.should_quit);
        assert!(!cancel.load(Ordering::SeqCst));
    }

    #[test]
    fn rescan_key_ignored_while_scan_active() {
        let mut app = App {
            scan: ScanState::Discovering {
                completed: 0,
                total: 4,
            },
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('r'), &cancel);
        assert!(!app.rescan_requested);
        assert_eq!(
            app.scan,
            ScanState::Discovering {
                completed: 0,
                total: 4
            }
        );
    }

    #[test]
    fn rescan_key_works_after_scan_ends() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Started { total: 1 });
        app.apply_event(ScanEvent::Finished);
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('r'), &cancel);
        assert!(app.rescan_requested);
        assert_eq!(app.scan, ScanState::Completed);
    }

    #[test]
    fn new_scan_key_opens_dialog_prefilled_from_target() {
        let mut app = app_with_target();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        assert!(app.new_scan_mode);
        assert_eq!(app.new_scan_target, "127.0.0.1");
        assert_eq!(app.new_scan_discovery, Discovery::Auto);
        assert_eq!(app.new_scan_profile, PortProfile::Quick);
        assert_eq!(app.new_scan_focus, NewScanField::Target);
        assert!(app.new_scan_error.is_none());
        assert!(!app.should_quit);
        assert!(!cancel.load(Ordering::SeqCst));
    }

    #[test]
    fn new_scan_key_opens_dialog_without_target() {
        let mut app = App::default();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        assert!(app.new_scan_mode);
        assert_eq!(app.new_scan_target, "");
    }

    #[test]
    fn new_scan_key_ignored_while_scan_active() {
        let mut app = App {
            scan: ScanState::Discovering {
                completed: 0,
                total: 4,
            },
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        assert!(!app.new_scan_mode);
    }

    #[test]
    fn new_scan_dialog_char_appends_and_moves_focus_to_target() {
        let mut app = app_with_target();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        app.new_scan_focus = NewScanField::Profile;
        app.handle_key(KeyCode::Char('5'), &cancel);
        assert_eq!(app.new_scan_target, "127.0.0.15");
        assert_eq!(app.new_scan_focus, NewScanField::Target);
    }

    #[test]
    fn new_scan_dialog_backspace_pops_char() {
        let mut app = app_with_target();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        app.new_scan_target = "10.0.0.1".to_string();
        app.handle_key(KeyCode::Backspace, &cancel);
        assert_eq!(app.new_scan_target, "10.0.0.");
    }

    #[test]
    fn new_scan_dialog_tab_cycles_focus() {
        let mut app = App::default();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        assert_eq!(app.new_scan_focus, NewScanField::Target);
        app.handle_key(KeyCode::Tab, &cancel);
        assert_eq!(app.new_scan_focus, NewScanField::Strategy);
        app.handle_key(KeyCode::Tab, &cancel);
        assert_eq!(app.new_scan_focus, NewScanField::Profile);
        app.handle_key(KeyCode::Tab, &cancel);
        assert_eq!(app.new_scan_focus, NewScanField::Target);
    }

    #[test]
    fn new_scan_dialog_right_cycles_discovery_forward() {
        let mut app = App::default();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        app.new_scan_focus = NewScanField::Strategy;
        app.handle_key(KeyCode::Right, &cancel);
        assert_eq!(app.new_scan_discovery, Discovery::Icmp);
        app.handle_key(KeyCode::Right, &cancel);
        assert_eq!(app.new_scan_discovery, Discovery::Tcp);
        app.handle_key(KeyCode::Right, &cancel);
        assert_eq!(app.new_scan_discovery, Discovery::Auto);
    }

    #[test]
    fn new_scan_dialog_left_cycles_discovery_backward() {
        let mut app = App::default();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        app.new_scan_focus = NewScanField::Strategy;
        app.handle_key(KeyCode::Left, &cancel);
        assert_eq!(app.new_scan_discovery, Discovery::Tcp);
    }

    #[test]
    fn new_scan_dialog_arrows_cycle_profile() {
        let mut app = App::default();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        app.new_scan_focus = NewScanField::Profile;
        app.handle_key(KeyCode::Right, &cancel);
        assert_eq!(app.new_scan_profile, PortProfile::Common);
        app.handle_key(KeyCode::Right, &cancel);
        assert_eq!(app.new_scan_profile, PortProfile::Full);
        app.handle_key(KeyCode::Right, &cancel);
        assert_eq!(app.new_scan_profile, PortProfile::Quick);
        app.handle_key(KeyCode::Left, &cancel);
        assert_eq!(app.new_scan_profile, PortProfile::Full);
    }

    #[test]
    fn new_scan_dialog_arrows_ignored_on_target_focus() {
        let mut app = app_with_target();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        app.handle_key(KeyCode::Left, &cancel);
        assert_eq!(app.new_scan_focus, NewScanField::Target);
        assert_eq!(app.new_scan_discovery, Discovery::Auto);
        assert_eq!(app.new_scan_profile, PortProfile::Quick);
    }

    #[test]
    fn new_scan_dialog_enter_valid_target_sets_request() {
        let mut app = app_with_target();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        app.new_scan_target = "10.0.0.1".to_string();
        app.new_scan_discovery = Discovery::Tcp;
        app.new_scan_profile = PortProfile::Full;
        app.handle_key(KeyCode::Enter, &cancel);
        assert!(!app.new_scan_mode);
        let request = app
            .new_scan_requested
            .take()
            .expect("a request should be recorded");
        assert_eq!(request.target, ScanTarget::parse("10.0.0.1").unwrap());
        assert_eq!(request.discovery, Discovery::Tcp);
        assert_eq!(request.profile, PortProfile::Full);
        assert!(!cancel.load(Ordering::SeqCst));
    }

    #[test]
    fn new_scan_dialog_enter_invalid_target_shows_error() {
        let mut app = app_with_target();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        app.new_scan_target = "not-an-ip".to_string();
        app.handle_key(KeyCode::Enter, &cancel);
        assert!(app.new_scan_mode);
        assert!(app.new_scan_error.is_some());
        assert!(app.new_scan_requested.is_none());
    }

    #[test]
    fn new_scan_dialog_typing_and_backspace_clear_error() {
        let mut app = app_with_target();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        app.new_scan_target = "nope".to_string();
        app.handle_key(KeyCode::Enter, &cancel);
        assert!(app.new_scan_error.is_some());
        app.handle_key(KeyCode::Char('x'), &cancel);
        assert!(app.new_scan_error.is_none());
        app.handle_key(KeyCode::Enter, &cancel);
        assert!(app.new_scan_error.is_some());
        app.handle_key(KeyCode::Backspace, &cancel);
        assert!(app.new_scan_error.is_none());
    }

    #[test]
    fn new_scan_dialog_esc_cancels_and_clears_error() {
        let mut app = app_with_target();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        app.new_scan_error = Some("boom".to_string());
        app.handle_key(KeyCode::Esc, &cancel);
        assert!(!app.new_scan_mode);
        assert!(app.new_scan_error.is_none());
        assert!(app.new_scan_requested.is_none());
    }

    #[test]
    fn new_scan_dialog_consumes_overview_keys() {
        let mut app = app_with_target();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('s'), &cancel);
        app.handle_key(KeyCode::Char('q'), &cancel);
        assert!(!app.should_quit);
        assert!(!cancel.load(Ordering::SeqCst));
        assert_eq!(app.new_scan_target, "127.0.0.1q");
    }

    /// Render the app into an in-memory buffer and return its text content.
    fn render_app_text(app: &App, width: u16, height: u16) -> String {
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test backend");
        let frame = terminal
            .draw(|frame| draw(frame, app))
            .expect("draw into test backend");
        frame
            .buffer
            .content()
            .iter()
            .map(|cell| cell.symbol().to_string())
            .collect()
    }

    #[test]
    fn new_scan_dialog_renders_fields() {
        let mut app = app_with_target();
        app.open_new_scan();
        let text = render_app_text(&app, 80, 24);
        assert!(text.contains("New Scan"));
        assert!(text.contains("Target"));
        assert!(text.contains("127.0.0.1"));
        assert!(text.contains("Strategy"));
        assert!(text.contains("Auto"));
        assert!(text.contains("Profile"));
        assert!(text.contains("Quick"));
        assert!(text.contains("Enter Start"));
        assert!(text.contains("Esc Cancel"));
    }

    #[test]
    fn new_scan_dialog_shows_placeholder_for_empty_target() {
        let mut app = App::default();
        app.open_new_scan();
        let text = render_app_text(&app, 80, 24);
        assert!(text.contains("IPv4 address or CIDR"));
    }

    #[test]
    fn new_scan_dialog_renders_error_line() {
        let mut app = app_with_target();
        app.open_new_scan();
        app.new_scan_error = Some("not a target".to_string());
        let text = render_app_text(&app, 80, 24);
        assert!(text.contains("not a target"));
    }

    #[test]
    fn export_key_is_noop_without_target() {
        let mut app = App::default();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('e'), &cancel);
        assert!(app.export_status.is_none());
        assert!(!cancel.load(Ordering::SeqCst));
    }

    #[test]
    fn export_key_types_into_filter_input_while_filtering() {
        let mut app = App {
            target: Some(ScanTarget::parse("127.0.0.1").unwrap()),
            ..Default::default()
        };
        app.filter_mode = true;
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('e'), &cancel);
        assert!(app.export_status.is_none());
        assert_eq!(app.filter_input, "e");
    }

    #[test]
    fn host_discovered_appends_hosts() {
        let mut app = App::default();
        app.apply_event(ScanEvent::HostDiscovered(Host::up(
            "10.0.0.1".parse::<Ipv4Addr>().unwrap(),
            Duration::from_millis(3),
        )));
        app.apply_event(ScanEvent::HostDiscovered(Host::down(
            "10.0.0.2".parse().unwrap(),
        )));
        assert_eq!(app.hosts.len(), 2);
        assert_eq!(app.up_count(), 1);
        assert_eq!(
            app.hosts[0],
            Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(3))
        );
    }

    #[test]
    fn default_app_has_no_selection_or_filter() {
        let app = App::default();
        assert!(app.selected_host.is_none());
        assert!(app.filter.is_none());
        assert!(app.filter_input.is_empty());
        assert!(!app.filter_mode);
        assert!(app.selected().is_none());
    }

    #[test]
    fn selected_returns_host_at_selected_index() {
        let mut app = App::default();
        app.apply_event(ScanEvent::HostDiscovered(Host::up(
            "10.0.0.1".parse().unwrap(),
            Duration::from_millis(1),
        )));
        app.apply_event(ScanEvent::HostDiscovered(Host::down(
            "10.0.0.2".parse().unwrap(),
        )));
        app.selected_host = Some(1);
        let selected = app.selected().expect("index 1 is in range");
        assert_eq!(selected, &app.hosts[1]);
    }

    #[test]
    fn selected_returns_none_when_index_out_of_range() {
        let mut app = App::default();
        app.apply_event(ScanEvent::HostDiscovered(Host::up(
            "10.0.0.1".parse().unwrap(),
            Duration::from_millis(1),
        )));
        // One host exists, so index 1 is out of range.
        app.selected_host = Some(1);
        assert!(app.selected().is_none());
    }

    #[test]
    fn selected_returns_none_with_empty_host_list() {
        let app = App {
            selected_host: Some(0),
            ..Default::default()
        };
        assert!(app.selected().is_none());
    }

    #[test]
    fn filter_is_stored_and_can_be_cleared() {
        let mut app = App {
            filter: Some("10.0.0.".to_owned()),
            ..Default::default()
        };
        assert_eq!(app.filter.as_deref(), Some("10.0.0."));
        app.filter = None;
        assert!(app.filter.is_none());
    }

    #[test]
    fn host_matches_ip_substring() {
        let host = Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(1));
        assert!(host_matches(&host, "10.0.0"));
        assert!(host_matches(&host, "0.0.1"));
        assert!(!host_matches(&host, "10.0.1"));
        assert!(!host_matches(&host, "192.168"));
    }

    #[test]
    fn host_matches_state_case_insensitively() {
        let up = Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(1));
        let down = Host::down("10.0.0.2".parse().unwrap());
        assert!(host_matches(&up, "up"));
        assert!(host_matches(&up, "UP"));
        assert!(host_matches(&up, "Up"));
        assert!(!host_matches(&up, "down"));
        assert!(host_matches(&down, "down"));
        assert!(host_matches(&down, "DOWN"));
    }

    #[test]
    fn host_matches_probed_port_numbers() {
        let mut host = Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(1));
        host.add_probed_port(Port::new(22).unwrap(), PortState::Open);
        host.add_probed_port(Port::new(443).unwrap(), PortState::Closed);
        assert!(host_matches(&host, "22"));
        assert!(host_matches(&host, "443"));
        // No service has been detected on either port, so a service needle
        // does not match; an unprobed port number never matches either.
        assert!(!host_matches(&host, "ssh"));
        assert!(!host_matches(&host, "8080"));
    }

    #[test]
    fn host_matches_detected_service_names() {
        let mut host = Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(1));
        host.add_probed_port(Port::new(22).unwrap(), PortState::Open);
        host.ports
            .iter_mut()
            .find(|p| p.port == Port::new(22).unwrap())
            .unwrap()
            .service = Some(ServiceInfo::new("ssh"));
        // Case-insensitive substring match against the detected service name.
        assert!(host_matches(&host, "ssh"));
        assert!(host_matches(&host, "SSH"));
        assert!(host_matches(&host, "sh"));
        assert!(!host_matches(&host, "http"));
        assert!(!host_matches(&host, "telnet"));
    }

    #[test]
    fn host_matches_hostname_and_vendor_case_insensitively() {
        let mut host = Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(1));
        host.hostname = Some("Router".to_owned());
        host.mac = Some(MacAddress::new([0x3C, 0x52, 0x82, 0x11, 0x22, 0x33]));
        host.vendor = Some("Hewlett-Packard".to_owned());

        // Hostname: case-insensitive substring match.
        assert!(host_matches(&host, "router"));
        assert!(host_matches(&host, "ROUTER"));
        assert!(host_matches(&host, "rout"));
        // Vendor: case-insensitive substring match.
        assert!(host_matches(&host, "hewlett"));
        assert!(host_matches(&host, "PACKARD"));
        // Unrelated needles do not match any field.
        assert!(!host_matches(&host, "server"));
        assert!(!host_matches(&host, "cisco"));
        // The MAC address is deliberately not a filter target.
        assert!(!host_matches(&host, "3c:52:82"));
    }

    #[test]
    fn host_detail_lines_shows_base_lines_only_without_enrichment() {
        let host = Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(3));
        let lines = host_detail_lines(&host);
        // Exactly the three base lines; none of the enrichment labels appear.
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("IP"));
        assert!(lines[1].starts_with("State"));
        assert!(lines[2].starts_with("Latency"));
        assert!(!lines.iter().any(|line| line.starts_with("Hostname")));
        assert!(!lines.iter().any(|line| line.starts_with("MAC")));
        assert!(!lines.iter().any(|line| line.starts_with("Vendor")));
    }

    #[test]
    fn host_detail_lines_appends_each_discovered_enrichment_field() {
        let mut host = Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(3));
        host.hostname = Some("router".to_owned());
        host.mac = Some(MacAddress::new([0x3C, 0x52, 0x82, 0x11, 0x22, 0x33]));
        host.vendor = Some("Hewlett-Packard".to_owned());

        let lines = host_detail_lines(&host);
        // Three base lines plus one line per discovered field.
        assert_eq!(lines.len(), 6);
        assert!(lines.iter().any(|line| line.contains("router")));
        assert!(lines.iter().any(|line| line.contains("3C:52:82:11:22:33")));
        // The vendor is OUI-derived, so it is explicitly labelled as inferred.
        let vendor_line = lines
            .iter()
            .find(|line| line.starts_with("Vendor"))
            .expect("a vendor line is present");
        assert!(vendor_line.contains("Hewlett-Packard"));
        assert!(vendor_line.ends_with("(inferred)"));
    }

    #[test]
    fn host_detail_lines_includes_only_present_enrichment_fields() {
        let mut host = Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(3));
        // Only a hostname was discovered; MAC and vendor stay absent.
        host.hostname = Some("router".to_owned());

        let lines = host_detail_lines(&host);
        assert_eq!(lines.len(), 4);
        assert!(lines.iter().any(|line| line.contains("router")));
        assert!(!lines.iter().any(|line| line.starts_with("MAC")));
        assert!(!lines.iter().any(|line| line.starts_with("Vendor")));
    }

    #[test]
    fn service_label_omits_version_when_absent() {
        assert_eq!(service_label(&ServiceInfo::new("http")), "http");
    }

    #[test]
    fn service_label_includes_version_when_present() {
        let mut service = ServiceInfo::new("ssh");
        service.version = Some("OpenSSH_9.6p1".to_string());
        assert_eq!(service_label(&service), "ssh OpenSSH_9.6p1");
    }

    #[test]
    fn service_discovered_attaches_to_matching_host_and_port() {
        let mut app = App::default();
        let ip = "10.0.0.1".parse::<Ipv4Addr>().unwrap();
        // Mirror the real event order: Started moves Idle -> Discovering,
        // which is the state the first PortDiscovered transitions out of.
        app.apply_event(ScanEvent::Started { total: 1 });
        app.apply_event(ScanEvent::HostDiscovered(Host::up(
            ip,
            Duration::from_millis(1),
        )));
        app.apply_event(ScanEvent::PortDiscovered {
            ip,
            port: Port::new(22).unwrap(),
            state: PortState::Open,
        });
        app.apply_event(ScanEvent::ServiceDiscovered {
            ip,
            port: Port::new(22).unwrap(),
            service: ServiceInfo::new("ssh"),
        });

        let host = &app.hosts[0];
        let probed = host
            .ports
            .iter()
            .find(|p| p.port == Port::new(22).unwrap())
            .unwrap();
        assert_eq!(probed.service, Some(ServiceInfo::new("ssh")));
        // The service event attaches data only; it does not change the scan
        // state or the probed-port count (the port event already did).
        assert_eq!(app.scan, ScanState::ScanningPorts);
        assert_eq!(app.ports_probed, 1);
    }

    #[test]
    fn service_discovered_for_unknown_host_or_port_is_ignored() {
        let mut app = App::default();
        // Unknown host: nothing to attach to, and no host is created.
        app.apply_event(ScanEvent::ServiceDiscovered {
            ip: "10.0.0.9".parse().unwrap(),
            port: Port::new(22).unwrap(),
            service: ServiceInfo::new("ssh"),
        });
        assert!(app.hosts.is_empty());

        // Known host, unprobed port: silently ignored.
        let ip = "10.0.0.1".parse::<Ipv4Addr>().unwrap();
        app.apply_event(ScanEvent::HostDiscovered(Host::up(
            ip,
            Duration::from_millis(1),
        )));
        app.apply_event(ScanEvent::ServiceDiscovered {
            ip,
            port: Port::new(8080).unwrap(),
            service: ServiceInfo::new("http"),
        });
        assert!(app.hosts[0].ports.is_empty());
        assert_eq!(app.ports_probed, 0);
    }

    #[test]
    fn host_matches_empty_needle_matches_everything() {
        let up = Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(1));
        let down = Host::down("10.0.0.2".parse().unwrap());
        assert!(host_matches(&up, ""));
        assert!(host_matches(&down, ""));
    }

    #[test]
    fn effective_filter_none_when_no_filter_or_input() {
        let app = App::default();
        assert_eq!(app.effective_filter(), None);
    }

    #[test]
    fn effective_filter_falls_back_to_committed_filter() {
        let app = App {
            filter: Some("10.0.0.".to_owned()),
            ..Default::default()
        };
        assert_eq!(app.effective_filter(), Some("10.0.0."));
    }

    #[test]
    fn effective_filter_prefers_live_input_over_committed_filter() {
        let app = App {
            filter: Some("10.0.0.".to_owned()),
            filter_input: "192".to_owned(),
            filter_mode: true,
            ..Default::default()
        };
        assert_eq!(app.effective_filter(), Some("192"));
    }

    #[test]
    fn visible_indices_all_hosts_without_filter() {
        let app = app_with_hosts(3);
        assert_eq!(app.visible_indices(), vec![0, 1, 2]);
    }

    #[test]
    fn visible_indices_returns_matching_subset() {
        let mut app = app_with_hosts(3);
        app.filter_input = "10.0.0.1".to_owned();
        assert_eq!(app.visible_indices(), vec![1]);
    }

    #[test]
    fn visible_indices_empty_when_nothing_matches() {
        let mut app = app_with_hosts(3);
        app.filter_input = "192.168".to_owned();
        assert!(app.visible_indices().is_empty());
    }

    /// Three hosts where the filter `"1.1"` matches only the first and third.
    fn app_with_three_hosts() -> App {
        App {
            hosts: vec![
                Host::up("192.168.1.1".parse().unwrap(), Duration::from_millis(1)),
                Host::up("192.168.1.2".parse().unwrap(), Duration::from_millis(2)),
                Host::up("192.168.1.11".parse().unwrap(), Duration::from_millis(3)),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn move_selection_skips_hidden_hosts() {
        let mut app = app_with_three_hosts();
        app.filter = Some("1.1".to_owned());
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('j'), &cancel);
        assert_eq!(app.selected_host, Some(0));
        app.handle_key(KeyCode::Char('j'), &cancel);
        // Host 1 is hidden by the filter, so the next visible host is 2.
        assert_eq!(app.selected_host, Some(2));
        app.handle_key(KeyCode::Char('j'), &cancel);
        // Clamped at the last visible host.
        assert_eq!(app.selected_host, Some(2));
        app.handle_key(KeyCode::Char('k'), &cancel);
        assert_eq!(app.selected_host, Some(0));
    }

    #[test]
    fn move_selection_treats_hidden_selection_as_no_selection() {
        let mut app = app_with_three_hosts();
        app.filter = Some("1.1".to_owned());
        let cancel = AtomicBool::new(false);
        // Host 1 is hidden, so the selection is invalid against the filter.
        app.selected_host = Some(1);
        app.handle_key(KeyCode::Char('j'), &cancel);
        assert_eq!(app.selected_host, Some(0));

        app.selected_host = Some(1);
        app.handle_key(KeyCode::Char('k'), &cancel);
        assert_eq!(app.selected_host, Some(2));
    }

    #[test]
    fn move_selection_clears_selection_when_nothing_visible() {
        let mut app = app_with_three_hosts();
        app.filter = Some("no-such-host".to_owned());
        let cancel = AtomicBool::new(false);
        app.selected_host = Some(0);
        app.handle_key(KeyCode::Char('j'), &cancel);
        assert_eq!(app.selected_host, None);
    }

    #[test]
    fn slash_starts_filter_input_mode_with_empty_buffer() {
        let mut app = app_with_three_hosts();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('/'), &cancel);
        assert!(app.filter_mode);
        assert!(app.filter_input.is_empty());
        assert!(app.filter.is_none());
    }

    #[test]
    fn typed_filter_text_filters_live_and_clears_hidden_selection() {
        let mut app = app_with_three_hosts();
        app.selected_host = Some(1);
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('/'), &cancel);
        app.handle_key(KeyCode::Char('1'), &cancel);
        app.handle_key(KeyCode::Char('1'), &cancel);
        // "192.168.1.11" is the only host containing "11".
        assert_eq!(app.filter_input, "11");
        assert_eq!(app.visible_indices(), vec![2]);
        // The previously selected host is now hidden.
        assert_eq!(app.selected_host, None);
    }

    #[test]
    fn enter_commits_filter_and_leaves_input_mode() {
        let mut app = app_with_hosts(3);
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('/'), &cancel);
        app.handle_key(KeyCode::Char('1'), &cancel);
        app.handle_key(KeyCode::Char('0'), &cancel);
        app.handle_key(KeyCode::Enter, &cancel);
        assert_eq!(app.filter.as_deref(), Some("10"));
        assert!(app.filter_input.is_empty());
        assert!(!app.filter_mode);
    }

    #[test]
    fn enter_with_empty_buffer_clears_committed_filter() {
        let mut app = app_with_hosts(3);
        app.filter = Some("10".to_owned());
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('/'), &cancel);
        app.handle_key(KeyCode::Enter, &cancel);
        assert!(app.filter.is_none());
        assert!(app.filter_input.is_empty());
        assert!(!app.filter_mode);
    }

    #[test]
    fn esc_in_input_mode_discards_buffer_and_keeps_committed_filter() {
        let mut app = app_with_hosts(3);
        app.filter = Some("10".to_owned());
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('/'), &cancel);
        app.handle_key(KeyCode::Char('a'), &cancel);
        app.handle_key(KeyCode::Char('b'), &cancel);
        app.handle_key(KeyCode::Esc, &cancel);
        assert_eq!(app.filter.as_deref(), Some("10"));
        assert!(app.filter_input.is_empty());
        assert!(!app.filter_mode);
    }

    #[test]
    fn esc_on_overview_clears_committed_filter() {
        let mut app = app_with_hosts(3);
        app.filter = Some("10".to_owned());
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Esc, &cancel);
        assert!(app.filter.is_none());
        assert!(!app.filter_mode);
    }

    #[test]
    fn esc_on_overview_without_filter_is_a_noop() {
        let mut app = app_with_hosts(3);
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Esc, &cancel);
        assert!(app.filter.is_none());
        assert!(!app.filter_mode);
    }

    #[test]
    fn backspace_edits_filter_buffer() {
        let mut app = app_with_hosts(3);
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('/'), &cancel);
        app.handle_key(KeyCode::Char('a'), &cancel);
        app.handle_key(KeyCode::Char('b'), &cancel);
        app.handle_key(KeyCode::Backspace, &cancel);
        assert_eq!(app.filter_input, "a");
        app.handle_key(KeyCode::Backspace, &cancel);
        assert!(app.filter_input.is_empty());
        // A further backspace past the start is a no-op.
        app.handle_key(KeyCode::Backspace, &cancel);
        assert!(app.filter_input.is_empty());
    }

    #[test]
    fn overview_keys_are_consumed_as_filter_input() {
        let mut app = app_with_hosts(3);
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('/'), &cancel);
        for key in [
            KeyCode::Char('q'),
            KeyCode::Char('c'),
            KeyCode::Char('?'),
            KeyCode::Char('j'),
            KeyCode::Up,
        ] {
            app.handle_key(key, &cancel);
        }
        assert_eq!(app.filter_input, "qc?j");
        assert!(app.filter_mode);
        // None of the overview handlers ran.
        assert!(!app.should_quit);
        assert!(!cancel.load(Ordering::SeqCst));
        assert!(!app.show_help);
        assert_eq!(app.selected_host, None);
    }

    #[test]
    fn port_discovered_open_records_port_on_matching_host() {
        let mut app = App::default();
        let ip = "10.0.0.1".parse::<Ipv4Addr>().unwrap();
        app.apply_event(ScanEvent::HostDiscovered(Host::up(
            ip,
            Duration::from_millis(3),
        )));
        for (port, state) in [
            (Port::new(443).unwrap(), PortState::Open),
            (Port::new(22).unwrap(), PortState::Open),
            (Port::new(80).unwrap(), PortState::Open),
        ] {
            app.apply_event(ScanEvent::PortDiscovered { ip, port, state });
        }
        let ports: Vec<u16> = app.hosts[0].ports.iter().map(|p| p.port.as_u16()).collect();
        // Recorded in arrival order, kept sorted by `add_probed_port`.
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn port_discovered_closed_is_recorded_with_state() {
        // A closed result is a real discovery, so it is recorded alongside the
        // open ones (Phase 8: the detail screen shows probed ports with state).
        let mut app = App::default();
        let ip = "10.0.0.1".parse::<Ipv4Addr>().unwrap();
        app.apply_event(ScanEvent::HostDiscovered(Host::up(
            ip,
            Duration::from_millis(3),
        )));
        app.apply_event(ScanEvent::PortDiscovered {
            ip,
            port: Port::new(23).unwrap(),
            state: PortState::Closed,
        });
        assert_eq!(
            app.hosts[0].ports,
            vec![ProbedPort::new(Port::new(23).unwrap(), PortState::Closed)]
        );
    }

    #[test]
    fn port_discovered_for_unknown_host_is_ignored() {
        let mut app = App::default();
        app.apply_event(ScanEvent::PortDiscovered {
            ip: "10.9.9.9".parse().unwrap(),
            port: Port::new(80).unwrap(),
            state: PortState::Open,
        });
        assert!(app.hosts.is_empty());
    }

    #[test]
    fn ports_total_is_up_hosts_times_ports_per_host() {
        let app = App {
            ports_per_host: 3,
            hosts: vec![
                Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(1)),
                Host::down("10.0.0.2".parse().unwrap()),
                Host::up("10.0.0.3".parse().unwrap(), Duration::from_millis(2)),
            ],
            ..Default::default()
        };
        // 2 up hosts × 3 ports each.
        assert_eq!(app.ports_total(), 6);
    }

    #[test]
    fn ports_total_is_zero_with_no_up_hosts() {
        let app = App {
            ports_per_host: 5,
            hosts: vec![Host::down("10.0.0.2".parse().unwrap())],
            ..Default::default()
        };
        assert_eq!(app.ports_total(), 0);
    }

    #[test]
    fn port_progress_hidden_before_any_port_probed() {
        let app = App {
            ports_per_host: 3,
            hosts: vec![Host::up(
                "10.0.0.1".parse().unwrap(),
                Duration::from_millis(1),
            )],
            ..Default::default()
        };
        assert_eq!(app.port_progress(), None);
    }

    #[test]
    fn port_progress_counts_open_and_closed_ports() {
        let ip = "10.0.0.1".parse::<Ipv4Addr>().unwrap();
        let mut app = App {
            ports_per_host: 4,
            hosts: vec![Host::up(ip, Duration::from_millis(1))],
            ..Default::default()
        };
        // 2 open + 1 closed = 3 probed out of 4.
        app.apply_event(ScanEvent::PortDiscovered {
            ip,
            port: Port::new(22).unwrap(),
            state: PortState::Open,
        });
        app.apply_event(ScanEvent::PortDiscovered {
            ip,
            port: Port::new(80).unwrap(),
            state: PortState::Open,
        });
        app.apply_event(ScanEvent::PortDiscovered {
            ip,
            port: Port::new(23).unwrap(),
            state: PortState::Closed,
        });
        assert_eq!(app.port_progress(), Some("Ports: 3/4".to_owned()));
    }

    #[test]
    fn port_progress_hidden_when_total_is_zero() {
        // No up hosts, so the total is 0; the display stays hidden even if a
        // count were somehow present.
        let app = App {
            ports_per_host: 4,
            ports_probed: 5,
            ..Default::default()
        };
        assert_eq!(app.port_progress(), None);
    }

    #[test]
    fn format_open_ports_joins_and_shows_dash_when_empty() {
        assert_eq!(format_open_ports(&[]), "-");
        let ports = vec![
            ProbedPort::new(Port::new(22).unwrap(), PortState::Open),
            ProbedPort::new(Port::new(80).unwrap(), PortState::Open),
            ProbedPort::new(Port::new(443).unwrap(), PortState::Open),
        ];
        assert_eq!(format_open_ports(&ports), "22,80,443");
    }

    #[test]
    fn format_open_ports_excludes_closed_ports() {
        // Only ports probed open appear in the host-table column; closed
        // results are still recorded on the host and shown on the detail
        // screen instead.
        let ports = vec![
            ProbedPort::new(Port::new(22).unwrap(), PortState::Open),
            ProbedPort::new(Port::new(23).unwrap(), PortState::Closed),
            ProbedPort::new(Port::new(443).unwrap(), PortState::Open),
        ];
        assert_eq!(format_open_ports(&ports), "22,443");

        // All closed means no open ports at all.
        let closed_only = vec![
            ProbedPort::new(Port::new(23).unwrap(), PortState::Closed),
            ProbedPort::new(Port::new(80).unwrap(), PortState::Closed),
        ];
        assert_eq!(format_open_ports(&closed_only), "-");
    }

    #[test]
    fn finished_event_sets_completed() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Finished);
        assert_eq!(app.scan, ScanState::Completed);
    }

    #[test]
    fn cancelled_event_sets_cancelled() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Cancelled);
        assert_eq!(app.scan, ScanState::Cancelled);
    }

    #[test]
    fn error_event_sets_error_state_and_message() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Error(ScanError::Socket("boom".to_owned())));
        assert_eq!(app.scan, ScanState::Error);
        assert_eq!(app.scan_error.as_deref(), Some("socket error: boom"));
    }

    #[test]
    fn full_scan_sequence_reaches_completed() {
        let mut app = app_with_target();
        app.apply_event(ScanEvent::Started { total: 1 });
        app.apply_event(ScanEvent::HostDiscovered(Host::up(
            "127.0.0.1".parse().unwrap(),
            Duration::from_millis(1),
        )));
        app.apply_event(ScanEvent::Progress {
            completed: 1,
            total: 1,
        });
        app.apply_event(ScanEvent::Finished);
        assert_eq!(app.scan, ScanState::Completed);
        assert_eq!(app.hosts.len(), 1);
        assert_eq!(app.up_count(), 1);
        assert_eq!(app.scan.label(), "COMPLETED");
    }

    #[test]
    fn active_states_have_labels() {
        assert_eq!(ScanState::Starting.label(), "STARTING");
        assert_eq!(
            ScanState::Discovering {
                completed: 2,
                total: 4
            }
            .label(),
            "DISCOVERING"
        );
        assert_eq!(ScanState::ScanningPorts.label(), "SCANNING PORTS");
    }

    #[test]
    fn idle_label_is_empty() {
        assert_eq!(ScanState::Idle.label(), "");
    }

    #[test]
    fn terminal_states_have_labels() {
        assert_eq!(ScanState::Completed.label(), "COMPLETED");
        assert_eq!(ScanState::Cancelled.label(), "CANCELLED");
        assert_eq!(ScanState::Error.label(), "ERROR");
    }

    #[test]
    fn up_count_counts_only_up_hosts() {
        let app = App {
            hosts: vec![
                Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(1)),
                Host::down("10.0.0.2".parse().unwrap()),
                Host::up("10.0.0.3".parse().unwrap(), Duration::from_millis(2)),
            ],
            ..Default::default()
        };
        assert_eq!(app.up_count(), 2);
    }

    #[test]
    fn down_count_counts_only_down_hosts() {
        let app = App {
            hosts: vec![
                Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(1)),
                Host::up("10.0.0.2".parse().unwrap(), Duration::from_millis(2)),
                Host::down("10.0.0.3".parse().unwrap()),
            ],
            ..Default::default()
        };
        assert_eq!(app.down_count(), 1);
        assert_eq!(App::default().down_count(), 0);
    }

    fn app_with_hosts(count: usize) -> App {
        let hosts = (0..count)
            .map(|i| {
                Host::up(
                    Ipv4Addr::new(10, 0, 0, i as u8),
                    Duration::from_millis(i as u64 + 1),
                )
            })
            .collect();
        App {
            hosts,
            ..Default::default()
        }
    }

    #[test]
    fn move_selection_noop_with_empty_host_list() {
        let mut app = App::default();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('j'), &cancel);
        app.handle_key(KeyCode::Char('k'), &cancel);
        assert_eq!(app.selected_host, None);
    }

    #[test]
    fn move_selection_down_selects_first_when_none_selected() {
        let mut app = app_with_hosts(3);
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('j'), &cancel);
        assert_eq!(app.selected_host, Some(0));
    }

    #[test]
    fn move_selection_up_selects_last_when_none_selected() {
        let mut app = app_with_hosts(3);
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('k'), &cancel);
        assert_eq!(app.selected_host, Some(2));
    }

    #[test]
    fn move_selection_steps_down_and_clamps_at_end() {
        let mut app = app_with_hosts(3);
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Down, &cancel);
        assert_eq!(app.selected_host, Some(0));
        app.handle_key(KeyCode::Down, &cancel);
        assert_eq!(app.selected_host, Some(1));
        app.handle_key(KeyCode::Down, &cancel);
        assert_eq!(app.selected_host, Some(2));
        // Clamped at the last host.
        app.handle_key(KeyCode::Down, &cancel);
        assert_eq!(app.selected_host, Some(2));
    }

    #[test]
    fn move_selection_steps_up_and_clamps_at_start() {
        let mut app = app_with_hosts(3);
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Up, &cancel);
        assert_eq!(app.selected_host, Some(2));
        app.handle_key(KeyCode::Up, &cancel);
        assert_eq!(app.selected_host, Some(1));
        app.handle_key(KeyCode::Up, &cancel);
        assert_eq!(app.selected_host, Some(0));
        // Clamped at the first host.
        app.handle_key(KeyCode::Up, &cancel);
        assert_eq!(app.selected_host, Some(0));
    }

    #[test]
    fn move_selection_treats_stale_index_as_no_selection() {
        let cancel = AtomicBool::new(false);
        // Two hosts, but the selection points past the end, so it is treated
        // as no selection: down anchors on the first visible host...
        let mut app = app_with_hosts(2);
        app.selected_host = Some(9);
        app.handle_key(KeyCode::Char('j'), &cancel);
        assert_eq!(app.selected_host, Some(0));

        // ...and up anchors on the last.
        let mut app = app_with_hosts(2);
        app.selected_host = Some(9);
        app.handle_key(KeyCode::Char('k'), &cancel);
        assert_eq!(app.selected_host, Some(1));
    }

    /// Hosts spanning two /24 subnets, deliberately not in IP order.
    fn app_with_multi_subnet_hosts() -> App {
        App {
            hosts: vec![
                Host::up("192.168.2.5".parse().unwrap(), Duration::from_millis(1)),
                Host::up("10.0.0.9".parse().unwrap(), Duration::from_millis(2)),
                Host::up("192.168.2.3".parse().unwrap(), Duration::from_millis(3)),
                Host::up("10.0.0.2".parse().unwrap(), Duration::from_millis(4)),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn network_order_sorts_groups_by_network_and_hosts_by_ip() {
        let app = app_with_multi_subnet_hosts();
        // Groups sorted by network address (10.0.0.0 before 192.168.2.0);
        // hosts sorted by IP within each group.
        assert_eq!(app.network_order(), vec![3, 1, 2, 0]);
    }

    #[test]
    fn network_order_empty_without_hosts() {
        assert!(App::default().network_order().is_empty());
    }

    #[test]
    fn n_key_opens_network_view_from_overview() {
        let mut app = app_with_multi_subnet_hosts();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('n'), &cancel);
        assert_eq!(app.view, View::Network);
    }

    #[test]
    fn network_view_navigation_steps_through_grouped_order() {
        let mut app = app_with_multi_subnet_hosts();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('n'), &cancel);
        app.handle_key(KeyCode::Char('j'), &cancel);
        assert_eq!(app.selected_host, Some(3)); // 10.0.0.2
        app.handle_key(KeyCode::Char('j'), &cancel);
        assert_eq!(app.selected_host, Some(1)); // 10.0.0.9
        app.handle_key(KeyCode::Char('j'), &cancel);
        assert_eq!(app.selected_host, Some(2)); // 192.168.2.3 (next group)
        app.handle_key(KeyCode::Char('j'), &cancel);
        assert_eq!(app.selected_host, Some(0)); // 192.168.2.5
        app.handle_key(KeyCode::Char('j'), &cancel);
        // Clamped at the end of the grouped order.
        assert_eq!(app.selected_host, Some(0));
        app.handle_key(KeyCode::Char('k'), &cancel);
        assert_eq!(app.selected_host, Some(2));
    }

    #[test]
    fn network_view_enter_opens_detail_and_esc_returns_to_overview() {
        let mut app = app_with_multi_subnet_hosts();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('n'), &cancel);
        app.handle_key(KeyCode::Char('j'), &cancel);
        assert_eq!(app.selected_host, Some(3));
        app.handle_key(KeyCode::Enter, &cancel);
        assert!(app.show_detail);
        // Esc closes the detail and stays in the network view...
        app.handle_key(KeyCode::Esc, &cancel);
        assert!(!app.show_detail);
        assert_eq!(app.view, View::Network);
        // ...and the next Esc returns to the overview.
        app.handle_key(KeyCode::Esc, &cancel);
        assert_eq!(app.view, View::Overview);
    }

    #[test]
    fn help_key_opens_overlay() {
        let mut app = App::default();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('?'), &cancel);
        assert!(app.show_help);
    }

    #[test]
    fn help_key_and_esc_close_overlay() {
        let cancel = AtomicBool::new(false);
        let mut app = App {
            show_help: true,
            ..Default::default()
        };
        app.handle_key(KeyCode::Char('?'), &cancel);
        assert!(!app.show_help);

        let mut app = App {
            show_help: true,
            ..Default::default()
        };
        app.handle_key(KeyCode::Esc, &cancel);
        assert!(!app.show_help);
    }

    #[test]
    fn navigation_and_cancel_are_ignored_while_help_is_open() {
        let mut app = App {
            show_help: true,
            scan: ScanState::Discovering {
                completed: 1,
                total: 4,
            },
            ..Default::default()
        };
        app.apply_event(ScanEvent::HostDiscovered(Host::up(
            "10.0.0.1".parse().unwrap(),
            Duration::from_millis(1),
        )));
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('j'), &cancel);
        app.handle_key(KeyCode::Char('k'), &cancel);
        app.handle_key(KeyCode::Char('c'), &cancel);
        assert!(app.show_help);
        assert_eq!(app.selected_host, None);
        assert!(matches!(app.scan, ScanState::Discovering { .. }));
        assert!(!cancel.load(Ordering::SeqCst));
    }

    #[test]
    fn quit_works_while_help_is_open() {
        let mut app = App {
            show_help: true,
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('q'), &cancel);
        assert!(app.should_quit);
        assert!(cancel.load(Ordering::SeqCst));
    }

    #[test]
    fn enter_opens_detail_when_host_selected() {
        let mut app = app_with_hosts(3);
        app.selected_host = Some(1);
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Enter, &cancel);
        assert!(app.show_detail);
    }

    #[test]
    fn enter_does_not_open_detail_without_selection() {
        let mut app = app_with_hosts(3);
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Enter, &cancel);
        assert!(!app.show_detail);
    }

    #[test]
    fn enter_does_not_open_detail_with_stale_selection() {
        let mut app = app_with_hosts(2);
        // Stale out-of-range index: no host is actually selected.
        app.selected_host = Some(9);
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Enter, &cancel);
        assert!(!app.show_detail);
    }

    #[test]
    fn esc_closes_detail() {
        let mut app = App {
            show_detail: true,
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Esc, &cancel);
        assert!(!app.show_detail);
        assert!(!app.should_quit);
    }

    #[test]
    fn navigation_and_cancel_are_ignored_while_detail_is_open() {
        let mut app = app_with_hosts(3);
        app.show_detail = true;
        app.selected_host = Some(1);
        app.scan = ScanState::Discovering {
            completed: 1,
            total: 4,
        };
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('j'), &cancel);
        app.handle_key(KeyCode::Char('k'), &cancel);
        app.handle_key(KeyCode::Down, &cancel);
        app.handle_key(KeyCode::Char('c'), &cancel);
        app.handle_key(KeyCode::Char('?'), &cancel);
        app.handle_key(KeyCode::Enter, &cancel);
        assert!(app.show_detail);
        assert_eq!(app.selected_host, Some(1));
        assert!(matches!(app.scan, ScanState::Discovering { .. }));
        assert!(!app.show_help);
        assert!(!cancel.load(Ordering::SeqCst));
    }

    #[test]
    fn quit_works_while_detail_is_open() {
        let mut app = App {
            show_detail: true,
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('q'), &cancel);
        assert!(app.should_quit);
        assert!(cancel.load(Ordering::SeqCst));
    }

    #[test]
    fn elapsed_is_none_before_any_scan() {
        let app = App::default();
        assert_eq!(app.elapsed(Instant::now()), None);
    }

    #[test]
    fn elapsed_while_scanning_counts_from_start() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Started { total: 1 });
        app.started_at = Some(Instant::now() - Duration::from_secs(5));
        let elapsed = app.elapsed(Instant::now()).expect("elapsed while scanning");
        assert!(
            elapsed >= Duration::from_secs(4) && elapsed <= Duration::from_secs(6),
            "expected ~5s, got {elapsed:?}"
        );
    }

    fn frozen_elapsed_after(event: ScanEvent) -> (App, Duration) {
        let mut app = App::default();
        app.apply_event(ScanEvent::Started { total: 1 });
        app.started_at = Some(Instant::now() - Duration::from_secs(5));
        app.apply_event(event);
        assert!(app.started_at.is_none(), "started_at must be taken");
        let frozen = app.elapsed(Instant::now()).expect("elapsed after scan");
        assert!(
            frozen >= Duration::from_secs(4) && frozen <= Duration::from_secs(6),
            "expected ~5s, got {frozen:?}"
        );
        // The frozen value is independent of the `now` argument.
        assert_eq!(
            app.elapsed(Instant::now() + Duration::from_secs(100)),
            Some(frozen)
        );
        (app, frozen)
    }

    #[test]
    fn finished_event_freezes_elapsed() {
        let (app, _) = frozen_elapsed_after(ScanEvent::Finished);
        assert_eq!(app.scan, ScanState::Completed);
    }

    #[test]
    fn cancelled_event_freezes_elapsed() {
        let (app, _) = frozen_elapsed_after(ScanEvent::Cancelled);
        assert_eq!(app.scan, ScanState::Cancelled);
    }

    #[test]
    fn error_event_freezes_elapsed() {
        let (app, _) = frozen_elapsed_after(ScanEvent::Error(ScanError::Socket("boom".to_owned())));
        assert_eq!(app.scan, ScanState::Error);
        assert_eq!(app.scan_error.as_deref(), Some("socket error: boom"));
    }

    #[test]
    fn format_duration_under_a_minute() {
        assert_eq!(format_duration(Duration::from_millis(400)), "0.4s");
        assert_eq!(format_duration(Duration::from_millis(1000)), "1.0s");
        assert_eq!(format_duration(Duration::from_millis(12400)), "12.4s");
    }

    #[test]
    fn format_duration_one_minute_or_more() {
        assert_eq!(format_duration(Duration::from_secs(60)), "1m 0.0s");
        assert_eq!(format_duration(Duration::from_secs_f64(65.3)), "1m 5.3s");
        assert_eq!(format_duration(Duration::from_secs(125)), "2m 5.0s");
    }

    #[test]
    fn window_start_defaults_to_top() {
        assert_eq!(window_start(0, None, 10), 0);
        assert_eq!(window_start(10, None, 5), 0);
        assert_eq!(window_start(10, Some(4), 0), 0); // no visible rows
        assert_eq!(window_start(10, Some(15), 5), 0); // stale index
    }

    #[test]
    fn window_start_returns_zero_when_selection_is_visible() {
        assert_eq!(window_start(10, Some(0), 5), 0);
        assert_eq!(window_start(10, Some(4), 5), 0);
    }

    #[test]
    fn window_start_shifts_down_when_selection_is_off_screen() {
        assert_eq!(window_start(10, Some(5), 5), 1);
        assert_eq!(window_start(10, Some(6), 5), 2);
        assert_eq!(window_start(10, Some(9), 5), 5);
    }

    // --- Phase 15: history and diff state transitions -------------------

    /// A unique temporary directory holding saved scan records, mirroring the
    /// storage tests' helper.
    fn temp_record_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "port-scanner-app-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// Write a minimal record (no hosts) with the given completion timestamp.
    fn save_test_record(dir: &std::path::Path, timestamp: u64, target: &str) {
        let record = crate::storage::ScanRecord {
            version: crate::storage::CURRENT_VERSION,
            timestamp,
            target: target.to_owned(),
            config: crate::storage::RecordConfig {
                discovery_timeout_ms: 300,
                discovery_concurrency: 16,
                ports: vec![22],
                port_timeout_ms: 300,
                port_concurrency: 8,
                detect_services: false,
                enrich: false,
            },
            hosts: vec![],
        };
        crate::storage::save(dir, &record).expect("save record");
    }

    /// An app in the history view with two saved records: timestamp 100 (the
    /// older one) and timestamp 200 (the newer one, listed first).
    fn app_with_history(name: &str) -> (App, std::path::PathBuf) {
        let dir = temp_record_dir(name);
        save_test_record(&dir, 100, "10.0.0.0/24");
        save_test_record(&dir, 200, "10.0.0.0/24");
        let mut app = App {
            view: View::History,
            ..Default::default()
        };
        app.load_history(&dir);
        (app, dir)
    }

    #[test]
    fn h_key_on_overview_switches_to_history_view() {
        let mut app = app_with_target();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('h'), &cancel);
        assert_eq!(app.view, View::History);
    }

    #[test]
    fn load_history_lists_records_newest_first() {
        let (app, dir) = app_with_history("list-order");
        assert_eq!(app.history_summaries.len(), 2);
        assert_eq!(app.history_summaries[0].timestamp, 200);
        assert_eq!(app.history_summaries[1].timestamp, 100);
        assert!(app.history_error.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_history_missing_dir_yields_empty_list() {
        let dir = temp_record_dir("missing-dir");
        let gone = dir.join("does-not-exist");
        let mut app = App::default();
        app.load_history(&gone);
        assert!(app.history_summaries.is_empty());
        assert!(app.history_error.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_history_unreadable_dir_sets_error() {
        let dir = temp_record_dir("unreadable-dir");
        // A regular file is not a directory, so `read_dir` fails.
        let file = dir.join("not-a-dir");
        std::fs::write(&file, b"nope").expect("write file");
        let mut app = App::default();
        app.load_history(&file);
        assert!(app.history_summaries.is_empty());
        assert!(app.history_error.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_navigation_clamps_at_bounds() {
        let (mut app, dir) = app_with_history("nav-clamp");
        let cancel = AtomicBool::new(false);
        // Two records: down, down (clamped), up, up (clamped).
        app.handle_key(KeyCode::Char('j'), &cancel);
        app.handle_key(KeyCode::Char('j'), &cancel);
        app.handle_key(KeyCode::Char('j'), &cancel);
        assert_eq!(app.history_selected, 1);
        app.handle_key(KeyCode::Char('k'), &cancel);
        app.handle_key(KeyCode::Char('k'), &cancel);
        app.handle_key(KeyCode::Char('k'), &cancel);
        assert_eq!(app.history_selected, 0);
        // Arrow keys behave the same.
        app.handle_key(KeyCode::Down, &cancel);
        assert_eq!(app.history_selected, 1);
        app.handle_key(KeyCode::Up, &cancel);
        assert_eq!(app.history_selected, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_d_marks_and_unmarks_the_selected_record() {
        let (mut app, dir) = app_with_history("mark-unmark");
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('d'), &cancel);
        assert_eq!(app.history_marked, Some(0));
        assert_eq!(app.view, View::History);
        // Pressing `d` on the marked record again clears the mark.
        app.handle_key(KeyCode::Char('d'), &cancel);
        assert_eq!(app.history_marked, None);
        assert_eq!(app.view, View::History);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_d_on_second_record_opens_diff_with_older_scan_first() {
        let (mut app, dir) = app_with_history("open-diff-order");
        let cancel = AtomicBool::new(false);
        // Mark the newer record (index 0), move to the older one (index 1),
        // then mark it: the diff must open with the older scan as "before".
        app.handle_key(KeyCode::Char('d'), &cancel);
        app.handle_key(KeyCode::Char('j'), &cancel);
        app.handle_key(KeyCode::Char('d'), &cancel);
        assert_eq!(app.view, View::Diff);
        let selection = app.diff_selection.as_ref().expect("diff is open");
        assert_eq!(selection.before.timestamp, 100);
        assert_eq!(selection.after.timestamp, 200);
        assert_eq!(app.history_marked, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_d_orders_by_timestamp_regardless_of_mark_order() {
        let (mut app, dir) = app_with_history("open-diff-reverse");
        let cancel = AtomicBool::new(false);
        // Mark the older record first, then the newer one.
        app.handle_key(KeyCode::Char('j'), &cancel);
        app.handle_key(KeyCode::Char('d'), &cancel);
        app.handle_key(KeyCode::Char('k'), &cancel);
        app.handle_key(KeyCode::Char('d'), &cancel);
        assert_eq!(app.view, View::Diff);
        let selection = app.diff_selection.as_ref().expect("diff is open");
        assert_eq!(selection.before.timestamp, 100);
        assert_eq!(selection.after.timestamp, 200);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_esc_returns_to_overview_and_clears_mark() {
        let (mut app, dir) = app_with_history("esc-to-overview");
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('d'), &cancel);
        assert_eq!(app.history_marked, Some(0));
        app.handle_key(KeyCode::Esc, &cancel);
        assert_eq!(app.view, View::Overview);
        assert_eq!(app.history_marked, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn diff_esc_returns_to_history_and_clears_selection() {
        let (mut app, dir) = app_with_history("diff-esc");
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('d'), &cancel);
        app.handle_key(KeyCode::Char('j'), &cancel);
        app.handle_key(KeyCode::Char('d'), &cancel);
        assert_eq!(app.view, View::Diff);
        app.handle_key(KeyCode::Esc, &cancel);
        assert_eq!(app.view, View::History);
        assert!(app.diff_selection.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn q_quits_from_history_and_diff_views() {
        let (mut app, dir) = app_with_history("quit-from-history");
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('q'), &cancel);
        assert!(app.should_quit);
        let _ = std::fs::remove_dir_all(&dir);

        let (mut app, dir) = app_with_history("quit-from-diff");
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('d'), &cancel);
        app.handle_key(KeyCode::Char('j'), &cancel);
        app.handle_key(KeyCode::Char('d'), &cancel);
        app.handle_key(KeyCode::Char('q'), &cancel);
        assert!(app.should_quit);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overview_navigation_keys_are_routed_to_history_view() {
        // With the history view active, `j` moves the record highlight, not
        // the host selection.
        let (mut app, dir) = app_with_history("view-routing");
        app.hosts = (0..3)
            .map(|i| Host::up(Ipv4Addr::new(10, 0, 0, i as u8), Duration::from_millis(1)))
            .collect();
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('j'), &cancel);
        assert_eq!(app.history_selected, 1);
        assert_eq!(app.selected_host, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_diff_reports_load_failure_and_stays_in_history() {
        let (mut app, dir) = app_with_history("diff-load-failure");
        // Replace the summaries with ones pointing at nonexistent files.
        app.history_summaries = vec![
            RecordSummary {
                path: dir.join("missing-a.json"),
                timestamp: 100,
                target: "10.0.0.0/24".to_owned(),
                host_count: 0,
                open_port_count: 0,
            },
            RecordSummary {
                path: dir.join("missing-b.json"),
                timestamp: 200,
                target: "10.0.0.0/24".to_owned(),
                host_count: 0,
                open_port_count: 0,
            },
        ];
        let first = app.history_summaries[0].clone();
        let second = app.history_summaries[1].clone();
        app.open_diff(&first, &second);
        assert_eq!(app.view, View::History);
        assert!(app.diff_selection.is_none());
        assert!(app.history_error.is_some());
        assert_eq!(app.history_marked, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn format_age_renders_seconds() {
        assert_eq!(format_age(100, 142), "42s ago");
        assert_eq!(format_age(100, 100), "0s ago");
    }

    #[test]
    fn format_age_renders_minutes() {
        assert_eq!(format_age(100, 100 + 60), "1m ago");
        assert_eq!(format_age(100, 100 + 300), "5m ago");
        assert_eq!(format_age(100, 100 + 3599), "59m ago");
    }

    #[test]
    fn format_age_renders_hours() {
        assert_eq!(format_age(100, 100 + 3600), "1h ago");
        assert_eq!(format_age(100, 100 + 7200), "2h ago");
        assert_eq!(format_age(100, 100 + 86_399), "23h ago");
    }

    #[test]
    fn format_age_renders_days() {
        assert_eq!(format_age(100, 100 + 86_400), "1d ago");
        assert_eq!(format_age(100, 100 + 172_800), "2d ago");
    }

    #[test]
    fn format_age_saturates_for_future_timestamps() {
        assert_eq!(format_age(1000, 100), "0s ago");
    }

    #[test]
    fn hosts_frame_title_is_plain_without_a_filter() {
        assert_eq!(hosts_frame_title(None, 42), "Hosts");
    }

    #[test]
    fn hosts_frame_title_shows_match_count_with_a_filter() {
        assert_eq!(hosts_frame_title(Some(3), 42), "Hosts  3 of 42");
    }

    #[test]
    fn scan_progress_is_none_when_idle() {
        let app = App::default();
        assert_eq!(app.scan_progress(), None);
    }

    #[test]
    fn scan_progress_is_none_after_the_scan_finishes() {
        for scan in [ScanState::Completed, ScanState::Cancelled, ScanState::Error] {
            let app = App {
                scan,
                ..Default::default()
            };
            assert_eq!(app.scan_progress(), None);
        }
    }

    #[test]
    fn scan_progress_starts_at_zero_while_starting() {
        let app = App {
            scan: ScanState::Starting,
            ..Default::default()
        };
        // No scan has started yet, so there is no elapsed time to report.
        assert_eq!(app.scan_progress(), Some((0.0, "Starting…".to_owned())));
    }

    #[test]
    fn scan_progress_reports_discovery_ratio_and_up_count() {
        let app = App {
            scan: ScanState::Discovering {
                completed: 5,
                total: 10,
            },
            hosts: vec![Host::up(
                "10.0.0.1".parse().unwrap(),
                Duration::from_millis(1),
            )],
            ..Default::default()
        };
        assert_eq!(
            app.scan_progress(),
            Some((0.5, "Discovering 5/10 · 1 up".to_owned()))
        );
    }

    #[test]
    fn scan_progress_discovery_keeps_ratio_zero_without_a_total() {
        let app = App {
            scan: ScanState::Discovering {
                completed: 3,
                total: 0,
            },
            ..Default::default()
        };
        assert_eq!(
            app.scan_progress(),
            Some((0.0, "Discovering 3/0 · 0 up".to_owned()))
        );
    }

    #[test]
    fn scan_progress_reports_port_probe_ratio() {
        let app = App {
            scan: ScanState::ScanningPorts,
            ports_per_host: 4,
            ports_probed: 2,
            hosts: vec![Host::up(
                "10.0.0.1".parse().unwrap(),
                Duration::from_millis(1),
            )],
            ..Default::default()
        };
        assert_eq!(
            app.scan_progress(),
            Some((0.5, "Probing ports 2/4 · 1 up".to_owned()))
        );
    }

    #[test]
    fn scan_progress_port_ratio_is_zero_without_up_hosts() {
        let app = App {
            scan: ScanState::ScanningPorts,
            ports_per_host: 4,
            ports_probed: 2,
            ..Default::default()
        };
        assert_eq!(
            app.scan_progress(),
            Some((0.0, "Probing ports 2/0 · 0 up".to_owned()))
        );
    }
}
