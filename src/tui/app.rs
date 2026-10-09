//! Application state and the main TUI event loop.
//!
//! The TUI renders application state and handles keyboard input. It consumes
//! scanner events from a channel but never performs network operations itself
//! (see AGENTS.md).

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Modifier, Style},
    widgets::{Cell, Paragraph, Row, Table},
    Frame, Terminal,
};

use crate::network::{Host, HostState, Port, PortState};
use crate::scanner::ScanEvent;
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
    /// A scan is running; counts come from progress events.
    Scanning { completed: u64, total: u64 },
    /// The scan completed normally.
    Finished,
    /// The user cancelled the scan; the TUI stays open.
    Cancelled,
    /// The scan failed; holds the error message.
    Failed(String),
}

impl ScanState {
    /// Short label shown on the right side of the title row. Empty while
    /// idle so the row only shows the title and target.
    pub fn label(&self) -> String {
        match self {
            ScanState::Idle => String::new(),
            ScanState::Scanning { completed, total } => {
                let percent = if *total > 0 {
                    completed * 100 / total
                } else {
                    0
                };
                format!("SCANNING {percent}%")
            }
            ScanState::Finished => "FINISHED".to_owned(),
            ScanState::Cancelled => "CANCELLED".to_owned(),
            ScanState::Failed(_) => "FAILED".to_owned(),
        }
    }
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
}

impl App {
    /// Number of discovered hosts currently in the up state.
    pub fn up_count(&self) -> usize {
        self.hosts
            .iter()
            .filter(|host| host.state == HostState::Up)
            .count()
    }

    /// Apply one scanner event to the application state.
    pub fn apply_event(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Started { total } => {
                self.scan = ScanState::Scanning {
                    completed: 0,
                    total,
                };
            }
            ScanEvent::HostDiscovered(host) => {
                self.hosts.push(host);
            }
            ScanEvent::Progress { completed, total } => {
                if matches!(self.scan, ScanState::Scanning { .. }) {
                    self.scan = ScanState::Scanning { completed, total };
                }
            }
            ScanEvent::Finished => self.scan = ScanState::Finished,
            ScanEvent::Cancelled => self.scan = ScanState::Cancelled,
            ScanEvent::PortDiscovered { ip, port, state } => {
                // The scanner emits this for every probed port (open or closed);
                // the TUI records only open ports on the matching host. A host is
                // always discovered before its ports are probed, so it is already
                // present here; a miss is simply ignored.
                if state == PortState::Open {
                    if let Some(host) = self.hosts.iter_mut().find(|h| h.ip == ip) {
                        host.add_open_port(port);
                    }
                }
            }
            ScanEvent::Error(err) => self.scan = ScanState::Failed(err.to_string()),
        }
    }

    /// Handle a keypress, updating application state.
    ///
    /// `cancel` is the shared cancellation flag the scanner polls; pressing
    /// `c` or `q` sets it so in-flight probes stop.
    pub fn handle_key(&mut self, key: KeyCode, cancel: &AtomicBool) {
        match key {
            KeyCode::Char('q') => {
                self.should_quit = true;
                cancel.store(true, Ordering::SeqCst);
            }
            KeyCode::Char('c') if matches!(self.scan, ScanState::Scanning { .. }) => {
                cancel.store(true, Ordering::SeqCst);
                self.scan = ScanState::Cancelled;
            }
            _ => {}
        }
    }
}

/// Run the terminal UI until the user quits, then restore the terminal.
pub fn run(
    target: Option<ScanTarget>,
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
        ..Default::default()
    };
    let result = run_loop(&mut terminal, &mut app, &events, &cancel);

    // Restore the terminal even if the event loop failed.
    let restore = restore_terminal(&mut terminal);

    match (result, restore) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    events: &Receiver<ScanEvent>,
    cancel: &AtomicBool,
) -> io::Result<()> {
    loop {
        // Drain scanner events first so new results appear on the next frame.
        // A disconnected channel simply means the scanner is done (or never
        // started); there is nothing more to apply.
        while let Ok(event) = events.try_recv() {
            app.apply_event(event);
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
    }
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()
}

fn draw(frame: &mut Frame, app: &App) {
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

    let status_line = Paragraph::new(format!(
        "Hosts: {} up / {} scanned",
        app.up_count(),
        app.hosts.len()
    ));
    frame.render_widget(status_line, chunks[1]);

    if app.target.is_some() {
        frame.render_widget(host_table(app), chunks[2]);
    } else {
        let hint =
            Paragraph::new("No target. Run port-scanner with an IPv4 address or CIDR range.");
        frame.render_widget(hint, chunks[2]);
    }

    let help = Paragraph::new("q Quit  c Cancel");
    frame.render_widget(help, chunks[3]);
}

fn host_table(app: &App) -> Table<'_> {
    let header = Row::new(vec!["IP", "STATE", "LATENCY", "OPEN PORTS"])
        .style(Style::default().add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = app
        .hosts
        .iter()
        .map(|host| {
            Row::new(vec![
                Cell::from(host.ip.to_string()),
                Cell::from(host.state.to_string()),
                Cell::from(format_latency(host.latency)),
                Cell::from(format_open_ports(&host.ports)),
            ])
        })
        .collect();
    Table::new(
        [header].into_iter().chain(rows),
        [
            Constraint::Length(18),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Min(10),
        ],
    )
}

fn format_latency(latency: Option<Duration>) -> String {
    match latency {
        Some(latency) => format!("{:.1} ms", latency.as_secs_f64() * 1000.0),
        None => "-".to_owned(),
    }
}

/// Render a host's open ports as a comma-separated list (`22,80,443`), or a
/// dash when none have been found yet. Display-only; the structured data is
/// the host's sorted `ports` list.
fn format_open_ports(ports: &[Port]) -> String {
    match ports.len() {
        0 => "-".to_owned(),
        _ => ports
            .iter()
            .map(Port::to_string)
            .collect::<Vec<_>>()
            .join(","),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ScanError;
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
    fn cancel_key_sets_flag_and_state_while_scanning() {
        let mut app = App::default();
        app.scan = ScanState::Scanning {
            completed: 1,
            total: 4,
        };
        let cancel = AtomicBool::new(false);
        app.handle_key(KeyCode::Char('c'), &cancel);
        assert!(!app.should_quit);
        assert!(cancel.load(Ordering::SeqCst));
        assert_eq!(app.scan, ScanState::Cancelled);
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
    fn started_event_sets_scanning() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Started { total: 4 });
        assert_eq!(
            app.scan,
            ScanState::Scanning {
                completed: 0,
                total: 4
            }
        );
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
            ScanState::Scanning {
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
        let ports: Vec<u16> = app.hosts[0].ports.iter().map(Port::as_u16).collect();
        // Recorded in arrival order, kept sorted by `add_open_port`.
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn port_discovered_closed_is_not_recorded() {
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
        assert!(app.hosts[0].ports.is_empty());
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
    fn format_open_ports_joins_and_shows_dash_when_empty() {
        assert_eq!(format_open_ports(&[]), "-");
        let ports = vec![
            Port::new(22).unwrap(),
            Port::new(80).unwrap(),
            Port::new(443).unwrap(),
        ];
        assert_eq!(format_open_ports(&ports), "22,80,443");
    }

    #[test]
    fn finished_event_sets_finished() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Finished);
        assert_eq!(app.scan, ScanState::Finished);
    }

    #[test]
    fn cancelled_event_sets_cancelled() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Cancelled);
        assert_eq!(app.scan, ScanState::Cancelled);
    }

    #[test]
    fn error_event_sets_failed_with_message() {
        let mut app = App::default();
        app.apply_event(ScanEvent::Error(ScanError::Socket("boom".to_owned())));
        assert_eq!(app.scan, ScanState::Failed("socket error: boom".to_owned()));
    }

    #[test]
    fn full_scan_sequence_reaches_finished() {
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
        assert_eq!(app.scan, ScanState::Finished);
        assert_eq!(app.hosts.len(), 1);
        assert_eq!(app.up_count(), 1);
        assert_eq!(app.scan.label(), "FINISHED");
    }

    #[test]
    fn scanning_label_shows_percentage() {
        assert_eq!(
            ScanState::Scanning {
                completed: 2,
                total: 4
            }
            .label(),
            "SCANNING 50%"
        );
        assert_eq!(
            ScanState::Scanning {
                completed: 1,
                total: 3
            }
            .label(),
            "SCANNING 33%"
        );
        assert_eq!(
            ScanState::Scanning {
                completed: 0,
                total: 1
            }
            .label(),
            "SCANNING 0%"
        );
    }

    #[test]
    fn scanning_label_handles_zero_total() {
        assert_eq!(
            ScanState::Scanning {
                completed: 0,
                total: 0
            }
            .label(),
            "SCANNING 0%"
        );
    }

    #[test]
    fn idle_label_is_empty() {
        assert_eq!(ScanState::Idle.label(), "");
    }

    #[test]
    fn terminal_states_have_labels() {
        assert_eq!(ScanState::Finished.label(), "FINISHED");
        assert_eq!(ScanState::Cancelled.label(), "CANCELLED");
        assert_eq!(ScanState::Failed("x".to_owned()).label(), "FAILED");
    }

    #[test]
    fn up_count_counts_only_up_hosts() {
        let mut app = App::default();
        app.hosts = vec![
            Host::up("10.0.0.1".parse().unwrap(), Duration::from_millis(1)),
            Host::down("10.0.0.2".parse().unwrap()),
            Host::up("10.0.0.3".parse().unwrap(), Duration::from_millis(2)),
        ];
        assert_eq!(app.up_count(), 2);
    }
}
