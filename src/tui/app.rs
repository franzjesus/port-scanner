//! Application state and the main TUI event loop.

use std::io;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    widgets::Paragraph,
    Frame, Terminal,
};

use crate::target::ScanTarget;

/// Central application state.
///
/// Phase 2 keeps this minimal: the parsed scan target is displayed. Later
/// phases will track scan state, discovered hosts, selection, and filters.
#[derive(Debug, Default)]
pub struct App {
    pub should_quit: bool,
    /// The validated scan target, if the user provided one.
    pub target: Option<ScanTarget>,
}

impl App {
    /// Handle a keypress, updating application state.
    pub fn handle_key(&mut self, key: KeyCode) {
        if let KeyCode::Char('q') = key {
            self.should_quit = true;
        }
    }
}

/// Run the terminal UI until the user quits, then restore the terminal.
pub fn run(target: Option<ScanTarget>) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App {
        target,
        ..Default::default()
    };
    let result = run_loop(&mut terminal, &mut app);

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
) -> io::Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;

        if app.should_quit {
            return Ok(());
        }

        if event::poll(Duration::from_millis(100))? {
            // Resize and other events are reflected on the next draw,
            // which re-queries the terminal size.
            if let Event::Key(key) = event::read()? {
                app.handle_key(key.code);
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
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(frame.area());

    // The title echoes the plan's UI mockup: `PORT-SCANNER  192.168.1.0/24`.
    let title = match &app.target {
        Some(target) => format!("PORT-SCANNER  {target}"),
        None => "PORT-SCANNER".to_owned(),
    };
    let title = Paragraph::new(title).style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(title, chunks[0]);

    let body = match &app.target {
        Some(target) => {
            let unit = if target.len() == 1 { "host" } else { "hosts" };
            format!(
                "Target: {target} ({} {unit}). Press q to quit.",
                target.len()
            )
        }
        None => "No target. Run port-scanner with an IPv4 address or CIDR range.".to_owned(),
    };
    let body = Paragraph::new(body);
    frame.render_widget(body, chunks[1]);

    let help = Paragraph::new("q Quit");
    frame.render_widget(help, chunks[2]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quit_key_sets_should_quit() {
        let mut app = App::default();
        assert!(!app.should_quit);
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit);
    }

    #[test]
    fn other_keys_do_not_quit() {
        let mut app = App::default();
        app.handle_key(KeyCode::Char('x'));
        app.handle_key(KeyCode::Enter);
        assert!(!app.should_quit);
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
}
