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

/// Central application state.
///
/// Phase 1 keeps this minimal. Later phases will track scan state, discovered
/// hosts, selection, and filters here.
#[derive(Debug, Default)]
pub struct App {
    pub should_quit: bool,
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
pub fn run() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::default();
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
        terminal.draw(draw)?;

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

fn draw(frame: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let title = Paragraph::new("NETSCOPE").style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(title, chunks[0]);

    let body = Paragraph::new("Ready. Press q to quit.");
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
}
