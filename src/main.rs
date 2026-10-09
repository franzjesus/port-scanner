mod network;
mod scanner;
mod target;
mod tui;

use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use clap::Parser;

use crate::target::ScanTarget;

/// PORT-SCANNER — interactive terminal network exploration.
///
/// target → hosts → services → changes
#[derive(Parser, Debug)]
#[command(
    name = "port-scanner",
    version,
    about = "Interactive terminal network exploration: target, hosts, services, changes."
)]
struct Cli {
    /// Scan target: an IPv4 address or CIDR subnet (e.g. 192.168.1.0/24).
    target: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Parse and validate the target before entering the TUI. Invalid input
    // produces a clear error and a non-zero exit code without panicking.
    let target = match cli.target {
        Some(raw) => match ScanTarget::parse(&raw) {
            Ok(target) => Some(target),
            Err(err) => {
                eprintln!("port-scanner: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    // The TUI always consumes scan events through a channel. The scanner
    // thread that feeds it is wired up in a later task; until then the
    // sender is dropped so the channel is disconnected from the start.
    let (sender, receiver) = mpsc::channel();
    drop(sender);
    let cancel = Arc::new(AtomicBool::new(false));

    match tui::app::run(target, receiver, cancel) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("port-scanner: {err}");
            ExitCode::FAILURE
        }
    }
}
