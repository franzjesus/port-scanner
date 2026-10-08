mod target;
mod tui;

use std::process::ExitCode;

use clap::Parser;

use crate::target::ScanTarget;

/// NETSCOPE — interactive terminal network exploration.
///
/// target → hosts → services → changes
#[derive(Parser, Debug)]
#[command(
    name = "netscope",
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
                eprintln!("netscope: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    match tui::app::run(target) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("netscope: {err}");
            ExitCode::FAILURE
        }
    }
}
