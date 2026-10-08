mod tui;

use std::process::ExitCode;

use clap::Parser;

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
    ///
    /// Accepted now; consumed by the scanner in later phases.
    target: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Phase 1: the target is captured but intentionally unused until host
    // discovery and scanning are implemented in later phases.
    let _ = cli.target;

    match tui::app::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("netscope: {err}");
            ExitCode::FAILURE
        }
    }
}
