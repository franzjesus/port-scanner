mod network;
mod scanner;
mod target;
mod tui;

use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use clap::Parser;

use crate::scanner::{DiscoveryConfig, HostDiscovery, IcmpDiscovery, ScanEvent};
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

    // The scanner runs on a dedicated background thread and reports progress
    // to the TUI through this channel; cancellation is shared through the
    // `cancel` flag. The sender handle is either moved into the scanner
    // thread (so the channel disconnects when the scan finishes) or dropped
    // up front when there is nothing to scan.
    let (sender, receiver) = mpsc::channel::<ScanEvent>();
    let cancel = Arc::new(AtomicBool::new(false));

    if let Some(target) = &target {
        let target = target.clone();
        let cancel = cancel.clone();
        std::thread::spawn(move || {
            let config = DiscoveryConfig::default();
            let _ = IcmpDiscovery.discover(&target, &config, &sender, &cancel);
        });
    } else {
        drop(sender);
    }

    match tui::app::run(target, receiver, cancel) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("port-scanner: {err}");
            ExitCode::FAILURE
        }
    }
}
