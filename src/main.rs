mod network;
mod ports;
mod scanner;
mod target;
mod tui;

use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use clap::Parser;

use crate::ports::{
    PortConfig, PortProfile, PortProfileError, PortSpec, PortSpecError, DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT,
};
use crate::scanner::{run_scan, DiscoveryConfig, IcmpDiscovery, ScanEvent, TcpPortScanner};
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

    /// Ports to probe: a comma-separated list and/or ranges (e.g. 22,80,8000-8100).
    /// Takes precedence over `--profile`.
    #[arg(long)]
    ports: Option<String>,

    /// Named port profile to probe: quick, common, or full.
    /// Ignored when `--ports` is given.
    #[arg(long, value_parser = parse_profile)]
    profile: Option<PortProfile>,
}

/// Parse the `--profile` argument into a [`PortProfile`].
///
/// Delegates to [`PortProfile`]'s `FromStr` implementation so the parsing
/// logic (and its tests) live in a single place.
fn parse_profile(raw: &str) -> Result<PortProfile, PortProfileError> {
    raw.parse::<PortProfile>()
}

/// Resolve the port configuration from the CLI's `--ports` and `--profile`
/// flags.
///
/// Precedence: an explicit `--ports` spec wins over `--profile`; when neither
/// is given, the default Quick profile is used. The timeout and concurrency
/// bounds are always the defaults — only the port set varies.
fn resolve_port_config(
    ports: Option<String>,
    profile: Option<PortProfile>,
) -> Result<PortConfig, PortSpecError> {
    let port_spec = match (ports, profile) {
        (Some(spec), _) => PortSpec::parse(&spec)?,
        (None, Some(profile)) => profile.ports(),
        (None, None) => PortProfile::Quick.ports(),
    };

    Ok(PortConfig {
        ports: port_spec,
        timeout: DEFAULT_TIMEOUT,
        concurrency: DEFAULT_CONCURRENCY,
    })
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

    // Resolve the port configuration up front so an invalid `--ports` value
    // produces a clear error and a non-zero exit code, mirroring how the
    // target is validated above. `--ports` wins over `--profile`; with neither
    // flag the Quick profile is the default.
    let port_config = match resolve_port_config(cli.ports, cli.profile) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("port-scanner: {err}");
            return ExitCode::FAILURE;
        }
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
        let port_config = port_config.clone();
        let cancel = cancel.clone();
        std::thread::spawn(move || {
            let discovery_config = DiscoveryConfig::default();
            let _ = run_scan(
                &target,
                &IcmpDiscovery,
                &discovery_config,
                &port_config,
                &TcpPortScanner,
                &sender,
                &cancel,
            );
        });
    } else {
        drop(sender);
    }

    // The TUI derives live port progress from the number of ports it will
    // probe per up host, so pass that count through from the resolved config.
    let ports_per_host = port_config.ports.len();
    match tui::app::run(target, ports_per_host, receiver, cancel) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("port-scanner: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_quick_when_nothing_is_given() {
        let config = resolve_port_config(None, None).unwrap();
        assert_eq!(config, PortConfig::default());
    }

    #[test]
    fn selects_the_named_profile() {
        let config = resolve_port_config(None, Some(PortProfile::Common)).unwrap();
        assert_eq!(config.ports, PortProfile::Common.ports());
        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
        assert_eq!(config.concurrency, DEFAULT_CONCURRENCY);
    }

    #[test]
    fn explicit_ports_take_precedence_over_profile() {
        let config = resolve_port_config(Some("80,443".into()), Some(PortProfile::Full)).unwrap();
        assert_eq!(config.ports, PortSpec::parse("80,443").unwrap());
    }

    #[test]
    fn explicit_ports_with_ranges_parse() {
        // 22 is one port; 8000..=8100 is 101 ports (inclusive), so 102 total.
        let config = resolve_port_config(Some("22,8000-8100".into()), None).unwrap();
        assert_eq!(config.ports.len(), 102);
    }

    #[test]
    fn invalid_ports_are_rejected_with_a_clear_error() {
        let err = resolve_port_config(Some("99999".into()), None).unwrap_err();
        assert!(matches!(err, PortSpecError::Parse { .. }));
    }
}
