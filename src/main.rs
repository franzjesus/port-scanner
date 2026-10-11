mod diff;
mod export;
mod headless;
mod network;
mod ports;
mod scanner;
mod storage;
mod subnet;
mod target;
mod tui;

use std::fmt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use clap::Parser;

use crate::ports::{
    PortConfig, PortProfile, PortProfileError, PortSpec, PortSpecError, DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT,
};
use crate::scanner::{
    default_detectors, default_enrichers, run_scan, IcmpDiscovery, ScanConfig, ScanEvent,
    ScanSpawner, TcpPortScanner,
};
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

    /// Skip service detection on open ports.
    #[arg(long)]
    no_services: bool,

    /// Skip host enrichment (reverse-DNS hostname, MAC address, vendor).
    #[arg(long)]
    no_enrichment: bool,

    /// Per-stage scan timeout, applied to both host discovery and port
    /// scanning. A bare number is milliseconds; `ms`, `s`, and `m` suffixes
    /// are also accepted (e.g. 300, 500ms, 1s, 2m).
    #[arg(long, value_parser = parse_timeout)]
    timeout: Option<Duration>,

    /// Run headlessly: perform the scan without the TUI and print the JSON
    /// export document to stdout.
    #[arg(long, conflicts_with = "json_file")]
    json: bool,

    /// Run headlessly and write the JSON export document to the given file,
    /// overwriting it if it exists.
    #[arg(long, value_name = "PATH", conflicts_with = "json")]
    json_file: Option<PathBuf>,
}

/// Parse the `--profile` argument into a [`PortProfile`].
///
/// Delegates to [`PortProfile`]'s `FromStr` implementation so the parsing
/// logic (and its tests) live in a single place.
fn parse_profile(raw: &str) -> Result<PortProfile, PortProfileError> {
    raw.parse::<PortProfile>()
}

/// Error produced when the `--timeout` argument cannot be parsed.
#[derive(Debug)]
enum TimeoutError {
    Parse { input: String, reason: String },
}

impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeoutError::Parse { input, reason } => {
                write!(f, "invalid timeout {input:?}: {reason}")
            }
        }
    }
}

impl std::error::Error for TimeoutError {}

/// Parse the `--timeout` argument into a [`Duration`].
///
/// A bare non-negative integer is milliseconds, matching the default. The
/// `ms`, `s`, and `m` suffixes are accepted (case-sensitive), with or without
/// a space before the unit (e.g. `300`, `500ms`, `1s`, `2m`). Fractions are
/// not supported.
fn parse_timeout(raw: &str) -> Result<Duration, TimeoutError> {
    let err = |reason: &str| TimeoutError::Parse {
        input: raw.to_string(),
        reason: reason.to_string(),
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(err("empty value"));
    }

    // Split off an optional unit suffix. A space before the unit is allowed.
    let (value, unit) = if let Some(pos) = trimmed.rfind(' ') {
        let unit = trimmed[pos..].trim_start();
        if unit == "ms" || unit == "s" || unit == "m" {
            (trimmed[..pos].trim_end(), Some(unit))
        } else {
            (trimmed, None)
        }
    } else if let Some(stripped) = trimmed.strip_suffix("ms") {
        (stripped, Some("ms"))
    } else if let Some(stripped) = trimmed.strip_suffix('s') {
        (stripped, Some("s"))
    } else if let Some(stripped) = trimmed.strip_suffix('m') {
        (stripped, Some("m"))
    } else {
        (trimmed, None)
    };

    let number: u64 = value
        .parse()
        .map_err(|_| err("not a non-negative integer"))?;

    let millis = match unit {
        None => number, // bare value = milliseconds
        Some("ms") => number,
        Some("s") => number
            .checked_mul(1_000)
            .ok_or_else(|| err("value out of range"))?,
        Some("m") => number
            .checked_mul(60_000)
            .ok_or_else(|| err("value out of range"))?,
        _ => unreachable!("only known units are matched above"),
    };

    Ok(Duration::from_millis(millis))
}

/// Resolve the port configuration from the CLI's `--ports`, `--profile`, and
/// `--timeout` flags.
///
/// Precedence: an explicit `--ports` spec wins over `--profile`; when neither
/// is given, the default Quick profile is used. The timeout comes from
/// `--timeout` when present and falls back to the default otherwise; the
/// concurrency bound is always the default.
fn resolve_port_config(
    ports: Option<String>,
    profile: Option<PortProfile>,
    timeout: Option<Duration>,
) -> Result<PortConfig, PortSpecError> {
    let port_spec = match (ports, profile) {
        (Some(spec), _) => PortSpec::parse(&spec)?,
        (None, Some(profile)) => profile.ports(),
        (None, None) => PortProfile::Quick.ports(),
    };

    Ok(PortConfig {
        ports: port_spec,
        timeout: timeout.unwrap_or(DEFAULT_TIMEOUT),
        concurrency: DEFAULT_CONCURRENCY,
    })
}

/// Build a spawner that runs a scan on a dedicated background thread (Phase 10).
///
/// The TUI calls this spawner for every scan — the initial one and each
/// rescan — so all scans go through the same code path. Each spawned thread
/// receives its own clone of the master sender; the master sender itself stays
/// alive for the lifetime of the TUI, so the event channel never disconnects
/// mid-session.
///
/// The spawner captures the default service detectors and host enrichers
/// once and hands them to every scan; whether detection and enrichment
/// actually run are decided per scan by [`ScanConfig::detect_services`] (set
/// from the `--no-services` flag) and [`ScanConfig::enrich`] (set from the
/// `--no-enrichment` flag). The detector and enricher sets live behind `Arc`s
/// because the spawner is an `Fn` closure invoked for every scan and the
/// trait objects themselves cannot be cloned.
fn build_spawner() -> ScanSpawner {
    let detectors = Arc::new(default_detectors());
    let enrichers = Arc::new(default_enrichers());
    Box::new(move |config, master_tx, cancel| {
        let detectors = Arc::clone(&detectors);
        let enrichers = Arc::clone(&enrichers);
        std::thread::spawn(move || {
            let _ = run_scan(
                &config,
                &IcmpDiscovery,
                &TcpPortScanner,
                &detectors,
                &enrichers,
                &master_tx,
                &cancel,
            );
        });
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
    let port_config = match resolve_port_config(cli.ports, cli.profile, cli.timeout) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("port-scanner: {err}");
            return ExitCode::FAILURE;
        }
    };

    // Build the scan configuration up front when a target was given; the port
    // set, timeout, and feature toggles come from the CLI. The TUI launches
    // the scan itself through the spawner (Phase 10).
    let config = target.as_ref().map(|target| {
        let mut config = ScanConfig::new(target.clone());
        config.ports = port_config.clone();
        // `--timeout` applies to both stages, so mirror it into the discovery
        // stage when the user set it.
        if let Some(timeout) = cli.timeout {
            config.discovery.timeout = timeout;
        }
        config.detect_services = !cli.no_services;
        config.enrich = !cli.no_enrichment;
        config
    });

    // Headless mode (Phase 11): run the scan without the TUI and emit the same
    // JSON export document to stdout or a file. A target is required.
    if cli.json || cli.json_file.is_some() {
        return match &config {
            Some(config) => headless::run(config, cli.json_file.as_deref()),
            None => {
                eprintln!("port-scanner: headless mode requires a target");
                ExitCode::FAILURE
            }
        };
    }

    // The scanner reports structured events through this channel; the TUI
    // keeps the master sender alive for its whole lifetime so rescans can
    // reuse the channel. Cancellation is shared through the `cancel` flag.
    let (master_tx, events) = mpsc::channel::<ScanEvent>();
    let cancel = Arc::new(AtomicBool::new(false));

    // The TUI derives live port progress from the number of ports it will
    // probe per up host, so pass that count through from the resolved config.
    let ports_per_host = port_config.ports.len();
    match tui::app::run(
        target,
        ports_per_host,
        config,
        build_spawner(),
        master_tx,
        events,
        cancel,
    ) {
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
        let config = resolve_port_config(None, None, None).unwrap();
        assert_eq!(config, PortConfig::default());
    }

    #[test]
    fn selects_the_named_profile() {
        let config = resolve_port_config(None, Some(PortProfile::Common), None).unwrap();
        assert_eq!(config.ports, PortProfile::Common.ports());
        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
        assert_eq!(config.concurrency, DEFAULT_CONCURRENCY);
    }

    #[test]
    fn explicit_ports_take_precedence_over_profile() {
        let config =
            resolve_port_config(Some("80,443".into()), Some(PortProfile::Full), None).unwrap();
        assert_eq!(config.ports, PortSpec::parse("80,443").unwrap());
    }

    #[test]
    fn explicit_ports_with_ranges_parse() {
        // 22 is one port; 8000..=8100 is 101 ports (inclusive), so 102 total.
        let config = resolve_port_config(Some("22,8000-8100".into()), None, None).unwrap();
        assert_eq!(config.ports.len(), 102);
    }

    #[test]
    fn invalid_ports_are_rejected_with_a_clear_error() {
        let err = resolve_port_config(Some("99999".into()), None, None).unwrap_err();
        assert!(matches!(err, PortSpecError::Parse { .. }));
    }

    #[test]
    fn explicit_timeout_overrides_the_default() {
        let timeout = Duration::from_millis(750);
        let config = resolve_port_config(None, None, Some(timeout)).unwrap();
        assert_eq!(config.timeout, timeout);
    }

    #[test]
    fn bare_number_is_milliseconds() {
        assert_eq!(parse_timeout("300").unwrap(), Duration::from_millis(300));
        assert_eq!(parse_timeout("0").unwrap(), Duration::ZERO);
    }

    #[test]
    fn unit_suffixes_are_supported() {
        assert_eq!(parse_timeout("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_timeout("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_timeout("2m").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn space_before_unit_is_allowed() {
        assert_eq!(parse_timeout("500 ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_timeout("1 s").unwrap(), Duration::from_secs(1));
    }

    #[test]
    fn invalid_timeout_values_are_rejected() {
        for input in ["", "  ", "abc", "1.5s", "-1", "1x"] {
            let err = parse_timeout(input).unwrap_err();
            assert!(
                matches!(err, TimeoutError::Parse { .. }),
                "expected parse error for {input:?}"
            );
        }
    }

    #[test]
    fn overflowing_timeout_is_rejected() {
        // 18446744073709551615 ms overflows a u64 when converted to seconds,
        // and u64::MAX seconds overflows the millisecond conversion.
        let err = parse_timeout("18446744073709551615s").unwrap_err();
        assert!(matches!(err, TimeoutError::Parse { .. }));
    }
}
