# PORT-SCANNER

Interactive terminal network exploration: **target → hosts → services → changes.**

PORT-SCANNER is a Rust-based Linux TUI application for discovering and exploring
hosts on an IP address or subnet. It discovers live hosts, probes TCP ports,
detects services, enriches hosts with hostname/MAC/vendor information, and lets
you compare scans over time — all from a responsive terminal interface.

[![CI](https://github.com/franzjesus/port-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/franzjesus/port-scanner/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/franzjesus/port-scanner)](https://github.com/franzjesus/port-scanner/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

- **Target parsing** — single IPv4 addresses and CIDR subnets (host bits
  truncated), with validation, clear errors, and a maximum subnet size guard.
- **Host discovery** — ICMP echo, with an automatic TCP-probe fallback
  (and a visible warning) when the ICMP socket cannot be opened. No root
  required to get started; ICMP gives better coverage when available.
- **TCP port scanning** — concurrent, bounded (128 workers) connect scans with
  per-stage timeouts, live per-host progress, and full cancellation.
- **Port profiles** — `quick` (18 high-signal ports), `common` (a curated set of
  well-known service ports), or `full` (all 65535 ports); or any explicit
  list/range such as `22,80,8000-8100`.
- **Service detection** — HTTP and HTTPS (server header) and SSH (version
  banner) detectors run against open ports.
- **Host enrichment** — reverse-DNS hostname, MAC address from the ARP table,
  and vendor from the MAC's OUI (labelled as inferred, since it is derived
  rather than discovered on the wire).
- **JSON export** — a structured export document of the current scan state;
  export files are never overwritten (a numeric suffix is added instead).
- **Scan history & diffs** — every completed scan is saved to disk; compare any
  two scans to see added/removed hosts, port state changes, service changes,
  and hostname/MAC/vendor changes (latency is excluded as noise).
- **Network view** — hosts grouped by /24 subnet (grouping is purely
  organizational and labelled as such).
- **In-TUI new scan** — start or switch targets from the overview screen
  without leaving the app.
- **Headless mode** — run a full scan without the TUI and emit the same JSON
  export document to stdout or a file.

## Requirements

- Linux
- Rust toolchain (`cargo`, `rustc`)

## Build

```sh
cargo build
```

## Usage

```sh
cargo run -- 192.168.1.0/24
```

Omitting the target launches the TUI idle; press `s` to open the new-scan
dialog and pick a target, discovery strategy, and port profile.

### CLI options

| Option                | Description                                                                                                                                                                         |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `target` (positional) | IPv4 address or CIDR subnet (e.g. `192.168.1.0/24`). Optional in TUI mode.                                                                                                          |
| `--ports <SPEC>`      | Comma-separated ports and/or ranges (e.g. `22,80,8000-8100`). Takes precedence over `--profile`.                                                                                    |
| `--profile <P>`       | `quick` (default), `common`, or `full`. Ignored when `--ports` is given.                                                                                                            |
| `--discovery <S>`     | `auto` (default), `icmp`, or `tcp`. `auto` tries ICMP first and falls back to TCP probing when the ICMP socket cannot be opened.                                                    |
| `--timeout <T>`       | Per-stage timeout for host discovery and port scanning. A bare number is milliseconds; `ms`, `s`, and `m` suffixes are accepted (e.g. `300`, `500ms`, `1s`, `2m`). Default `300ms`. |
| `--no-services`       | Skip service detection on open ports.                                                                                                                                               |
| `--no-enrichment`     | Skip host enrichment (reverse DNS, MAC, vendor).                                                                                                                                    |
| `--json`              | Run headlessly and print the JSON export document to stdout.                                                                                                                        |
| `--json-file <PATH>`  | Run headlessly and write the JSON export document to the given file, overwriting it if it exists.                                                                                   |

Headless mode requires a target. Examples:

```sh
cargo run -- 10.0.0.5 --profile full
cargo run -- 192.168.1.0/24 --discovery tcp --no-enrichment
cargo run -- 192.168.1.0/24 --ports 22,80,443 --timeout 1s
cargo run -- 192.168.1.0/24 --json | jq .
cargo run -- 192.168.1.0/24 --json-file scan.json
```

## TUI

The TUI stays responsive while scanning; results appear incrementally as they
arrive. Press `?` at any time for the in-app help overlay.

### Views

- **Overview** — the main scan screen: a host table (IP, state, latency, open
  ports) with a live progress gauge.
- **Host detail** — selected with `Enter`; shows the host's IP, state,
  latency, and any discovered enrichment fields, plus every probed port with
  the state its probe found. `c` toggles visibility of closed ports; the port
  list scrolls with `↑/↓`/`PgUp`/`PgDn`.
- **History** — saved scan records (age, target, host and port counts). `l`
  loads the selected record into the overview; `d` marks two records to
  compare.
- **Diff** — the comparison of two saved scans, ordered oldest-first, with
  added/removed hosts, port changes, and service changes.
- **Network** — hosts grouped by /24 subnet, sorted by IP within each group.

### Keyboard

| Key             | Action                                                                             |
| --------------- | ---------------------------------------------------------------------------------- |
| `↑` / `k`       | Up                                                                                 |
| `↓` / `j`       | Down                                                                               |
| `PgUp` / `PgDn` | Page up / down                                                                     |
| `Enter`         | Host detail                                                                        |
| `Esc`           | Back / close                                                                       |
| `/`             | Filter (case-insensitive substring over IP, state, and port numbers; `Esc` clears) |
| `h`             | History                                                                            |
| `n`             | Network view                                                                       |
| `s`             | New scan (overview, when idle)                                                     |
| `r`             | Rescan                                                                             |
| `c`             | Cancel scan (overview) / toggle closed ports (detail)                              |
| `e`             | Export results to JSON                                                             |
| `?`             | Help                                                                               |
| `q`             | Quit                                                                               |

### New scan dialog

Press `s` on the overview screen while idle. The dialog is prefilled with the
current target and offers three fields: **Target** (an IPv4 address or CIDR),
**Strategy** (`auto` / `icmp` / `tcp`), and **Profile** (`quick` / `common` /
`full`). Navigate fields with `Tab`, choose values with `←`/`→`, start with
`Enter`, cancel with `Esc`. A target parse error is shown in red.

### Export and storage

- **Export** (`e` or headless mode) writes `port-scanner-export.json` in the
  current directory; existing files are never overwritten (the name is
  suffixed `port-scanner-export-2.json`, `-3.json`, …).
- **History records** are saved under `$XDG_DATA_HOME/port-scanner` (default
  `~/.local/share/port-scanner`), one JSON file per completed scan.

## Project layout

```
src/
├── main.rs          # Entry point + CLI (clap) + scan configuration
├── target.rs        # IPv4/CIDR target parsing and validation
├── ports.rs         # Port specs, ranges, and profiles (quick/common/full)
├── subnet.rs        # Subnet helpers
├── network/         # Structured data model (hosts, ports, states)
├── scanner/         # Scanner engine (decoupled from the TUI)
│   ├── mod.rs       # Scan orchestration and event emission
│   ├── icmp.rs      # ICMP echo discovery
│   ├── tcp_discovery.rs  # TCP-probe discovery fallback
│   ├── discovery.rs # Discovery strategy selection
│   ├── ports.rs     # Concurrent TCP port scanning
│   ├── services.rs  # Service detectors (HTTP/HTTPS/SSH)
│   └── enrichment.rs    # Reverse DNS, MAC, vendor enrichment
├── export.rs        # JSON export document
├── headless.rs      # Headless scan mode (TUI-free, same JSON document)
├── storage.rs       # Scan record persistence (history)
├── diff.rs          # Scan-to-scan comparison
└── tui/             # TUI (ratatui + crossterm)
    ├── mod.rs       # Terminal setup and event loop
    └── app.rs       # Application state, views, key handling, drawing
```

Dependency direction: `CLI → Scanner → Network/Data Models → Scan Events → TUI`.
The scanner never depends on the TUI, and the TUI never performs network
operations.

## Development

```sh
cargo fmt --check
cargo check
cargo test
cargo clippy
```

See [AGENTS.md](AGENTS.md) for the development workflow and
[PLAN.md](PLAN.md) for the implementation plan and progress tracker.

## License

MIT — see [LICENSE](LICENSE).
