# Network TUI Scanner — Implementation Plan

## 1\. Project Overview

Build a Linux terminal user interface (TUI) application in Rust for discovering and exploring hosts on an IP address or subnet.

The application should make it easy to go from:

```
Target → Host discovery → Open ports → Services → Historical changes
```

The primary goal is **interactive network exploration from the terminal**, not simply reproducing the output of an existing command-line scanner.

The application should be fast, responsive, asynchronous, and designed so the scanner engine is independent from the TUI.

---

# 2\. Product Goals

## Primary goals

- Scan a single IPv4 address.
- Scan an IPv4 CIDR subnet.
- Discover live hosts.
- Scan TCP ports.
- Display results interactively in a TUI.
- Show scan progress while scanning.
- Inspect individual hosts.
- Filter and search scan results.
- Export scan results as JSON.
- Keep scanner logic independent from the UI.
- Support concurrent network operations.
- Provide useful error handling and cancellation.

## Future goals

- ARP discovery.
- Service detection.
- Hostname resolution.
- MAC address and vendor information.
- TLS information.
- Saved scans.
- Scan history.
- Scan-to-scan diff.
- Network visualization.
- IPv6.
- Additional discovery mechanisms.
- Additional service detectors.

## Non-goals for the initial release

Do not attempt to implement a full Nmap replacement.

Do not initially implement:

- UDP scanning.
- OS fingerprinting.
- Aggressive service fingerprinting.
- Complex packet crafting.
- Vulnerability scanning.
- Exploit detection.
- Network topology claims based only on IP addresses.

These can be considered later if there is a clear need.

---

# 3\. High-Level Architecture

Keep the project separated into three major layers:

```
                    ┌───────────────┐
                    │      CLI      │
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │    Scanner     │
                    └───────┬───────┘
                            │
                       Scan Events
                            │
              ┌─────────────┴─────────────┐
              │                           │
       ┌──────▼──────┐             ┌──────▼──────┐
       │     TUI     │             │   Storage   │
       └─────────────┘             └─────────────┘
```

## Important architectural rule

The scanner must not depend on the TUI.

The scanner should be usable independently and produce structured results/events.

The TUI consumes scanner events and renders application state.

This allows future functionality such as:

```
port-scanner scan 192.168.1.0/24
port-scanner tui 192.168.1.0/24
port-scanner export scan.json
```

without requiring scanner logic to be rewritten.

---

# 4\. Proposed Project Structure

Start with the following structure:

```
src/
├── main.rs
├── cli/
│   └── mod.rs
├── scanner/
│   ├── mod.rs
│   ├── discovery.rs
│   ├── icmp.rs
│   ├── arp.rs
│   ├── tcp.rs
│   └── ports.rs
├── network/
│   ├── mod.rs
│   ├── host.rs
│   ├── port.rs
│   └── subnet.rs
├── storage/
│   ├── mod.rs
│   └── json.rs
└── tui/
    ├── mod.rs
    ├── app.rs
    ├── events.rs
    ├── state.rs
    └── views/
        ├── overview.rs
        ├── hosts.rs
        ├── host_detail.rs
        └── ports.rs
```

Do not create modules until they have a concrete purpose.

The structure may evolve as implementation progresses.

---

# 5\. Core Data Model

The internal data model must be independent of the TUI.

## Host

Conceptually:

```
struct Host {
    ip: IpAddr,
    state: HostState,
    hostname: Option<String>,
    mac: Option<MacAddr>,
    vendor: Option<String>,
    latency: Option<Duration>,
    ports: Vec<Port>,
}
```

Initial implementation may omit fields whose functionality has not yet been implemented.

## Host state

```
enum HostState {
    Unknown,
    Scanning,
    Up,
    Down,
    Error,
}
```

## Port

```
struct Port {
    number: u16,
    protocol: Protocol,
    state: PortState,
    service: Option<String>,
}
```

## Port state

Initially:

```
enum PortState {
    Open,
    Closed,
    Filtered,
}
```

Only states that can actually be determined by the implemented scanner should be reported.

---

# 6\. Scan Events

The scanner should communicate progress through events.

Conceptually:

```
enum ScanEvent {
    Started,
    HostDiscovered(Host),
    PortDiscovered {
        ip: IpAddr,
        port: Port,
    },
    HostCompleted(IpAddr),
    Progress {
        completed: usize,
        total: usize,
    },
    Finished,
    Cancelled,
    Error(ScanError),
}
```

The exact design may change during implementation.

Requirements:

- Events must be usable by the TUI.
- Events must not contain TUI-specific types.
- Scanning must not block the UI thread.
- The UI should update incrementally as results arrive.

---

# 7\. Phase 1 — Project Bootstrap

## Tasks

- [x]Create Rust binary project.
- [x]Configure Rust edition.
- [x]Add basic command-line argument parsing.
- [x]Add TUI framework.
- [x]Add asynchronous runtime if required by scanner architecture.
- [x]Establish formatting/linting configuration.
- [x]Add basic test infrastructure.
- [x]Add README.
- [x]Add LICENSE.
- [x]Add `.gitignore`.

## Acceptance criteria

The application builds successfully with:

```
cargo build
```

and runs with:

```
cargo run
```

The project should have a minimal TUI that can start and exit cleanly.

## Notes

- Crate/binary name: `port-scanner` (edition 2021).
- TUI stack: `ratatui 0.29` + `crossterm 0.28` (latest compatible majors at bootstrap time).
- CLI parsing: `clap 4` (derive).
- Async runtime: `tokio 1` (rt-multi-thread, macros) — included now per the scanner architecture.
- Linting: `[lints.clippy] all = "warn"` in `Cargo.toml`; formatting via `rustfmt.toml` (`max_width = 100`).
- Minimal TUI: three-row layout (title / body / help), 100 ms event poll, quits on `q`, restores the terminal on both success and failure paths.
- CLI captures an optional `target` argument; intentionally unused until Phase 2.
- Verified: `cargo fmt --check`, `cargo check` (no warnings), `cargo test` (2 unit tests), `cargo clippy --all-targets` (clean), `cargo build`, and a PTY smoke test (renders all three rows, enters/leaves the alternate screen, exits 0 on `q`).

---

# 8\. Phase 2 — Target Parsing

Implement parsing and validation of scan targets.

Supported initially:

```
192.168.1.1
192.168.1.0/24
10.0.0.1
10.0.0.0/28
```

Use proper IP/CIDR types rather than manually parsing strings.

## Tasks

- [x]Parse single IPv4 addresses into a structured target.
- [x]Parse and normalize CIDR subnets (host bits truncated).
- [x]Reject invalid targets with clear errors, without panicking.
- [x]Enforce a maximum subnet size to prevent accidental unbounded scans.
- [x]Wire target parsing into the CLI (invalid input → clear error, non-zero exit).
- [x]Display the parsed target in the TUI (title and body).
- [x]Add unit tests for parsing, validation, and error messages.

## Requirements

- Validate IPv4 addresses.
- Validate CIDR prefixes.
- Reject invalid targets cleanly.
- Prevent accidental unbounded scans.
- Provide useful error messages.

Examples of invalid input:

```
192.168.1.999
192.168.1.0/99
hello
```

## Acceptance criteria

Valid targets become structured scan targets.

Invalid targets produce clear errors without panicking.

## Notes

- CIDR handling uses `ipnet 2` (`Ipv4Net`): the standard library provides `Ipv4Addr` but no CIDR type, and `ipnet` is small and dependency-free.
- `ScanTarget` is an enum: `Host(Ipv4Addr)` / `Subnet(Ipv4Net)`. Subnets are normalized via `trunc()`, so `192.168.1.1/24` is stored as `192.168.1.0/24`. `len()` returns the address count as `u64` (a `/0` is 2^32).
- `MAX_SUBNET_SIZE = 65_536` (i.e. minimum prefix `/16`) rejects larger targets with a `TooManyHosts` error. It is a constant for now and can become configurable once scan configuration exists (Phase 5).
- IPv6 input is explicitly rejected with `Ipv6NotSupported` until IPv6 support lands (Phase 23).
- The TUI displays the target in the title (per the UI mockup) and in the body (`Target: ... (N hosts). Press q to quit.`); the body remains a placeholder until the host list exists in a later phase.
- Verified: `cargo fmt --check`, `cargo check`, `cargo test` (16 unit tests), `cargo clippy --all-targets` (clean), plus manual CLI checks of every error path (invalid address, invalid prefix, oversized subnet, IPv6 → exit 1) and a PTY smoke test (renders the target title/body, clean exit on `q`).

---

# 9\. Phase 3 — Host Discovery

Implement the first real scanner.

## Tasks

- [x]3.1 Add `ScanTarget::iter()` / `ScanTargetIter` to enumerate every address in a target.
- [x]3.2 Add the `network` module: the structured `Host` model and `HostState`.
- [x]3.3 Add the `scanner` module: the `ScanEvent` and `ScanError` event models.
- [x]3.4 Add `DiscoveryConfig` and the `HostDiscovery` abstraction.
- [x]3.5 Add ICMP echo primitives (`PingSocket`) over unprivileged ping sockets.
- [x]3.6 Add `IcmpDiscovery` with a batched, bounded-concurrency sweep and a localhost integration test.
- [x]3.7 Rework the TUI `App` to consume scan events, track scan state, and render a live host table.
- [x]3.8 Wire the scanner onto a background thread from `main`, with cancellation and a guaranteed terminal event.
- [x]3.9 Update this plan and record implementation notes.

## Initial discovery strategy

Start with a simple mechanism that works reliably in normal user environments.

Primary initial mechanism:

- ICMP echo discovery where practical.

Design discovery behind an abstraction so additional mechanisms can be added later.

Implemented as (blocking, run on a dedicated thread — see the notes):

```
trait HostDiscovery: Send {
    fn discover(
        &self,
        target: &ScanTarget,
        config: &DiscoveryConfig,
        events: &Sender<ScanEvent>,
        cancel: &Arc<AtomicBool>,
    ) -> Result<(), ScanError>;
}
```

The trait reports progress through `ScanEvent`s on the `events` channel (rather than returning a `Vec<Host>`), so results appear incrementally and cancellation can be checked between probes. It is intentionally blocking: the scanner runs on its own `std::thread`, which keeps the scanner decoupled from any async runtime and the TUI responsive.

## Requirements

- Scan all addresses in the target.
- Run probes concurrently.
- Respect configurable timeout.
- Respect configurable concurrency.
- Report hosts incrementally.
- Support cancellation.
- Do not freeze the TUI.

## Acceptance criteria

Scanning:

```
192.168.1.0/24
```

produces live hosts as they are discovered.

The TUI remains responsive during the scan.

Both acceptance criteria are met (verified by a PTY smoke test scanning `127.0.0.1`: the live host is discovered, the host table and `Hosts: 1 up / 1 scanned` status line render, the label transitions `SCANNING` → `FINISHED`, and the TUI stays responsive throughout).

## Notes

- **Discovery mechanism:** ICMP echo over an unprivileged ping socket (`SOCK_DGRAM`/`IPPROTO_ICMP` via `libc`), not a raw socket. This works without `CAP_NET_RAW`/root in normal user environments (verified here: `SOCK_DGRAM`/ICMP opens and replies on loopback; `SOCK_RAW`/ICMP fails with `EPERM`).
- **Per-socket identifier:** for `SOCK_DGRAM` ICMP sockets the kernel assigns and manages the identifier itself, so replies are matched to a host by `(source address, sequence number)` only — no identifier filtering is needed. (The echo header layout is type, code, checksum (bytes 2–4), identifier (bytes 4–6), sequence (bytes 6–8); the checksum and identifier fields are adjacent and easy to confuse.)
- **Concurrency model:** `IcmpDiscovery` collects the target's addresses into a `Vec` and sweeps them in `chunks(concurrency)` (default 128). Each batch sends all of its probes, then receives replies in `RECV_CHUNK = 50ms` steps until `timeout` (default 300ms) elapses from the batch start; any address still in flight at expiry is marked `Down`. Cancellation is checked before each batch and between receive chunks.
- **Event emission:** a `HostDiscovered` event is emitted for every host (both `Up` and `Down`), followed by a `Progress` event, so the TUI can render the full host table and drive its progress count from `Progress` alone.
- **`HostState` simplified to `Up`/`Down`:** Phase 3 needs only a liveness verdict (plus optional latency for `Up` hosts); richer states are not required yet.
- **Known limitation:** a reply that arrives for a host already marked `Down` in an earlier window is ignored (it is no longer tracked as in flight). Acceptable for the initial mechanism.
- **Terminal-event guarantee:** a single scan run emits exactly one terminal event (`Finished`, `Cancelled`, or `Error`); the socket-creation failure path emits an `Error` before returning `Err`, so the TUI never gets stuck in `Idle`. In Phase 3 this was owned by `discover`; since 4.9b the guarantee is owned by the `run_scan` orchestrator, and `discover`/`sweep` are the unframed core (they emit no `Started`/`Finished`; `sweep` may still emit a mid-sweep `Cancelled`).
- **Scanner/TUI separation preserved:** the scanner runs on a dedicated `std::thread` and communicates only through the `ScanEvent` channel and the shared `AtomicBool` cancellation flag. No tokio tasks are used; tokio remains only the `#[tokio::main]` entry point.
- **Verified:** `cargo fmt --check`, `cargo check` (no warnings), `cargo test` (51 tests, including the `IcmpDiscovery` localhost integration test), `cargo clippy` (clean), and PTY smoke tests for both the no-target path and a live `127.0.0.1` scan.

---

# 10\. Phase 4 — TCP Port Scanning

Implement TCP connect scanning.

## Requirements

- Support configurable ports.
- Support individual ports.
- Support port ranges.
- Support predefined scan profiles.
- Run scans concurrently.
- Respect connection timeout.
- Report results incrementally.

Example port specification:

```
22
80
443
22,80,443
8000-8100
22,80,8000-8100
```

## Initial profiles

### Quick

Small set of common ports.

### Common

Larger predefined list.

### Full

TCP ports 1–65535.

Full scans should require an explicit selection.

## Acceptance criteria

Given a live host, the scanner can report:

```
22/tcp   open
80/tcp   open
443/tcp  closed
```

Results appear in the TUI while scanning.

Both acceptance criteria are met. The scanner reports a `PortState` for every probed port — `TcpPortScanner` maps a successful `connect_timeout` to `Open` and any error (refused or timeout) to `Closed`, emitting one `ScanEvent::PortDiscovered` per port (a local-listener integration test asserts the open port reports `Open` and a closed port reports `Closed`). The TUI records open ports in the OPEN PORTS column and shows live `Ports: probed/total` progress while scanning (verified by a PTY smoke test scanning `127.0.0.1`: the open port is recorded and the progress reaches `18/18`).

## Tasks

- [x]4.1 Port data model (`Port`, `PortState`, `PortError`), `Host.ports`, and the `ScanEvent::PortDiscovered` event.
- [x]4.2 `PortSpec` type + single-port parsing + `PortSpecError` + tests.
- [x]4.3 `PortSpec` range + mixed parsing, reversed-range normalization, + tests. (The `is_full` helper added here was removed in 4.9c: it was test-only with no Phase-4 consumer.)
- [x]4.4 `PortProfile` (Quick/Common/Full lists) + `PortConfig` + `Default` + re-exports.
- [x]4.5 `PortScanner` trait + `TcpPortScanner` (bounded worker pool, `connect_timeout`).
- [x]4.6 `TcpPortScanner` integration test against a local listener (open + closed).
- [x]4.7 Refactor `IcmpDiscovery` to expose a reusable `sweep`.
  - Extracted the batched ICMP loop from `discover` into a `pub(crate)` free
    function `sweep(socket, addresses, config, events, cancel)` in `discovery.rs`.
    It owns the loop, `HostDiscovered`/`Progress` emission, `Cancelled` on cancel,
    and the socket-error path; it never emits `Started`/`Finished`.
  - Returns `DiscoveryOutcome::Completed(Vec<Host>)` (up-hosts, arrival order) or
    `DiscoveryOutcome::Cancelled` (unit: the caller stops, so partial hosts are dropped).
    (Renamed from `SweepOutcome` in 4.9a; now `pub` and re-exported from `scanner`.)
  - `discover` is now the unframed core: it opens the raw ICMP socket, runs `sweep`,
    and returns `Result<DiscoveryOutcome, ScanError>`. The run framing (`Started` and
    the terminal `Finished`/`Cancelled`) is owned by `run_scan` (4.8/4.9b), not by
    `discover` (`discovers_localhost` still passes).
- [x]4.8 `run_scan` orchestrator (discovery + ports, single `Started`/`Finished`).
  - Added `pub fn run_scan(target, discovery, ports, events, cancel)` in `scanner/mod.rs`.
  - Opens the socket before announcing (so a socket failure is an `Error` event, not a
    half-started scan), then emits one `Started{total}`.
  - Calls `discovery::sweep`; on `Completed(up_hosts)` it port-scans each host via
    `TcpPortScanner::scan` with a cooperative cancel check before each host, and one more
    check after the loop so a cancel that landed during the final host reports `Cancelled`
    rather than `Finished`. On `Cancelled` the sweep already reported it, so it stops.
  - A loopback test asserts exactly one `Started`/`Finished` pair, the host up, and one
    `PortDiscovered` per probed port.
  - (4.9b) `run_scan` is now the generic 7-arg orchestrator; it no longer opens the socket
    or calls `sweep` directly — `discover` opens the socket and runs `sweep`, and `run_scan`
    calls `discover` then port-scans via `P`. The single-`Started`/`Finished` framing above
    still holds, but is now owned by `run_scan` alone.
- [x]4.9 CLI `--ports`/`--profile` (default Quick; Full requires explicit selection) wired into `main`.
  - Split into three commit-ready sub-tasks (4.9a/b/c), each committed separately so the app
    kept compiling and working at every step.
  - 4.9a `refactor(scanner)`: `discover` returns `Result<DiscoveryOutcome, ScanError>`
    (renames `SweepOutcome` → `pub enum DiscoveryOutcome`, re-exported from `scanner/mod.rs`);
    `discover` still opens the socket, emits `Started`, and emits `Finished`/`Cancelled`, and
    `run_scan`'s match arms are renamed. `main.rs` untouched (the TUI still gets `Finished`).
  - 4.9b `refactor(scanner)`: `run_scan<D: HostDiscovery, P: PortScanner>` becomes a 7-arg
    orchestrator (calls `discovery.discover()`, port-scans each host, emits the terminal
    `Finished`/`Cancelled` itself); `discover` drops `Started` and `Finished` (now the
    unframed core returning `Result<DiscoveryOutcome, ScanError>`); `main` is rewired
    to `run_scan(..., &IcmpDiscovery, &PortConfig::default(), &TcpPortScanner, ...)`, so the
    app actually port-scans while the TUI still receives its `Finished`.
  - 4.9c `feat(cli)`: `--ports`/`--profile` flags + `resolve_port_config` (precedence
    `--ports` > `--profile` > Quick default) + `PortProfile: FromStr`; `main` validates
    `--ports` in the linear flow and passes the resolved `PortConfig` to `run_scan`.
    Also removes `PortSpec::is_full` (test-only, no Phase-4 consumer).
- [x]4.10 TUI: record open ports on the host + OPEN PORTS column.
- [x]4.11 TUI: live port progress.
- [x]4.12 Update `PLAN.md`.

## Notes

- **Scan mechanism:** TCP connect scan — `TcpStream::connect_timeout` per port; a
  successful connect means `Open`, any error (refused or timeout) means `Closed`. No raw
  sockets or privileges required.
- **Concurrency model:** `TcpPortScanner` runs a bounded worker pool over the target's
  port set (`PortConfig::concurrency`, default `DEFAULT_CONCURRENCY` = 128); ports are
  drawn from a shared queue, so concurrency never scales with target size. Cancellation
  is checked before each host and between port batches.
- **Port configuration:** `--ports` (comma/range list) and `--profile` (quick/common/full)
  resolve via `resolve_port_config` with precedence `--ports` > `--profile` > Quick default.
  `Full` (1–65535) is reachable only by explicit selection. `PortConfig` defaults to the
  Quick profile with a 300ms timeout (`DEFAULT_TIMEOUT`).
- **Event emission:** a `PortDiscovered { ip, port, state }` event is emitted for every
  probed port (open **and** closed), so the scanner reports the full picture even though
  the TUI records only open ports in the OPEN PORTS column.
- **TUI live port progress:** the TUI derives global port progress by counting
  `PortDiscovered` events against `up_count() × ports_per_host` (passed in from `main` as
  `port_config.ports.len()`). Because every `HostDiscovered` precedes every
  `PortDiscovered`, `up_count()` is stable across the port phase and the total is exact.
  The `Ports: probed/total` line appears once the first port is probed and stays accurate
  through `Finished`/`Cancelled`.
- **Reachability / warnings:** with the CLI wired (4.9), the TUI recording open ports
  (4.10), and live port progress (4.11), `run_scan`, the `TcpPortScanner`/`PortScanner`
  items, `Host::add_open_port`, the `ScanEvent::PortDiscovered` fields, and
  `PortSpec::len` (consumed by `main` via `port_config.ports.len()`) are all
  reachable/consumed. The TUI test module constructs `App` with struct-update syntax
  (e.g. `App { hosts, ..Default::default() }`) so `cargo clippy --all-targets` is
  warning-free.
- **Verified:** `cargo fmt --check` (clean), `cargo check` (no warnings), `cargo test`
  (110 passed), `cargo clippy --all-targets` (no warnings), `cargo build` (clean), and a
  PTY smoke test scanning `127.0.0.1` (the open port is recorded in the OPEN PORTS column
  and the live `Ports:` progress reaches `18/18`).

---

# 11\. Phase 5 — Scanner Configuration

Create a scan configuration model.

Conceptually:

```
struct ScanConfig {
    target: ScanTarget,
    discovery: DiscoveryConfig,
    ports: PortConfig,
    timeout: Duration,
    concurrency: usize,
}
```

The configuration should be usable without the TUI.

Initial configurable properties:

- Target.
- Discovery method.
- Port list/profile.
- Timeout.
- Concurrency.

Use sensible defaults.

Avoid exposing every internal scanner option to users initially.

## Tasks

- [x]5.1 `ScanConfig` model bundling `target`, `discovery`, and `ports`.
- [x]5.2 `ScanConfig::new` (sensible per-stage defaults); `run_scan` refactored to take `&ScanConfig`.
- [x]5.3 Wire `main` to build a `ScanConfig` and pass `&config` to `run_scan`.
- [x]5.4 Tests: `ScanConfig::new` defaults + `run_scan` framing via a `ScanConfig`.
- [x]5.5 Update `PLAN.md`.
- [x]5.6 Make the scan timeout user-configurable from the CLI. A `--timeout`
  flag was added; a bare number is milliseconds and `ms`/`s`/`m` suffixes are
  accepted. It is applied to both the discovery and port stages (mirrored into
  `DiscoveryConfig::timeout` and `PortConfig::timeout`); concurrency remains
  fixed at `DEFAULT_CONCURRENCY`.

## Notes

- **No top-level `timeout`/`concurrency`:** the conceptual sketch above lists top-level
  `timeout` and `concurrency`, but `DiscoveryConfig` and `PortConfig` each already own a
  `timeout` + `concurrency`. Storing them again at the top level would duplicate state and
  be ambiguous (which stage does a top-level value apply to?). `ScanConfig` therefore keeps
  only `target` plus the two stage configs; each stage's timeout/concurrency is configured
  on that stage (`DiscoveryConfig::timeout`/`concurrency` for discovery,
  `PortConfig::timeout`/`concurrency` for ports). This is a deliberate deviation from the
  conceptual sketch.
- **Discovery method stays a generic param:** the discovery _method_ (a
  `D: HostDiscovery` strategy) is passed to `run_scan` as a generic parameter rather than
  stored in `ScanConfig`. There is currently a single stateless method (`IcmpDiscovery`),
  so storing an enum in the config would be premature. When a second method lands (e.g.
  ARP), the choice can be promoted into `ScanConfig` then.
- **No `Default` on `ScanConfig`:** `ScanTarget` has no `Default` (a target is always
  required), so `ScanConfig` derives `Debug, Clone, PartialEq, Eq` and offers
  `ScanConfig::new(target)` to fill in `DiscoveryConfig::default()` and
  `PortConfig::default()`.
- **`run_scan` signature:** now
  `run_scan<D: HostDiscovery, P: PortScanner>(config: &ScanConfig, discovery, port_scanner, events, cancel)`;
  it reads `config.target` for the `Started { total }` count, and `config.discovery` /
  `config.ports` for the stage tunables. The single `Started`/`Finished` framing and the
  early-return `Cancelled`/`Finished` path are preserved.
- **TUI interface unchanged:** the TUI still takes `target` (for display) and
  `ports_per_host` (for progress), not the whole `ScanConfig` — it does not need the stage
  configs.
- **Verified:** `cargo fmt --check` (clean), `cargo check` (no warnings), `cargo test`
  (111 passed), `cargo clippy --all-targets` (no warnings), `cargo build` (clean).

---

# 12\. Phase 6 — TUI Application State

Create a central application state model.

Conceptually:

```
struct App {
    scan: ScanState,
    hosts: Vec<Host>,
    selected_host: Option<usize>,
    filter: Option<String>,
    should_quit: bool,
}
```

The exact representation can evolve.

The TUI should consume `ScanEvent`s and update state.

The TUI must not directly perform network operations.

## Tasks

- [x]6.1 Verify `App` is the single central state: it consumes `ScanEvent`s via
  `apply_event`, holds no scan logic of its own, and the TUI performs no network
  operations.
- [x]6.2 Add `selected_host: Option<usize>` to `App`, with an in-range
  `selected()` accessor for the host detail screen (Phase 8).
- [x]6.3 Add `filter: Option<String>` to `App`; stored for the interactive filter
  (Phase 9), not yet applied to the displayed host list.
- [x]6.4 Tests for the new state fields (defaults, in-range selection,
  out-of-range/empty selection, filter stored and cleared).
- [x]6.5 Update `PLAN.md`.

## Notes

- **Navigation, detail rendering, and filtering belong to later phases:**
  keyboard navigation (Phase 7), the host detail screen (Phase 8), and applying
  the filter to the displayed list (Phase 9) are out of scope here. Phase 6 only
  introduces the state those phases will read and write.
- **`selected_host` is an index into `hosts`:** hosts are only ever appended, so
  an in-range index stays valid for the life of the current results.
  `App::selected()` returns the host at that index, or `None` when no host is
  selected or the index is out of range.
- **`filter` is stored but not yet applied:** the value round-trips through the
  state unchanged; applying it to the displayed host list is Phase 9.
- **Staged code carries `#[allow(dead_code)]`** until Phases 7–9 consume the new
  fields and `selected()`; remove the attributes when that happens.
- **Verified:** `cargo fmt --check` (clean), `cargo check` (no warnings),
  `cargo test` (116 passed), `cargo clippy --all-targets` (no warnings),
  `cargo build` (clean).

---

# 13\. Phase 7 — Overview Screen

Create the primary scan screen.

Display:

```
Target: 192.168.1.0/24

Hosts:
  37 up
  219 down

Progress:
  194 / 256

Elapsed:
  12.4s
```

Below the summary, display discovered hosts.

Example:

```
IP              STATE       LATENCY
192.168.1.1     UP          1.2 ms
192.168.1.10    UP          2.1 ms
192.168.1.20    UP          0.8 ms
192.168.1.42    UP          3.4 ms
```

## Keyboard navigation

At minimum:

```
↑ / k       Move up
↓ / j       Move down
Enter       Open host
r           Rescan
/           Filter
?           Help
q           Quit
```

Follow normal terminal/TUI conventions where possible.

## Tasks

- [x]7.1 Render the scan summary: the target, host up/down counts, progress
  (`completed / total`, shown only while a scan is running), and elapsed time.
- [x]7.2 Render the discovered-host list below the summary (IP, state, latency),
  with a leading selection column.
- [x]7.3 Move the host selection with `↑`/`k` and `↓`/`j`; a stale out-of-range
  index is clamped into range before stepping.
- [x]7.4 Keep the selected row visible (scroll-to-selection) and mark it with a
  `▸` prefix and reversed styling.
- [x]7.5 Toggle a static help overlay with `?`; while it is open only `?`/`Esc`
  close it and `q` still quits, all other keys are ignored.
- [x]7.6 Track scan elapsed time: record the start instant on `Started` and freeze
  the total duration when a terminal state (`Finished`/`Cancelled`/`Failed`) is
  reached.
- [x]7.7 Tests for selection movement, the help overlay, elapsed timing,
  `format_duration`, `window_start`, and `down_count`.
- [x]7.8 Update `PLAN.md`.

## Notes

- **Only the keys that belong to this phase are wired up:** `Enter` (open the
  selected host) is Phase 8, `/` (filter) is Phase 9, and `r` (rescan) is Phase 10.
  The plan's keyboard section lists them, but their handlers are intentionally
  not implemented yet and the `?` help overlay lists only the keys that work.
- **`move_selection` anchors at the end you move towards:** with no current
  selection, the first `↓` selects the first host and the first `↑` selects the
  last. An existing selection steps by one, clamped at both ends; a stale
  out-of-range index is first clamped into range.
- **Elapsed time is testable:** `App::elapsed(now)` takes the reference instant as
  a parameter. While a scan runs it is `now - started_at`; after a terminal state
  the frozen total (`scan_duration`) is returned regardless of `now`, so a
  finished scan keeps showing its real duration.
- **Progress counts live only in the `Scanning` variant:** `completed`/`total` are
  shown only while a scan is running; the `ScanState` shapes are unchanged from
  Phase 6.
- **Verified:** `cargo fmt --check` (clean), `cargo check` (no warnings),
  `cargo test` (137 passed), `cargo clippy --all-targets` (no warnings),
  `cargo build` (clean).

---

# 14\. Phase 8 — Host Detail Screen

Selecting a host should display detailed information.

Initial version:

```
Host
────────────────────────
IP          192.168.1.42
State       UP
Latency     3.4 ms

Ports
────────────────────────
22/tcp      OPEN
80/tcp      OPEN
443/tcp     CLOSED
```

Future fields:

```
Hostname
MAC address
Vendor
Services
TLS information
```

Do not display information that has not actually been discovered.

## Tasks

- [x]8.1 Store the state of every probed port on `Host`: new `ProbedPort { port,
state }` (kept sorted ascending by port, unique) with `Host::add_probed_port`,
  recording both open and closed results.
- [x]8.2 `Enter` opens the host detail screen when a host is selected (no-op for
  a missing or stale selection): a `Host` block (IP, state, latency) and a
  `Ports` block listing every probed port with the state its probe found, or `-`
  when no ports were probed.
- [x]8.3 Gate keys while the detail screen is open: only `Esc` (back) and `q`
  (quit) act; navigation, cancel, help, and `Enter` are ignored.
- [x]8.4 Context-sensitive bottom hint: the detail screen shows `Esc Back  q
Quit`; the overview key list gains `Enter Detail`.
- [x]8.5 `format_open_ports` filters to ports probed open, so the overview's
  OPEN PORTS column keeps showing only open ports (e.g. `22,80,443`).
- [x]8.6 Tests: `Enter`/`Esc`/key gating (including a stale selection),
  recording closed port results, and `format_open_ports` excluding closed ports.
- [x]8.7 Update `PLAN.md`.

## Notes

- **Display scope:** `Host.ports` stores every probed port with its state, not
  only open ones — a closed result is a legitimate discovery, and the detail
  screen is where it is shown. The overview's OPEN PORTS column is unchanged in
  appearance and still lists only ports probed open (the `format_open_ports`
  filter).
- **No auto-selection:** `apply_event` does not select a host on
  `HostDiscovered`; the Phase 7 anchoring behavior (the first `↓` selects the
  first host) is unchanged. The spec only requires the detail "when a host is
  selected," and auto-selecting would change overview behavior beyond this
  phase.
- **Detail layout:** lines are padded with `{:<12}` to match the plan's mockup
  (`IP          192.168.1.42`). Port states are uppercased only locally in the
  detail screen (`OPEN`/`CLOSED`); `PortState::Display` stays lowercase.
- **`ProbedPort` lives in `network/port.rs`** (re-exported from `network`),
  keeping the model self-contained; no TUI types leak into network code.
- **Verified:** `cargo fmt --check` (clean), `cargo check` (no warnings),
  `cargo test` (145 passed), `cargo clippy --all-targets` (no warnings),
  `cargo build` (clean); a PTY smoke test (pyte terminal emulation) confirmed
  the rendered detail screen — Host and Ports blocks, context-sensitive hint,
  `j`/`c` ignored while open, and `Esc` returning to the overview with the
  selection preserved.

---

# 15\. Phase 9 — Filtering

Implement interactive filtering.

Minimum requirement:

```
/ ssh
/ 192.168.1.42
/ up
```

The first implementation can use simple substring matching.

Potential future query syntax:

```
state:up
port:22
port:443
service:http
ip:192.168.1.*
```

Do not implement a complex query language until simple filtering proves insufficient.

Filtering should operate on the UI model and must not trigger a new scan.

## Tasks

- [x]9.1 Filter state on `App`: committed `filter: Option<String>` (`None` = no
  filter) plus private `filter_input: String` and `filter_mode: bool` for the
  interactive input mode.
- [x]9.2 `/` enters filter input mode (not gated on scan state, so filtering
  works while a scan runs); in input mode `Char` appends, `Backspace` deletes,
  `Enter` commits (an empty buffer commits `None`), and `Esc` discards the
  buffer while keeping the committed filter.
- [x]9.3 `host_matches(host, needle)`: case-insensitive substring match against
  the host's IP, its state string, and every probed port number; an empty
  needle matches every host.
- [x]9.4 Live preview: `effective_filter()` prefers a non-empty `filter_input`
  over the committed filter, so the table filters as the user types.
- [x]9.5 Selection anchoring: `move_selection(direction)` steps within the
  _visible_ hosts (clamped at the ends); if the selection is not visible it
  anchors to the first (`> 0`) or last (`< 0`) visible host. `sync_selection`
  clears a selection hidden by the filter.
- [x]9.6 `Esc` in the overview clears the committed filter; context-sensitive
  bottom hint: `Filter: <input>` while typing, `Filter: <f>  / Edit  Esc Clear
...` when committed, the default key list (with `/ Filter`) otherwise.
- [x]9.7 No-match message: when a filter is active and nothing matches, the
  table area renders `No hosts match the filter.`
- [x]9.8 Tests: input mode (commit, discard, empty commit), `host_matches`
  (ip/state/port, case-insensitivity, empty needle), live preview, selection
  anchoring and clamping, selection clearing, and the no-match rendering.
- [x]9.9 Update `PLAN.md`.

## Notes

- **Match scope:** IP, host state, and probed port numbers (as decimal
  strings). Service names are not matched yet: `/ ssh` deliberately matches
  nothing until Phase 17 adds service detection. The spec's `/ 192.168.1.42`
  and `/ up` examples work as-is.
- **No new scan:** filtering only changes which hosts the TUI renders; the
  scanner is untouched, satisfying "must not trigger a new scan".
- **Filtering during a scan:** because `/` is not gated on scan state, results
  keep streaming into the filtered view; `sync_selection` runs on every input
  change so the selection can never point at a hidden row.
- **Selection safety:** the committed filter is only ever applied to an
  already-consistent selection (`/` is pressed from a valid selection and
  hosts only get added while scanning), so `sync_selection` is needed on
  input changes, not on `Enter`/`Esc`.
- **Verified:** `cargo fmt --check` (clean), `cargo check` (no warnings),
  `cargo test` (167 passed), `cargo clippy --all-targets` (no warnings),
  `cargo build` (clean); a PTY smoke test with a minimal VT emulator confirmed
  the full flow — live preview hint, committed hint, `Esc` clears the filter,
  the no-match message, `Esc` in input mode discarding the buffer, and a clean
  `q` quit. (Byte-stream matching is unreliable here: ratatui's diff renderer
  emits only changed cells, so complete hint strings never appear verbatim.)

---

# 16\. Phase 10 — Scan Lifecycle

Implement proper scan lifecycle handling.

States:

```
Idle
Starting
Discovering
ScanningPorts
Completed
Cancelled
Error
```

The user must be able to:

- Start a scan.
- Cancel a scan.
- Return to results.
- Start another scan.

Cancellation must propagate to scanner tasks.

No orphaned network tasks should remain after cancellation.

## Tasks

- [x]10.1 `ScanState` enum with the seven plan states (`Idle`, `Starting`,
  `Discovering { completed, total }`, `ScanningPorts`, `Completed`,
  `Cancelled`, `Error`), a `label()` for the title row, and `is_active()` to
  gate the `c`/`r` keys.
- [x]10.2 Scan lifecycle fields on `App`: `scan`, `started_at`,
  `scan_duration`, `scan_error: Option<String>` (message for the `Error`
  state), and `rescan_requested`.
- [x]10.3 Event → state transitions in `apply_event` (the single place they
  happen): `Started` → `Discovering` (recording the total and start instant),
  the first `PortDiscovered` → `ScanningPorts`, and `Finished`/`Cancelled`/
  `Error` → their terminal states via `end_scan` (which freezes
  `scan_duration`). `Progress` only updates the discovery counts while
  still discovering.
- [x]10.4 `c` key: while a scan is active it only raises the shared
  cancellation flag; the scanner's `Cancelled` event performs the terminal
  state transition, keeping the TUI event-driven.
- [x]10.5 `r` key: when no scan is active it sets `rescan_requested`; the
  event loop consumes the flag and starts a new scan — so a rescan works
  after completion, after cancellation, and after an error.
- [x]10.6 `start_scan`: resets the host list, selection, error text, port
  count, and elapsed-time state, lowers the cancellation flag (a prior scan
  may have left it raised), and launches the scanner through a
  `ScanSpawner` closure.
- [x]10.7 Restructure `run`/`run_loop`: the `ScanConfig`, spawner, master
  event sender, and cancellation flag are owned by the caller rather than
  stored on `App` (the app stays a plain `Debug`/`Default` data container);
  the first scan launches when a target is present and rescans launch from
  the loop. The master sender lives for the TUI's whole lifetime, so the
  channel stays open between scans.
- [x]10.8 Status display: the phase label renders right-aligned in the title
  row; `Error: {message}` is appended to the summary line while
  `scan_error` is set.
- [x]10.9 Rebuild `main`: build the `Option<ScanConfig>` and a
  `ScanSpawner`, and hand them (with the master sender, event receiver, and
  cancellation flag) to `tui::app::run`; a missing target simply means no
  scan starts.
- [x]10.10 Document `r Rescan` and `c Cancel` in the `?` help overlay.
- [x]10.11 Tests: the first `PortDiscovered` transitioning to
  `ScanningPorts`, subsequent ports keeping that state, `Progress` being
  ignored during port scanning, and the `r` key being accepted only when no
  scan is active (idle and after a scan ends, rejected while active).
- [x]10.12 Update `PLAN.md`.

## Notes

- The TUI never mutates scan state when the user cancels: `c` only sets the
  shared flag and the scanner's `Cancelled` event performs the transition,
  so state changes stay exclusively event-driven (per AGENTS.md).
- Cancellation propagates through the scanner's own checks (between
  discovery batches and before each host's port scan); in-flight
  connections are allowed to finish and no tasks outlive the scan.
- Discovery keeps its batch window open for the full timeout even when
  replies arrive early, so even a single-host scan takes roughly the
  discovery timeout (~300 ms by default) — a comfortable, reliable window
  to cancel mid-scan.
- `start_scan` lowers the cancellation flag because a previous scan may have
  left it raised (e.g. after a cancel), so every new scan starts from a
  clean slate.
- **Verified:** `cargo fmt --check` (clean), `cargo check` (no warnings),
  `cargo test` (172 passed), `cargo clippy --all-targets` (no warnings),
  `cargo build` (clean); a PTY smoke test with a minimal VT emulator
  confirmed the full lifecycle — the initial CLI scan reaching COMPLETED,
  `r` then `c` mid-scan producing CANCELLED, `r` after cancellation reaching
  COMPLETED again, and a clean `q` exit (status 0).

---

# 17\. Phase 11 — JSON Export

Add export functionality.

Example:

```
port-scanner scan 192.168.1.0/24 --json
```

or from the TUI:

```
e → Export JSON
```

The exported format should contain structured scan information.

Example:

```
{
  "target": "192.168.1.0/24",
  "hosts": [
    {
      "ip": "192.168.1.1",
      "state": "up",
      "latency_ms": 1.2,
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open"
        }
      ]
    }
  ]
}
```

The exact schema should be treated as a versioned public format once released.

## Tasks

- [x]11.1 Dedicated serde export types in a new `src/export.rs` module:
  `ExportDocument`, `ExportHost`, and `ExportPort`. The network model itself
  carries no serde derives — the JSON document is the application's export
  format and is owned by the export module so it can be versioned
  independently of the internal model.
- [x]11.2 `ExportDocument::from_scan`: converts the target plus discovered
  hosts into the export format — lowercase states (`"up"`/`"down"`,
  `"open"`/`"closed"`), latency in milliseconds, and an explicit
  `protocol: "tcp"` on every port.
- [x]11.3 `latency_ms` is an `f64` omitted entirely for down hosts
  (`skip_serializing_if`), so a down host serializes as
  `{"ip", "state": "down", "ports": []}` with no latency key.
- [x]11.4 Deterministic file naming: base name `port-scanner-export.json`
  (no clock or timezone), and the file is never overwritten — an existing
  file causes the numeric suffix to increment
  (`port-scanner-export-2.json`, `-3.json`, ...).
- [x]11.5 `export_to(dir, …)` writes pretty-printed JSON into an explicit
  directory (testable); `export(…)` is the cwd wrapper the TUI uses.
- [x]11.6 TUI: the `e` key in the overview context exports the current
  results whenever a target exists (it also works while a scan is running,
  exporting whatever has been discovered so far); without a target it is a
  no-op. The result shows on the status line as `Exported <path>` or
  `Export failed: <error>`, and `start_scan` clears a stale export status.
  In filter mode `e` is typed into the filter input, not exported.
- [x]11.7 Document `e Export` in the hint line and the `?` help overlay.
- [x]11.8 Tests: the JSON shape matches the plan example exactly (lowercase
  states, `protocol`, millisecond latency), `latency_ms` is absent for down
  hosts, the filename suffix increments on collision, `export_to` writes
  valid JSON without overwriting an existing file, and the TUI treats `e` as
  a no-op without a target and as filter input while filtering.
- [ ]11.9 Headless CLI `--json` mode: run a scan from the command line and
  write the same JSON document to a file or stdout without launching the
  TUI. Deferred — the TUI route (`e`) is sufficient for the MVP.
- [x]11.10 Update `PLAN.md`.

## Notes

- **Scope decision:** the plan's example shows a headless CLI invocation
  (`port-scanner scan … --json`); only the TUI route was implemented. The
  headless CLI mode is recorded as task 11.9 and is not required for the MVP
  ("Results can be exported as JSON" is satisfied by the TUI export).
- The network model deliberately has no serde derives: the export types are
  a separate public contract, so changing internal field types or names does
  not silently change the exported format.
- Host state must not be reused from `HostState`'s `Display` (uppercase
  `"UP"`/`"DOWN"`); the export conversion maps the enum explicitly to the
  lowercase strings the format specifies.
- Export writes to the process's current working directory; the file name
  carries no timestamp, so repeated exports are distinguished only by the
  incrementing suffix.
- **Verified:** `cargo fmt --check` (clean), `cargo check` (no warnings),
  `cargo test` (180 passed), `cargo clippy --all-targets` (no warnings),
  `cargo build` (clean); a PTY smoke test with a minimal VT emulator
  confirmed the full flow — a CLI-targeted scan reaching COMPLETED, `e`
  producing `Exported <path>` on the status line and a file whose JSON
  matches the plan's shape (`target`, one `up` host with `latency_ms`, both
  requested ports with `protocol: "tcp"`), a second `e` creating
  `port-scanner-export-2.json` without overwriting the first, and a clean `q`
  exit (status 0).

---

# 18\. Phase 12 — Service Detection

After basic scanning is stable, add service detection.

Start conservatively.

Initial detectors:

- HTTP.
- HTTPS/TLS.
- SSH.

Possible later detectors:

- FTP.
- SMTP.
- DNS.
- SMB.
- RDP.

Service detection should be modular.

Conceptually:

```
trait ServiceDetector {
    async fn detect(
        &self,
        host: &Host,
        port: &Port,
    ) -> Result<Option<ServiceInfo>, ServiceError>;
}
```

Do not make service detection mandatory for basic port scanning.

## Tasks

- [x]12.1 `ServiceInfo` in a new `src/network/service.rs` module: `name`
  (e.g. `"http"`), optional `version`, optional `extra` (e.g. the HTTP status
  line), plus a `ServiceInfo::new(name)` helper; registered and re-exported
  from `src/network/mod.rs`.
- [x]12.2 `ProbedPort` gains a `service: Option<ServiceInfo>` field. `new`
  keeps its 2-argument signature (it sets `service: None` and stays a
  `const fn`), so no existing call site changes; `ProbedPort` drops `Copy`
  and `Hash` because the field is not `Copy`.
- [x]12.3 `ServiceDetector` trait and `ServiceError` in a new
  `src/scanner/services.rs` module. `detect(&self, ip: Ipv4Addr, port: Port)`
  is synchronous, matching the scanner's thread-based design; `Ok(None)`
  means "not this service"; a detection failure must never fail the scan.
- [x]12.4 HTTP detector: sends `GET / HTTP/1.0` with a `Host:` header and
  claims the port when the response starts with `HTTP/`; the status line goes
  into `extra`.
- [x]12.5 HTTPS/TLS detector: sends a hand-crafted minimal TLS 1.0
  ClientHello and claims the port when the first reply is a TLS record
  (byte `0x16`) carrying a ServerHello (handshake type `0x02`).
- [x]12.6 SSH detector: reads the server banner and claims the port when it
  starts with `SSH-2.0` or `SSH-1.99`; the software token goes into
  `version`.
- [x]12.7 `default_detectors()` returning the HTTP, HTTPS, and SSH
  detectors, each probe bounded by a ~2 s timeout so a slow or silent port
  cannot stall the scan.
- [x]12.8 `PortScanner::scan` returns `Result<Vec<Port>, ScanError>` — the
  ports found open, sorted ascending — instead of `()`. Update
  `TcpPortScanner` (collect results, sort at the end) and its tests.
- [x]12.9 `ScanEvent::ServiceDiscovered { ip, port, service }` variant.
- [x]12.10 `ScanConfig` gains `detect_services: bool`, defaulting to `true`
  (service detection is on by default, consistent with
  target → hosts → services).
- [x]12.11 `run_scan` takes `detectors: &[Box<dyn ServiceDetector>]` (the
  trait declares `Send + Sync` supertraits, which is all `run_scan` needs for
  the host's scan thread) and, for each up host, runs them over that host's
  open ports right after its port scan (interleaved per host, sequential per
  port, bounded). Cancellation is checked between probes; a detector failure
  is dropped, not propagated.
- [x]12.12 CLI: a `--no-services` flag disables detection; the spawner
  captures `default_detectors()` and passes them to `run_scan`.
- [x]12.13 TUI: `apply_event` handles `ServiceDiscovered` by attaching the
  service to the host's open `ProbedPort`. No scan-state transition and no
  change to `ports_probed`.
- [x]12.14 TUI: the host detail port lines show the detected service name;
  the host table keeps showing port numbers only.
- [x]12.15 TUI: `host_matches` also matches service names
  case-insensitively; update the filter test that previously asserted `"ssh"`
  did not match.
- [x]12.16 Tests: each detector against a local fake TCP server, the
  ClientHello byte prefix, `run_scan` with detection on and off using a fake
  detector (no network), and TUI attach/filter behavior.
- [x]12.17 Verify: `cargo fmt --check`, `cargo check`, `cargo test`,
  `cargo clippy --all-targets`, and a PTY smoke test — a local HTTP server
  plus a scan of 127.0.0.1 shows the service on the host detail without
  disturbing port progress.
- [x]12.18 Update `PLAN.md`.

## Notes

- The conceptual sketch above shows `async fn detect(&self, host: &Host,
  port: &Port)`. The implementation is synchronous
  (`fn detect(&self, ip: Ipv4Addr, port: Port)`), matching the scanner's
  thread-based design, and passes the address rather than the whole `Host`
  because a detector only needs the destination.
- Every probe sets a read timeout before its I/O, and `io_error` maps both
  `ErrorKind::TimedOut` and `ErrorKind::WouldBlock` to
  `ServiceError::Timeout`: on this Linux toolchain a timed-out read on a
  timeout-armed socket surfaces as `WouldBlock` (EAGAIN) rather than
  `TimedOut`.
- The TLS ClientHello is hand-crafted (TLS 1.0, a fixed zeroed 32-byte
  random, the single cipher suite `0x002f`) so no `rand` dependency is
  needed. The HTTPS detector matches strictly on record byte `0x16` plus
  handshake type `0x02`; a TLS fatal alert (`0x15`) is deliberately not
  claimed as TLS, keeping detection conservative.
- The spawner is a `Fn` closure invoked for the initial scan and every
  rescan, and the detector `Vec` is not `Clone`, so `build_spawner` wraps
  `default_detectors()` in an `Arc` and clones it per invocation, moving
  each clone into the scan thread.
- TUI attach is a plain double `find` (host by IP, then port) with no new
  `App` state; an unknown host or unprobed port is silently ignored. The
  filter matches detected service names (name only, not version or extra).
- The `run_scan` detection tests are hermetic: `FakeDiscovery` and
  `FakePortScanner` stand in for ICMP/bounded TCP listeners, and fake
  detectors (recognizing, no-match, failing) exercise the orchestration
  rules. Detector tests use a local fake TCP server per case.
- **Verified:** `cargo fmt --check` (clean), `cargo check` (no warnings),
  `cargo test` (207 passed), `cargo clippy --all-targets` (no warnings),
  `cargo build` (clean); a PTY smoke test with a local HTTP server on
  127.0.0.1:8080 and a scan of 127.0.0.1 (`--ports 8080`) confirmed the
  host detail shows the port row as `8080/tcp OPEN http` — detection
  attached to the discovered port without disturbing port progress, and a
  clean `q` exit followed.

---

# 19\. Phase 13 — Hostname, MAC and Vendor Information

Add optional enrichment.

## Hostname

Perform reverse DNS where appropriate.

## MAC address

Use ARP/local network mechanisms where available.

## Vendor

Map MAC OUI information to vendor.

Important:

- Treat enrichment as optional.
- Do not fail an entire scan because enrichment fails.
- Clearly distinguish discovered information from inferred information.

## Tasks

- [x]13.1 Add the `MacAddress` type in `src/network/mac.rs`: six bytes,
  `Display` as `AA:BB:CC:DD:EE:FF`, `FromStr`, OUI extraction (first three
  bytes), `is_zero()`, and `Copy`/`Eq`/`Hash` derives. Wire it into the
  `network` module.
- [x]13.2 `Host` gains `hostname: Option<String>`, `mac: Option<MacAddress>`,
  and `vendor: Option<String>`, all `None` from `Host::up`. Update the
  "intentionally omitted" doc comment to reflect that these are now optional
  enrichment fields.
- [x]13.3 Add `src/scanner/enrichment.rs`: the `HostEnricher: Send + Sync`
  trait (`fn enrich(&self, ip: Ipv4Addr) -> Result<Option<HostEnrichment>,
  EnrichmentError>`), the `HostEnrichment { hostname, mac }` carrier, and the
  `EnrichmentError { Timeout, Lookup(String) }` error — mirroring
  `ServiceDetector`.
- [x]13.4 Implement `ReverseDnsEnricher` using `libc::getnameinfo` with
  `NI_NAMEREQD` on an IPv4 `sockaddr`. Because the lookup blocks with no
  timeout, run it on a short-lived worker thread and bound it with a channel
  `recv_timeout`; a timeout or `EAI_NONAME` yields `Ok(None)`, other failures
  yield `Err(EnrichmentError)`.
- [x]13.5 Implement `ArpEnricher` reading an injectable path (default
  `/proc/net/arp`), matching the host's IP and returning its hardware
  address. Skip incomplete `00:00:00:00:00:00` entries; an unreadable or
  malformed file yields `Err(EnrichmentError::Lookup)`.
- [x]13.6 Add `vendor_for(&MacAddress) -> Option<String>` mapping the OUI to a
  vendor via the `rsmanuf` crate, returning `None` for an empty or
  `"unknown"` result (vendor is *inferred*, not discovered).
- [x]13.7 Add the `ScanEvent::HostEnriched { ip, hostname, mac, vendor }`
  variant.
- [x]13.8 `ScanConfig` gains `enrich: bool`, defaulting to `true` (enrichment
  is on by default, consistent with target → hosts → services). Update
  `ScanConfig::new`.
- [x]13.9 `run_scan` takes `enrichers: &[Box<dyn HostEnricher>]` and, for each
  up host, runs them after its port scan (interleaved per host, bounded, with
  a cancellation check before the stage). It merges any returned hostname/MAC,
  derives the vendor from the MAC, and emits `HostEnriched` only when at least
  one field is present. An enricher failure is dropped, never fatal.
- [x]13.10 CLI: a `--no-enrichment` flag disables enrichment; the spawner
  captures the default enrichers and passes them to `run_scan`.
- [x]13.11 TUI: `apply_event` handles `HostEnriched` by attaching
  hostname/mac/vendor to the matching host. No scan-state transition.
- [x]13.12 TUI: the host detail shows the enrichment, clearly labelling
  discovered information (hostname, MAC) separately from inferred information
  (vendor). The host table stays focused on port numbers.
- [x]13.13 TUI: `host_matches` also matches hostnames and vendors
  case-insensitively.
- [x]13.14 JSON export: include `hostname`, `mac`, and `vendor` on
  `ExportHost` (absent when unknown).
- [x]13.15 Tests: `MacAddress` round-trip and OUI extraction; the reverse-DNS
  and ARP enrichers against injected fixtures (no network); `vendor_for`;
  `run_scan` with enrichment on and off using a fake enricher (no network);
  and TUI attach/filter behavior.
- [x]13.16 Verify: `cargo fmt --check`, `cargo check`, `cargo test`,
  `cargo clippy --all-targets`, and a PTY smoke test confirming enrichment
  shows in the host detail without disturbing progress. Update `PLAN.md`.

- **Verified:** `cargo fmt --check` (clean), `cargo check` (no warnings),
  `cargo test` (233 passed), `cargo clippy --all-targets` (no warnings),
  `cargo build` (clean); a PTY smoke test against `127.0.0.1` (enrichment on
  by default) confirmed the scan reaches `COMPLETED` and the host detail shows
  `Hostname  localhost` from reverse DNS without disturbing port progress.
  Loopback has no ARP entry, so MAC and vendor are absent as expected.

---

# 20\. Phase 14 — Persistence

Add persistent scan storage.

Possible initial implementation:

- File storage.

Store:

```
Scan
 ├── target
 ├── timestamp
 ├── configuration
 └── hosts
      ├── host information
      └── ports
```

The storage layer must remain independent from the TUI.

---

# 21\. Phase 15 — Scan History and Diff

Allow comparison between scans.

Example:

```
NETWORK CHANGES

+ 192.168.1.73       NEW HOST
+ 192.168.1.42:8080  NEW PORT
- 192.168.1.20:445   PORT CLOSED
~ 192.168.1.10       HOST INFORMATION CHANGED
```

This should compare structured data rather than textual output.

---

# 22\. Phase 16 — Network Visualization

Add a dedicated network view.

The visualization should show discovered hosts and useful relationships.

Example:

```
                  192.168.1.1
                       │
          ┌────────────┼────────────┐
          │            │            │
     192.168.1.10  192.168.1.20  192.168.1.42
```

Important:

The application must not claim that an actual physical/network topology has been discovered unless it has supporting data.

The visualization should distinguish between:

- Known relationships.
- Inferred relationships.
- Simple subnet grouping.

A subnet view can be useful even without claiming topology.

---

# 23\. Future IPv6 Support

IPv6 should be considered in the architecture from the beginning, but does not need to be implemented in the MVP.

Avoid unnecessarily hardcoding IPv4-only assumptions into:

- Host models.
- Scan targets.
- Port models.
- Storage.
- UI rendering.

Initial implementation may explicitly reject IPv6 with a clear message.

---

# 24\. Error Handling

Errors should be structured and user-friendly.

Potential categories:

```
TargetError
DiscoveryError
ConnectionError
ScanError
ConfigurationError
StorageError
ExportError
```

The application should never panic because:

- A host is unreachable.
- A connection times out.
- A port refuses a connection.
- DNS fails.
- An optional enrichment operation fails.

Unexpected programmer errors may still panic during development, but user/network errors should be handled.

---

# 25\. Performance Requirements

The application should remain responsive during large scans.

Requirements:

- Network operations must not block the TUI.
- Concurrency must be configurable.
- Avoid spawning unbounded tasks.
- Use bounded channels/queues where appropriate.
- Avoid storing unnecessary duplicate data.
- Do not render more information than necessary for the current view.

Large subnet scans should provide continuous progress feedback.

---

# 26\. Security and Safety

This is a network scanner and must behave predictably.

Requirements:

- Make the target explicit.
- Make expensive scan modes explicit.
- Do not silently scan unrelated networks.
- Require explicit selection for full TCP scans.
- Avoid destructive network operations.
- Do not implement exploitation functionality.
- Do not send arbitrary payloads as part of the initial scanner.
- Clearly report scan configuration before execution where practical.

The tool should be designed primarily for networks the user is authorized to test.

---

# 27\. Testing Strategy

## Unit tests

Test:

- IP parsing.
- CIDR parsing.
- Port specification parsing.
- Port range expansion.
- Configuration validation.
- Filtering.
- Result serialization.
- Scan diff logic.

## Integration tests

Test:

- Scanner against controlled local test services.
- TCP port detection.
- JSON export.
- Event delivery.
- Cancellation.

## TUI tests

Where practical, test:

- State transitions.
- Selection movement.
- Filtering.
- Event handling.
- Scan completion/cancellation.

Avoid making tests dependent on a real external network.

---

# 28\. Logging and Diagnostics

The application should support optional debug logging.

Normal TUI operation should remain clean.

Possible approach:

```
RUST_LOG=debug port-scanner ...
```

When running in TUI mode, avoid writing logs directly over the terminal UI.

Consider logging to a file or only enabling detailed logs when explicitly requested.

---

# 29\. CLI Design

Initial command structure:

```
port-scanner
port-scanner scan <target>
port-scanner tui <target>
```

Possible future commands:

```
port-scanner history
port-scanner show <scan>
port-scanner diff <scan-a> <scan-b>
port-scanner export <scan>
```

Do not over-design the CLI before the core scanner works.

The default command can eventually launch the interactive TUI.

---

# 30\. Suggested MVP User Experience

A user should be able to run:

```
port-scanner 192.168.1.0/24
```

and immediately see:

```
┌─────────────────────────────────────────────────────────────┐
│ PORT-SCANNER  192.168.1.0/24                  SCANNING 42%      │
├─────────────────────────────────────────────────────────────┤
│ Hosts: 12 up / 95 scanned                                  │
├─────────────────────────────────────────────────────────────┤
│ IP              STATE       LATENCY     OPEN PORTS          │
│                                                             │
│ 192.168.1.1     UP          1.2 ms      22,80,443           │
│ 192.168.1.10    UP          2.1 ms      22,445              │
│ 192.168.1.20    UP          0.8 ms      80,443              │
│ 192.168.1.42    UP          3.4 ms      22,80               │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ ↑↓ Navigate  Enter Details  / Filter  r Rescan  q Quit     │
└─────────────────────────────────────────────────────────────┘
```

Selecting a host:

```
┌─ 192.168.1.42 ──────────────────────────────────────────────┐
│ State       UP                                              │
│ Latency     3.4 ms                                          │
│ Hostname    raspberrypi.local                               │
│                                                             │
│ PORT       STATE       SERVICE                              │
│ 22/tcp     OPEN        SSH                                  │
│ 80/tcp     OPEN        HTTP                                 │
│ 443/tcp    OPEN        HTTPS                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

# 31\. Development Order

Implement in this order:

- [x]Project bootstrap.
- [x]CLI and target parsing.
- [x]Core network data structures.
- [x]Scanner event model.
- [x]Basic host discovery.
- [x]Async/concurrent scanning.
- [x]TUI application state.
- [x]Live scan progress.
- [x]Host list.
- [x]Host detail view.
- [x]TCP port scanning.
- [x]Port profiles.
- [x]Filtering.
- [x]Cancellation.
- [x]JSON export.
- [ ]Improve error handling.
- [ ]Add tests and integration tests.
- [x]Service detection.
- [x]Hostname/MAC/vendor enrichment.
- [ ]Persistence.
- [ ]Scan history.
- [ ]Scan diff.
- [ ]Network visualization.
- [ ]IPv6.

Do not jump ahead to persistence, visualization, or service detection until the basic scanner and TUI are stable.

---

# 32\. Definition of Done for MVP

The MVP is complete when all of the following are true:

- [x]`port-scanner 192.168.1.0/24` launches the TUI.
- [x]Single IPv4 addresses can be scanned.
- [x]IPv4 CIDR subnets can be scanned.
- [x]Live hosts are discovered.
- [x]TCP ports can be scanned.
- [x]Scan concurrency is bounded.
- [x]Scan timeout is configurable.
  - The CLI `--timeout` flag sets both the discovery and port stage timeouts
    (mirrored into `DiscoveryConfig::timeout` and `PortConfig::timeout`); see
    task 5.6.
- [x]Progress is displayed in real time.
- [x]The UI remains responsive during scans.
- [x]Hosts can be selected.
- [x]Host details can be viewed.
- [x]Open ports are displayed.
- [x]Results can be filtered.
- [x]Scans can be cancelled.
- [x]A new scan can be started without restarting the application.
- [x]Results can be exported as JSON.
- [x]Network errors do not crash the application.
- [x]Core scanner functionality has automated tests.
- [x]The scanner has no dependency on the TUI.

---

# 33\. Implementation Principles for OpenCode

When implementing this plan:

1. **Work incrementally.**

Complete one phase before starting unrelated future functionality.

2. **Keep the project compiling.**

After each meaningful change, run formatting, compilation, and relevant tests.

3. **Prefer simple abstractions.**

Do not introduce traits or generic infrastructure without a concrete use case.

4. **Keep networking separate from presentation.**

The scanner should never import TUI-specific modules.

5. **Keep TUI state separate from scanner state.**

Scanner events should update application state.

6. **Use asynchronous/concurrent operations carefully.**

Never create an unbounded number of network tasks.

7. **Handle cancellation explicitly.**

A user pressing `q` or a cancellation key must not leave background scanner tasks running.

8. **Do not silently expand scan scope.**

A requested target should determine exactly what is scanned.

9. **Prefer structured data over formatted strings.**

Store IPs, ports, states, services, and timestamps as typed values.

10. **Do not implement future functionality prematurely.**

Especially avoid implementing service detection, topology inference, persistence, or IPv6 before the MVP is working.

11. **Write tests alongside functionality.**

Particularly for parsers, scanner state, filtering, serialization, and diff logic.

12. **Keep the user experience responsive.**

The TUI must remain interactive while scans are running.

13. **Document architectural decisions.**

If implementation requires deviating from this plan, update the plan or add an ADR explaining why.

14. **Never fabricate scan results.**

The UI must only display information actually reported by the scanner.

15. **Prefer platform-aware behavior.**

Network capabilities such as ICMP and ARP can differ across Linux environments. Fail gracefully and explain required permissions/capabilities when necessary.

---

# 34\. First Task for OpenCode

Start with **Phase 1 only**.

Before implementing the scanner:

1. Inspect the repository.
2. Determine whether a Rust project already exists.
3. Set up the project if necessary.
4. Select and configure the TUI framework.
5. Set up CLI argument parsing.
6. Create the initial module structure.
7. Create a minimal application state.
8. Render a basic TUI.
9. Make sure the application starts and exits cleanly.
10. Add initial tests.
11. Run formatting, compilation, and tests.

Do not implement network scanning yet.

Once Phase 1 is complete, proceed to Phase 2.
