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
- [ ]4.12 Update `PLAN.md`.

Note: with the CLI wired (4.9), the TUI recording open ports (4.10), and live port
progress (4.11), `run_scan`, the `TcpPortScanner`/`PortScanner` items,
`Host::add_open_port`, the `ScanEvent::PortDiscovered` fields, and `PortSpec::len`
(consumed by `main` via `port_config.ports.len()`) are all reachable/consumed. The TUI
test module constructs `App` with struct-update syntax (e.g. `App { hosts,
..Default::default() }`) so `cargo clippy --all-targets` is warning-free.

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

---

# 20\. Phase 14 — Persistence

Add persistent scan storage.

Possible initial implementation:

- SQLite.

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
- [ ]Host detail view.
- [ ]TCP port scanning.
- [ ]Port profiles.
- [ ]Filtering.
- [ ]Cancellation.
- [ ]JSON export.
- [ ]Improve error handling.
- [ ]Add tests and integration tests.
- [ ]Service detection.
- [ ]Hostname/MAC/vendor enrichment.
- [ ]Persistence.
- [ ]Scan history.
- [ ]Scan diff.
- [ ]Network visualization.
- [ ]IPv6.

Do not jump ahead to persistence, visualization, or service detection until the basic scanner and TUI are stable.

---

# 32\. Definition of Done for MVP

The MVP is complete when all of the following are true:

- [ ]`port-scanner 192.168.1.0/24` launches the TUI.
- [ ]Single IPv4 addresses can be scanned.
- [ ]IPv4 CIDR subnets can be scanned.
- [ ]Live hosts are discovered.
- [ ]TCP ports can be scanned.
- [ ]Scan concurrency is bounded.
- [ ]Scan timeout is configurable.
- [ ]Progress is displayed in real time.
- [ ]The UI remains responsive during scans.
- [ ]Hosts can be selected.
- [ ]Host details can be viewed.
- [ ]Open ports are displayed.
- [ ]Results can be filtered.
- [ ]Scans can be cancelled.
- [ ]A new scan can be started without restarting the application.
- [ ]Results can be exported as JSON.
- [ ]Network errors do not crash the application.
- [ ]Core scanner functionality has automated tests.
- [ ]The scanner has no dependency on the TUI.

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
