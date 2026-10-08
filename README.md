# NETSCOPE

Interactive terminal network exploration: **target → hosts → services → changes.**

NETSCOPE is a Rust-based Linux TUI application for discovering and exploring
hosts on an IP address or subnet.

> **Status: Phase 1 — Project bootstrap.** The TUI starts and exits cleanly.
> Scanning, discovery, and results arrive in later phases. See [PLAN.md](PLAN.md).

## Requirements

- Linux
- Rust toolchain (`cargo`, `rustc`)

## Build

```sh
cargo build
```

## Run

```sh
cargo run -- 192.168.1.0/24
```

The minimal TUI currently renders a placeholder screen. Press `q` to quit.

## Project layout

```
src/
├── main.rs      # Entry point + CLI
└── tui/
    ├── mod.rs
    └── app.rs   # Application state + event loop
```

## Development

See [AGENTS.md](AGENTS.md) for the development workflow and [PLAN.md](PLAN.md)
for the implementation plan and progress tracker.

## License

MIT — see [LICENSE](LICENSE).
