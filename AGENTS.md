# AGENTS.md

## Project Overview

This repository contains a Rust-based Linux TUI application for network discovery and exploration.

The application is intended to:

- Scan an IPv4 address or subnet.
- Discover live hosts.
- Scan TCP ports.
- Visualize scan results in an interactive terminal UI.
- Allow users to inspect individual hosts.
- Filter and search results.
- Export results.
- Eventually provide service detection, scan history, diffs, and network visualization.

The primary product goal is:

> **Provide a fast, interactive network exploration experience from the terminal: target → hosts → services → changes.**

---

# Source of Truth

## PLAN.md is the implementation plan

Before making significant changes, read:

```
PLAN.md
```

`PLAN.md` defines:

- Project goals.
- Architecture.
- Data models.
- Development phases.
- Implementation order.
- MVP requirements.
- Acceptance criteria.
- Future functionality.

The implementation should follow `PLAN.md` unless there is a good technical reason to deviate.

If the implementation needs to deviate from the plan:

1. Understand why the deviation is necessary.
2. Prefer updating `PLAN.md` to reflect the new direction.
3. If the decision is significant, document the reasoning in the plan or an appropriate architecture decision document.
4. Do not silently ignore planned requirements.

---

# IMPORTANT: Keep PLAN.md Updated

**This is a mandatory part of the development workflow.**

`PLAN.md` is not a static specification. It is also the project's progress tracker.

As implementation progresses, keep the status in `PLAN.md` accurate.

For example, when a task is completed:

```
- [ ] Implement target parsing.
```

must become:

```
- [x] Implement target parsing.
```

Do this **during development**, not only when the entire phase is finished.

## Status requirements

After completing a meaningful task:

1. Update the relevant checkbox in `PLAN.md`.
2. Update phase status if the phase has progressed.
3. Add newly discovered implementation tasks when necessary.
4. Remove or revise requirements that are no longer applicable.
5. Keep the "Definition of Done" section accurate.
6. Do not mark work as complete unless it actually satisfies the requirement.

At any point, a developer should be able to open `PLAN.md` and understand:

- What has been completed.
- What is currently being worked on.
- What remains.
- Which requirements are blocked.
- Which implementation decisions have changed.

## Never let status drift

Do not leave completed work marked as incomplete.

Do not mark an entire phase complete merely because some of its tasks are done.

Do not mark a task complete if it only partially works.

If a task is partially complete, leave it unchecked and optionally add a note describing the current state.

Example:

```
- [ ] Implement TCP port scanning.
  - Basic connect scan works.
  - Cancellation still needs to be implemented.
```

---

# Development Workflow

For each task:

## 1\. Read the relevant plan

Review the appropriate section of `PLAN.md` before coding.

Understand:

- The goal.
- Requirements.
- Acceptance criteria.
- Dependencies.
- What should explicitly not be implemented yet.

## 2\. Inspect the existing code

Before changing code:

- Understand the current architecture.
- Look for existing abstractions.
- Avoid duplicating functionality.
- Check existing tests.
- Check how the current TUI and scanner state are structured.

Do not assume the repository is in the same state described by an earlier plan.

## 3\. Implement the smallest coherent change

Prefer small, incremental changes.

Do not implement several unrelated phases simultaneously.

For example, when working on target parsing, do not also implement:

- Service detection.
- Scan history.
- Network visualization.
- IPv6.

unless the current implementation genuinely requires them.

## 4\. Validate the change

After meaningful changes, run the appropriate checks.

At minimum, when applicable:

```
cargo fmt --check
cargo check
cargo test
```

For larger changes, also consider:

```
cargo clippy
```

Fix relevant warnings rather than accumulating technical debt.

## 5\. Update PLAN.md

After the implementation is verified:

- Mark completed tasks.
- Update phase progress.
- Record important discoveries.
- Add newly discovered work.

The plan must reflect the repository's actual state.

## 6\. Review the resulting architecture

Before moving to the next phase, make sure the implementation still follows the architectural principles below.

---

# Architecture Rules

## Scanner and TUI must remain separate

The scanner must not depend on the TUI.

Preferred dependency direction:

```
CLI
 │
 ▼
Scanner ───────► Network/Data Models
 │
 ▼
Scan Events
 │
 ▼
TUI
```

Avoid:

```
Scanner ───────► TUI
```

The scanner should be usable independently of terminal rendering.

---

# Structured Data Over Display Strings

Represent network information using typed Rust structures.

Prefer:

```
Host {
    ip,
    state,
    latency,
    ports,
}
```

over storing formatted strings such as:

```
"192.168.1.42 UP 3.4ms 22,80,443"
```

Formatting belongs in the presentation layer.

---

# TUI Must Not Perform Network Operations

The TUI should:

- Display state.
- Handle keyboard input.
- Send commands.
- Consume scanner events.
- Update application state.

It should not directly perform:

- ICMP probes.
- TCP connections.
- ARP requests.
- DNS lookups.
- Service detection.

Those operations belong to appropriate backend/scanner modules.

---

# Event-Driven Scanning

Scanning should produce structured events that can be consumed by the application.

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

The exact implementation may evolve.

The important properties are:

- The TUI remains responsive.
- Results can appear incrementally.
- Scanner operations are asynchronous/concurrent.
- Cancellation can propagate through the scanner.
- Scanner events are not coupled to TUI widgets.

---

# Concurrency

Network operations should be concurrent but bounded.

Never create an unbounded number of network tasks based directly on target size.

Use configurable or safely bounded concurrency.

For example:

```
Subnet
  │
  ├── Worker
  ├── Worker
  ├── Worker
  └── Worker
```

rather than spawning an uncontrolled task for every operation.

---

# Cancellation

Cancellation is a first-class requirement.

When the user cancels a scan:

- New work should stop being scheduled.
- Existing operations should be cancelled where practical.
- Background tasks should terminate.
- Channels/resources should be cleaned up.
- The TUI should return to a consistent state.

Do not implement cancellation merely as hiding the scan UI while work continues in the background.

---

# Error Handling

Network failures are normal.

The application must not crash because:

- A host does not respond.
- A TCP connection times out.
- A port refuses a connection.
- DNS resolution fails.
- An optional enrichment operation fails.

Use structured errors where useful.

Unexpected programming errors can still panic during development, but normal network/user errors must be handled gracefully.

---

# Do Not Fabricate Network Information

Only display information that was actually discovered.

For example, do not infer:

```
Vendor: Apple
```

merely because the IP address looks familiar.

Do not claim:

```
Router → Host A → Host B
```

unless the scanner has evidence supporting that relationship.

The future network visualization must clearly distinguish:

- Known information.
- Inferred information.
- Organizational/grouping information.

---

# Scan Scope

The application must never silently expand the user's requested scan scope.

If the user requests:

```
192.168.1.10
```

do not automatically scan:

```
192.168.1.0/24
```

If the user requests:

```
192.168.1.0/24
```

do not silently expand it to another subnet.

Expensive operations such as full TCP port scanning should require explicit selection.

---

# Platform Awareness

This is a Linux-first application.

However, network capabilities can depend on:

- User privileges.
- Kernel configuration.
- Network interface.
- Containerization.
- Available system capabilities.

If an operation requires additional privileges or capabilities:

- Detect the failure.
- Explain the problem clearly.
- Suggest the appropriate configuration when possible.
- Do not make the entire scanner unusable if an optional mechanism is unavailable.

---

# TUI Design Principles

The TUI should prioritize:

1. Scan progress.
2. Hosts.
3. Host details.
4. Open ports/services.
5. Filtering/search.
6. Clear keyboard navigation.

Use familiar terminal conventions.

Expected navigation includes:

```
↑ / k       Up
↓ / j       Down
Enter       Select
Esc         Back
/           Filter
r           Rescan
?           Help
q           Quit
```

Exact bindings can evolve.

The interface must remain usable while scanning.

---

# Testing

Tests should be added with functionality rather than postponed until the end.

Prioritize tests for:

- Target parsing.
- CIDR parsing.
- Port parsing.
- Port ranges.
- Configuration validation.
- Filtering.
- Application state transitions.
- Event handling.
- Serialization.
- Scan diffs.

Network integration tests should use controlled/local test services where possible.

Do not make core tests depend on arbitrary external hosts or the public internet.

---

# Dependencies

Prefer mature, focused Rust dependencies.

Before adding a dependency:

1. Check whether the functionality can reasonably be implemented with the standard library.
2. Check whether an existing dependency already provides the functionality.
3. Avoid adding large frameworks for small features.
4. Consider Linux compatibility.
5. Consider maintenance status and API stability.
6. Keep dependency count reasonable.

Do not introduce dependencies merely for convenience if they significantly complicate the architecture.

---

# Code Quality

Follow idiomatic Rust.

Prefer:

- Strong types.
- `Result` for recoverable failures.
- `Option` for optional values.
- Small focused modules.
- Clear ownership boundaries.
- Explicit state transitions.
- Descriptive names.

Avoid:

- Excessive cloning.
- Global mutable state.
- Giant functions.
- Giant application structs.
- TUI-specific types leaking into scanner code.
- Stringly typed internal state.
- Premature abstraction.

Run formatting and tests regularly.

---

# Scope Control

Do not prematurely implement future functionality.

The planned development order is:

```
1. Project bootstrap
2. Target parsing
3. Core data structures
4. Scanner events
5. Host discovery
6. Async/concurrent scanning
7. TUI state
8. Live progress
9. Host list
10. Host details
11. TCP port scanning
12. Port profiles
13. Filtering
14. Cancellation
15. JSON export
16. Error handling/tests
17. Service detection
18. Host enrichment
19. Persistence
20. Scan history
21. Scan diff
22. Network visualization
23. IPv6
```

Follow this order unless there is a strong technical reason not to.

---

# Current Task Discipline

When working on a task:

- Identify the relevant `PLAN.md` phase.
- Implement only what is necessary for that phase.
- Keep the application compiling.
- Add tests where appropriate.
- Run validation.
- Update `PLAN.md`.
- Only then move to the next task.

If a task exposes a missing prerequisite, update `PLAN.md` with the prerequisite rather than silently implementing unrelated functionality.

---

# When Requirements Are Ambiguous

Prefer the simplest implementation consistent with `PLAN.md`.

Do not invent substantial product requirements.

If a decision has significant architectural or user-facing consequences:

1. Check `PLAN.md`.
2. Inspect existing implementation.
3. Choose the least disruptive option.
4. Document the decision.
5. Update `PLAN.md` if the plan needs to change.

---

# Definition of a Completed Task

A task is complete only when:

- The implementation exists.
- The implementation works as intended.
- Relevant tests pass.
- The code is formatted.
- Relevant warnings are addressed.
- The application still builds.
- `PLAN.md` has been updated.

A code change without an updated plan is considered incomplete project work.

---

# Definition of a Completed Phase

A phase is complete only when all of its required tasks and acceptance criteria in `PLAN.md` have been satisfied.

Do not mark the phase complete merely because the application compiles.

Before checking the phase's completion status:

1. Review every task.
2. Review the acceptance criteria.
3. Run relevant tests.
4. Manually verify important user-facing behavior where appropriate.
5. Update `PLAN.md`.

---

# End-of-Task Checklist

Before considering a task finished:

```
[ ] Read relevant PLAN.md section
[ ] Implemented the requested functionality
[ ] Added/updated tests
[ ] cargo fmt
[ ] cargo check
[ ] cargo test
[ ] cargo clippy where appropriate
[ ] Reviewed for unnecessary complexity
[ ] Updated PLAN.md status
[ ] Updated PLAN.md with newly discovered work
[ ] Confirmed no unrelated functionality was introduced
```

The most important final step is:

> **Update****`PLAN.md`****so that it accurately represents the current state of the repository.**

I’d put both files at the repository root:

```
.
├── AGENTS.md
├── PLAN.md
├── Cargo.toml
└── src/
```
