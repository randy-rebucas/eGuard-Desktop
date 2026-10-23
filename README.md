# eGuard for Windows

The desktop agent for eGuard: it runs on a child's Windows PC, pairs with the parent's dashboard, and enforces the
family's rules (app approval, time limits, bedtime, web filtering) even while the PC is offline.

The agent is being built in phases. Today it pairs, syncs, reports, and tells the parent which games and apps are
installed, but doesn't enforce anything yet; see [docs/STATUS.md](docs/STATUS.md) for what's done, what's next and what's waiting on a decision.

| Phase | What | Status |
|---|---|---|
| 1 | Core crate, no Windows APIs | Done |
| 2 | Pairing, sync and the service shell | Done |
| 3 | Scanning and identification | Done |
| 4 | Enforcement and time | Next |
| 5 | Web | |
| 6 | Removal protection and tamper | |
| 7 | Hardening and release readiness | |

## Layout

- `crates/eguard-core`: everything that doesn't touch Windows, so the Mac agent can share it. Wire types and the
  API client, canonical JSON, signature checks, offline removal codes, eGuard's trusted clock, local time in the
  family's zone, the rules engine, usage accounting, the offline queue, `/report` contents, the pipe messages, the
  service's sync loop, and the app scan's rules (`scan`: the catalog's four rules, launcher files, shortcuts, PE
  imports). No `unsafe`.
- `crates/eguard-win`: the Windows side. `WinHTTP`, DPAPI, atomic file replace, the named pipe and its permissions,
  clocks, the computer's details, and finding installed apps (registry, launchers, Store, shortcuts, user folders,
  Authenticode, version resources, change notifications). `unsafe` only here, at Win32 calls.
- `crates/eguard-service`: the Windows service (or the same work in a console, for development).
- `crates/eguard-agent`: runs in the signed-in session. For now a console that pairs the computer and shows its
  status.
- `crates/eguard-guard`: the watchdog. A stub until Phase 6.
- `fixtures/server/`: real responses from the eGuard server, used by the core's tests.
- `fixtures/canonical-vectors.json`: canonical JSON test vectors made from the server's own code.
- `tools/`: Node scripts that produce the fixtures, plus a throwaway test family for pairing by hand.
- `docs/STATUS.md`: progress, decisions for the owner, gotchas.

The spec, build plan and open questions live in the server repo (`~/eguard/docs/desktop-agent-*.md`). The spec is
the source of truth.

## Building and testing

Needs Rust 1.88 or newer (edition 2024) on Windows. Nothing else: no C compiler, CMake or Node to build.

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Tests, clippy and fmt must pass before a commit.

## Running it on a development PC

Against the local eGuard dev server (`~/eguard`, `pnpm dev`, on http://localhost:3000):

```sh
# 1. The service's work, in a console. Data goes to %LOCALAPPDATA%\eGuard\dev; nothing is installed
target\debug\eguard-service run

# 2. In a second console: a test family and a pairing code, then pair
node tools/dev-family.mjs create
target\debug\eguard-agent pair <CODE>
target\debug\eguard-agent status          # shows when the first app scan has run
target\debug\eguard-agent scan            # scan again now (at most every 2 minutes)

# 3. See the computer and its apps as the parent does, then clean up
node tools/dev-family.mjs show
node tools/dev-family.mjs apps
node tools/dev-family.mjs alerts
node tools/dev-family.mjs delete
```

To see what a scan of this PC would report, without pairing or sending anything:

```sh
target\debug\eguard-service scan --catalog fixtures/server/catalog.json [--verbose] [--trust "publisher name"]
```

It prints the `APPS_FOUND` events, then a summary. `--trust` tries a publisher as if the server's catalog listed it.

`eguard-service run --server URL` points a development build somewhere else. `eguard-service install` registers the
real Windows service (LocalSystem, auto-start, restart on failure). It needs an administrator, so use a VM, not your
own PC.

## Fixtures

Fixtures are captured, never hand-edited:

```sh
node tools/capture-fixtures.mjs   # needs ~/eguard's dev DB and a dev server (EGUARD_URL, default http://localhost:3000)
node tools/canonical-vectors.mjs
```

The capture script creates a test family, runs the whole device flow against the server, and deletes the family
afterwards.

## Ground rules

- **Fail closed.** No error, 401, timeout or bad signature ever lowers protection; the last good policy stays.
- **Secrets stay out of logs.** The device token and removal secret are redacted in every `Debug` impl, stored
  DPAPI-encrypted, and never sent over the pipe.
- **Signing keys are built in**, never fetched. Builds use the dev key unless `EGUARD_POLICY_PUBLIC_KEYS` is set at
  compile time; a release must never ship with the dev key. Release builds also need `EGUARD_SERVER_URL` and only
  talk `https://`.
- **The server isn't changed from here.** If it's wrong or missing something, it's written up in
  [docs/STATUS.md](docs/STATUS.md) for the owner.

## License

Proprietary. All rights reserved.
