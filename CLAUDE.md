# eGuard for Windows (desktop agent)

**Start here in every session: read [docs/STATUS.md](docs/STATUS.md)** (what's done, what's next, decisions waiting
on the owner, gotchas).

- **Spec (source of truth):** `C:\Users\corew\eguard\docs\desktop-agent-spec.md`
- **Build prompt (phases, non-negotiables, "ask me first" list):** `C:\Users\corew\eguard\docs\desktop-agent-prompt.md`
- **Open questions:** `C:\Users\corew\eguard\docs\desktop-agent-open-questions.md`
- **Wire reference:** `C:\Users\corew\eguard\docs\mobile-api.md` Part C, and the server code in
  `C:\Users\corew\eguard\src\app\api\device\v1\`

## How this repo is worked on

- One phase per session. At the end of a phase: update docs/STATUS.md, commit, and stop. The next phase starts in a
  new session from docs/STATUS.md.
- Don't change the server (`~/eguard`). If it's wrong or missing something, say which file and what you'd change.
- Things on the prompt's "ask me first" list wait for the owner (server/wire/spec changes, security changes on this
  PC, code signing, self-update, crates that need the network or run code at install time).

## Layout

- `crates/eguard-core`: platform-neutral (no Windows crate). Wire types, API client (`Transport` trait), rules, time
  accounting, trusted clock, signatures, removal codes, offline queue, sync state, `/report` contents, pipe messages,
  the service's sync loop (`engine`), enforcement (`enforce`: which program is which app, what to end, usage, the
  agent's screens and their words), web (`web`: the extension's store ids, fixed at build time, and how eGuard's
  entries go into browser policies others may share), eGuard's own updates (`update`: the signed manifest's checks,
  the hand-off between the service and the guard, the guard's swap/commit/rollback decision, `VERSION`).
  `#![forbid(unsafe_code)]` in its lib.rs.
- `crates/eguard-win`: `windows-sys` 0.61 (the same version `windows-service` uses). `WinHTTP`, DPAPI, atomic files,
  named pipe + DACL, clocks, device details, app scan sources (`apps`), Authenticode (embedded and catalog), change
  notifications, the crash handler (`crash`: last line in the log, no dump), processes (`process`, `etw`), sessions
  (`session`: WTS), input (`input`), the agent's Win32 screens (`ui`), the overlay's app buttons (`launch`: switch to
  or start an always-allowed app), browser policies (`browsers`: HKLM for the service, an inert HKCU copy in console
  mode), the service's DACL (`services`), the installed MSI (`msi`). The workspace denies `unsafe`; only this crate's
  FFI modules allow it.
- `crates/eguard-service`, `eguard-agent`, `eguard-guard`: the three binaries (spec section 3). The service's
  `lockdown` is removal protection: `install` (service + DACL, SafeBoot, guard task and cache, folder ACLs) and
  `purge` (takes all of it out). **Never run `eguard-service install`, `purge`, `msi-check` or the MSI on this PC:**
  they lock or remove a service, Safe Mode keys and Program Files; VM only. On the owner's PC the service runs in
  console mode (`eguard-service run`). Console mode ends programs only inside
  `--sandbox DIR` (without it, it only logs what it would end): never run it so it can end the owner's own tools.
  Browser policies on this PC are on the "ask me first" list: console mode writes them only under HKCU
  `Software\eGuard\Dev\Policies`, which no browser reads; never write HKLM policies here. The service's `update`
  downloads and checks a new version; only the real service (with the guard) installs it, so console mode never
  replaces files here. The guard swaps the program files and rolls a bad version back.
- `tools/enforce/`: stand-ins and scripts for checking enforcement by hand (`setup.ps1` makes a fake Steam CS2, an
  unsigned "Pixel Quest" and an unsigned "Pixel Browser"; `launch.ps1`, `play.ps1`, `press.ps1`, `waitoverlay.ps1`).
- `installer/`: `eguard.wxs` (WiX 5, per-machine MSI with the install/check/purge custom actions) and `build.ps1`.
  WiX 5.0.2 is a global dotnet tool here (`%USERPROFILE%\.dotnet\tools\wix.exe`; not WiX 6, which needs a fee
  agreement). Building the MSI is fine here; installing it isn't.
- `tools/vm/`: the VM test kit ([docs/VM-TESTS.md](docs/VM-TESTS.md)). `bundle.ps1` here builds
  `target\eguard-vm.zip` (with `eguard.msi`; `-Version 0.1.1` makes a newer build for the update test);
  `install.ps1`, `collect.ps1`, `reset.ps1`, `update-release.ps1` run on the VM only (never on this PC: they install
  and lock a service, or make and trust a code-signing certificate).
- `fixtures/server/`: real server responses, captured by `node tools/capture-fixtures.mjs` (needs ~/eguard's dev DB
  and a dev server; it deletes its test family afterwards). `fixtures/canonical-vectors.json`: made by
  `node tools/canonical-vectors.mjs`. Never hand-edit either.

## Commands

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
node tools/capture-fixtures.mjs        # refresh fixtures (EGUARD_URL defaults to http://localhost:3000)
node tools/dev-family.mjs create|code|show|apps|alerts|delete   # a test family for pairing this PC by hand
node tools/dev-family.mjs app NAME BLOCKED | limit GAMES 1 | protect KEY JSON | screen-time   # act as the parent
node tools/dev-family.mjs remove [now] | keep                     # the device page's removal (prints the offline code)
target\debug\eguard-service scan --catalog fixtures/server/catalog.json --verbose   # dry-run scan of this PC
target\debug\eguard-service run --sandbox %TEMP%\eguard-sandbox   # console mode; ends programs only in the sandbox
target\debug\eguard-service web                                   # the browser policies in place (reads only)
powershell -File installer\build.ps1 -Bin target\debug            # build target\eguard.msi (never install it here)
powershell -File tools\vm\bundle.ps1                              # target\eguard-vm.zip for the VM
powershell -File tools\vm\bundle.ps1 -Version 0.1.1               # target\eguard-vm-0.1.1.zip: a newer build (VM-TESTS G)
target\debug\eguard-agent preview block|overlay|warning          # look at a screen with sample words
target\debug\eguard-agent pair CODE --accounts corew              # pair; on this PC name corew (an administrator)
target\debug\eguard-agent accounts [--set NAME,NAME]              # which Windows accounts are the child's
target\debug\eguard-agent remove [CODE] --dev                     # "Remove with a code" (a window without CODE)
target\debug\eguard-agent crash panic|fault                        # crash on purpose: last line in agent.log
```

## Conventions

- Comments say why, in plain words, like the server's. Doc comments on every public item.
- `unsafe` only at FFI boundaries in the platform crate, wrapped in small safe functions with a `SAFETY` comment.
- Fail closed: no error, 401, timeout or bad signature ever lowers protection.
- Secrets (device token, removal secret) never reach logs: `Debug` impls redact them.
