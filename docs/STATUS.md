# Status

Updated 2026-10-23, end of Phase 1.

| Phase | What | Status |
|---|---|---|
| 1 | Core crate, no Windows APIs | **Done** (this commit) |
| 2 | Pairing, sync and the service shell | Next |
| 3 | Scanning and identification (spec 5, 6) | |
| 4 | Enforcement and time (spec 7, 8) | Needs a Windows 11 VM for acceptance tests 3–6 |
| 5 | Web (spec 9) | |
| 6 | Removal protection and tamper (spec 10, 11) | Needs a VM |
| 7 | Hardening and release readiness | Needs the code-signing certificate |

Phases and their "Done when" gates are in `~/eguard/docs/desktop-agent-prompt.md`.

## Phase 1: what was built

`crates/eguard-core` (package `eguard-core`, not `core`: a crate named `core` collides with Rust's built-in one, so
the prompt's `cargo test -p core` is `cargo test -p eguard-core`).

| Module | What it does |
|---|---|
| `wire` | Every device API body and answer from spec section 12, field for field. Unknown enum values fall back to `Unknown`, which rules treat strictly (unknown approval = blocked, unknown bedtime days = every day, unknown category = Other) |
| `canonical` | Canonical JSON byte-identical to the server's `canonicalJson` (UTF-16 key order, JS string escaping, JS number printing) |
| `signature` | ECDSA P-256 verification of the uninstall command (type, own deviceId, `at` within an hour of eGuard's clock) and the catalog (type, no rollback to an older version). Keys are built in (`keys.rs`), never fetched |
| `removal` | Offline removal codes (spec test vector passes), current + previous window, constant-time compare; guess limit (Q5) |
| `clock` | eGuard's clock: `serverTime` anchored to the monotonic counter; wall-clock changes detected; offline-reboot handling (Q6) |
| `localtime` | Days, weekdays and hours in the family's zone, from the IANA database bundled into the binary (jiff) |
| `rules` | Approval, per-app / category / daily limits, bedtime (port of the server's `bedtimeActive`, same test table), extra time, ALWAYS_ALLOWED; `seconds_left` for the 5- and 1-minute warnings; `screen_paused` for the overlay |
| `usage` | Foreground time per day, app and local hour (ms precision, split at hour and day boundaries, an hour capped at 60 min even when DST repeats it); `/usage` bodies |
| `queue` | Offline queue: newest usage per day, newest report per protection, events FIFO per type with `eventId`; backoff 30 s–15 min with equal jitter; 400/409 dropped; 401 keeps everything (fail closed); 429 waits ≥ 5 min |
| `state` | Applies `/sync` answers: last good policy stays on any error or 401; verified uninstall only; `minAppVersion` shows an update screen but keeps enforcing; before the first sync, new apps wait for approval |

**Verified (2026-10-23):**
- `cargo test -p eguard-core`: 64 passed (52 unit, 12 against real server fixtures).
- `cargo clippy --workspace --all-targets -- -D warnings` (pedantic on): clean. `cargo fmt --all --check`: clean.
- Fixtures are real: `tools/capture-fixtures.mjs` ran the whole flow against the dev server on :3000 (register →
  pair a WINDOWS PC → APPS_FOUND → usage with merged ids → full report → tamper → catalog → remove → keep → code
  ack → 401) and deleted its test family. The uninstall command and catalog signatures in them were made by the
  server's own `signPolicy` with its dev key, and verify in Rust.
- Dependencies: no crate needs the network at build time; build scripts are only the usual version/cfg probes
  (serde, serde_json, proc-macro2, quote, thiserror, generic-array, getrandom, zmij). The time zone database is
  bundled as data (jiff-tzdb), no build script.

## Found in the spec and the repos (for the owner)

1. **ALWAYS_ALLOWED during bedtime: the desktop spec contradicts the product.** Spec sections 7 and 8 say
   always-allowed apps stay usable at bedtime. The Apps tab (`child-forms.tsx`: "bedtime and the app's own limit
   still apply"), mobile-api C2 and child-app-spec 7 say bedtime still applies. The core follows the product
   definition (same behaviour as phones). Suggest fixing the spec's wording in 7 and 8.
2. **The browser extension's dev public key no longer matches the server's dev signing key.**
   `~/eguard-browser/.env` `VITE_POLICY_PUBLIC_KEY` is `MFkw…PPOg==`; the key derived from
   `~/eguard/.env.local` `BROWSER_POLICY_SIGNING_KEY` is `MFkw…5Q==` (keyId `60da38f4c654f71a`). A dev build of the
   extension would reject every policy from the local server. Not changed (not this repo).
3. **"Paired but unsynced" isn't in the spec.** The prompt refers to it. Chosen: before the first `/sync`, new apps
   wait for approval and no time limits apply. Pairing needs the network, and the first sync follows in seconds.
4. **A removal code still works after "Keep this computer".** The capture did keep → `UNINSTALL_ACK` with the code
   → 200, device deleted. Inherent to offline codes (the PC can't know about the keep), but the server could refuse
   codes for a device with no removal waiting. Owner's call.

## Open questions: recommendations

From `~/eguard/docs/desktop-agent-open-questions.md`. None is settled in the spec yet.

| # | Recommendation | State |
|---|---|---|
| Q2 Shared PCs | At pairing, the parent ticks which Windows accounts are the child's (default: the signed-in account, if standard). Only those sessions are enforced and counted. A new local account raises an alert (needs a new TAMPER kind or alert: server change) | Phase 2 UI; server part needs the owner |
| Q3 Anti-cheat | Spike at the start of Phase 4 on the VM: `TerminateProcess` on CS2, Fortnite (EAC) and Valorant (Vanguard) from SYSTEM. Fallbacks in order: IFEO `Debugger` stub for blocked exe names (paired with the id match), end the launcher, overlay + `LockWorkStation` | Phase 4 |
| Q4 Waking for removal | Short term: the server answers `nextSyncSeconds: 60` to computers always (one-line change in `sync/route.ts`), which makes acceptance test 9 ("within a minute") possible. Later: a long-poll endpoint. Today the agent can't learn of a removal for up to 5 minutes | Needs the owner (server change) |
| Q5 Guessing the code | **Built:** 5 wrong codes lock input for 15 min, doubling each lockout, capped at 24 h, persisted (`removal::CodeAttempts`). Telling the parent needs a new TAMPER kind `REMOVAL_CODE_GUESSED` (server change); until then the lockout is local only | Core done; alert needs the owner |
| Q6 Offline clock | **Built** (`clock`): last trusted time and offset persisted; after an offline reboot time never runs back before the last eGuard time seen; a wall clock set back is detected at boot; a forward jump is detected and reported at the next sync, which also corrects the clock. Stated limit: a forward jump while offline across a reboot can end bedtime early or start a new day until the PC is back online | Core done |
| Q1, Q7, Q8, Q9 | Not decided here; they need the owner (admin-account test 8, self-update design, end-of-life recovery, exclusive fullscreen) | Open |

## Next: Phase 2 (pairing, sync and the service shell)

Done when: on this PC, pairing with a dashboard code shows a WINDOWS computer on the device page with the right
capabilities, against the local dev server.

1. `crates/eguard-win` (the `windows` crate) and the binaries `eguard-service`, `eguard-agent` (UI comes in Tauri
   later; a minimal pairing window or console prompt is enough for Phase 2), `eguard-guard` (stub).
2. Durable store in `%ProgramData%\eGuard`: one JSON state file replaced atomically (write temp, flush,
   `ReplaceFileW`/`MoveFileExW` with write-through), holding `AgentState`, `UsageLedger`, `OutboundQueue`,
   `CodeAttempts`, the last good catalog. Secrets (token, removal secret) DPAPI machine-scope in a separate file.
3. API client: timeouts, honours `nextSyncSeconds` (clamped in `state`) and 429, maps statuses with
   `SendOutcome::from_status`. **Decide first:** the prompt says rustls, but rustls needs `ring` or `aws-lc-rs`,
   which compile C at build time (aws-lc-rs also needs CMake/NASM). That's on the "ask me first" list. Alternative
   with no build-time code: WinHTTP through the `windows` crate (system TLS, system proxy). Recommend WinHTTP
   behind a small `Transport` trait so the Mac agent can bring its own.
4. Service: LocalSystem, auto-start, recovery actions (restart on failure). Running a service on this PC needs an
   elevated install: **ask the owner**, or run the service logic in console mode for Phase 2 and install it only on
   a VM.
5. `/report` with the capability states from spec section 11 (`APP_RESTRICTIONS`, `CONTENT`, `LOCATION`,
   `NOTIFICATIONS` never reported; `UNINSTALL_PROTECTION` `enabled: false` with an `error` until Phase 6; `WEB`
   `mode: OFF` with an `error` until Phase 5). `fixtures/server/report-request.json` is a body the server accepted
   with nothing ignored.
6. Boot id for `ClockSample`: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\BootId`;
   monotonic: `QueryInterruptTime` (includes sleep).

## Gotchas

- Fixtures hold a device token and removal secret of a test device that was deleted at the end of the capture.
  They're useless, but don't copy the pattern with real devices.
- The dev server on :3000 belongs to the owner's session. Dev servers always send mail to Mailpit
  (`src/lib/mail.ts`), so the capture script is safe to run against it.
- `keys.rs` uses the dev key unless `EGUARD_POLICY_PUBLIC_KEYS` is set at compile time. Phase 7 must refuse to
  build a release with `keys::is_dev_build()`.
- Line endings: this repo is LF (rustfmt). `~/eguard` mixes CRLF/LF.
