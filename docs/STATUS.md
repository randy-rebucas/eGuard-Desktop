# Status

Updated 2026-10-23, end of Phase 3.

| Phase | What | Status |
|---|---|---|
| 1 | Core crate, no Windows APIs | Done |
| 2 | Pairing, sync and the service shell | Done |
| 3 | Scanning and identification (spec 5, 6) | **Done** (this commit), with the catalog gaps below for the owner |
| 4 | Enforcement and time (spec 7, 8) | Next. Needs a Windows 11 VM for acceptance tests 3–6 |
| 5 | Web (spec 9) | |
| 6 | Removal protection and tamper (spec 10, 11) | Needs a VM |
| 7 | Hardening and release readiness | Needs the code-signing certificate |

Phases and their "Done when" gates are in `~/eguard/docs/desktop-agent-prompt.md`.

## Phase 3: what was built

| Crate / module | What it does |
|---|---|
| core `scan` | `Candidate` (what the platform found), `Classifier` (the catalog's four rules, first match wins, spec 5), `merge` (one candidate per app: same folder, inside an installed app's folder, or named like an installed app), `classify_all` (one entry per name), `events` (first scan: `APPS_FOUND` in 200s; later: `APP_INSTALLED` per new app, or one `APPS_FOUND` when more than 3 are new) |
| core `scan::launchers` | Steam `libraryfolders.vdf` / `appmanifest_*.acf`, Epic `.item` (skips add-ons and half installs), launcher ids from Uninstall entries (Steam App, Riot `--uninstall-product`, Battle.net `--uid`, Uplay Install, GOG `_is1`, EA `EAInstaller`), MSI packed product codes, Store family names, `AppxManifest.xml`, publisher DNs |
| core `scan::vdf`, `lnk`, `pe` | Valve KeyValues, `.lnk` targets (`LinkInfo`), PE import tables (DirectX/Vulkan/XInput = a game signal). All bounds-checked and fuzzed by truncation in tests |
| core `engine` | `GET /catalog?since=` after pairing and every 6 h (verified; a forged or older one is refused and the kept one stays; 429 waits an hour). `scan_due`: never without a verified catalog; first scan after pairing, then every 6 h, or on a change (not within 2 min of the last). `apply_scan` queues the events |
| core `store` | Adds the raw signed catalog (verified again at every start), what was reported, the exe cache, the last scan time |
| `eguard-win::apps` | The sources of spec 5: Uninstall keys (HKLM both views + each loaded user hive), Steam, Epic, GOG, itch, Store packages per user (manifest + resolved `ms-resource` names), Start Menu shortcuts, exes in Downloads/Desktop (depth 2) and AppData Local/Roaming (depth 3, 3 000 exes max). Leaves out system components, updates, and anything removed by or living under `%SystemRoot%` |
| `eguard-win::authenticode` | `WinVerifyTrust`, embedded signatures, offline (no revocation, no URL retrieval). Signer = the certificate's O, else CN; both are matched (Microsoft signs .NET as CN ".NET") |
| `eguard-win::version`, `shell`, `watch` | Product name from the version resource; `SHLoadIndirectString`; change notifications on the Uninstall keys and launcher folders (20 s settle, rebuilt every 30 min) |
| `eguard-service` | Scans run on their own thread; the watcher asks for scans; `scan` (dry run: prints the payload, sends nothing; `--trust` tries a catalog addition) |
| `eguard-agent` | `scan` (ask for a scan now); `status` shows apps reported and the last scan |

Evidence for rule 3, in order: the main exe's signature (DisplayIcon exe, else the best exe in InstallLocation), then
the uninstaller's, then the cached MSI's (`C:\Windows\Installer\*.msi` keeps its signature; found through
`Installer\UserData\<sid>\Products\<packed code>`). A Store package's publisher counts as its signer (Windows
verified the package; a Store-signed one's publisher is a GUID, so its verified display name is used).

**Verified (2026-10-23, on this PC):**
- `cargo test --workspace`: 120 passed (core 89 unit + 12 fixture, win 18, service 1). The Windows tests scan this
  PC for real (a second scan checks no file again), verify Microsoft's and an unsigned file's signatures, read a
  product name, and see a folder change.
- `cargo clippy --workspace --all-targets -- -D warnings` (pedantic): clean. `cargo fmt --all --check`: clean.
- **Done when (dry run):** `eguard-service scan --catalog fixtures/server/catalog.json` on this PC: 126 candidates,
  79 left out as trusted (all Microsoft components and runtimes, Visual C++, .NET, Python, Chrome, Edge, Firefox,
  Android Studio, Realtek, ASUS Armoury Crate / Aura / ROG), 45 reported: 2 from the catalog as games (Microsoft
  Solitaire Collection and Xbox, from the Store, Microsoft-signed: rule 1 before rule 3) and 43 from publishers
  the catalog doesn't trust. The payload is one `APPS_FOUND` with all 45; each app carries its `EXE` id
  (`<signer>|<product>`) and Store apps their `MSSTORE` family name. No launchers are installed here, so rule 2 and
  the launcher readers are tested with sample files only.
- **Live, against the dev server:** pair → `/sync` → `GET /catalog` → `/report` → `/events` (`APPS_FOUND`), all 200.
  The parent's Apps tab lists the 45 (PENDING: App Approval is on by default), with one alert: "eGuard found 2
  games and 43 other apps on Mia's LocalPro, 43 from a publisher eGuard can't verify." Then a test Uninstall entry
  (HKCU, an unsigned exe with `UnityPlayer.dll` beside it) was noticed by the watcher, rescanned in 4.3 s (195
  files from the cache, 1 checked) and sent as one `APP_INSTALLED`: the Apps tab got "Pixel Quest" as GAMES and the
  alert "Mia asked to install Pixel Quest. Its publisher isn't verified." Test entry, files and family deleted.

**Not verified:** any launcher (none installed here: Steam, Epic, GOG, Riot, Battle.net, EA, Ubisoft, itch); a
scan as SYSTEM (other users' folders, their Store packages); game signals on a real game. All need the VM.

### What still shows that the "Done when" says shouldn't (for the owner)

The rules are the spec's: anything not signed by a catalog TRUSTED_PUBLISHER is reported. On this PC that leaves:

- **OEM tools whose publisher isn't in the catalog:** Epson ×4 (`seiko epson corporation`), LG Monitor App
  (`lg electronics inc.`), Intel Graphics Command Center (Store display name `intel corp`; the catalog has `intel
  corporation`). Adding those three as TRUSTED_PUBLISHER rows takes the list from 45 to 39 (tried with `--trust`).
  That's a catalog change on the server (`src/lib/desktop-catalog.ts` + the seed script), so it's the owner's call.
- **A printer driver with an unsigned installer:** "XPrinter Driver version 8.2" (installs to `C:\XINYE POS Printer
  Driver`). Nothing in the rules can tell it from a game; only a catalog entry or a parent's "block/allow" settles it.
- **Developer tools** (Git, Node.js, Docker, Postgres, MongoDB, ngrok, Playwright's browsers under AppData…): all
  unverified publishers by the rules. On a child's PC there would be few of these.
- **Leftovers:** "Discord" (only its updater is left, which can reinstall it), "Mozilla Maintenance Service" (its
  uninstaller is unsigned).

## Owner's decisions in Phase 2

- **HTTP: WinHTTP**, not rustls (rustls needs `ring`/`aws-lc-rs`, which compile C at build time). Behind
  `eguard_core::api::Transport`, so the Mac agent brings its own.
- **Service: console mode on this PC.** `eguard-service run` does the service's work in a console; nothing is
  installed. `eguard-service install` exists for a VM and hasn't been run anywhere.

## Phase 2: what was built

| Crate / module | What it does |
|---|---|
| core `api` | Device API client over a `Transport`: `/pair`, `/sync` (raw JSON, so signatures are checked on what arrived), queued `/usage` `/report` `/events` mapped to `SendOutcome` (429 keeps `Retry-After`). `ServerUrl`: `https://` only; `http://localhost` only in a dev build |
| core `engine` | The service's loop without the platform: pairing (refused once paired; code normalized like the server), `adopt` after the secrets are saved, `tick` = check the wall clock → `/sync` when due → send what's due. Sync failures back off 30 s–15 min with jitter; 401 retries in 15 min and switches nothing off; 429 waits ≥ 5 min. `CLOCK_CHANGED` queued from the wall-clock check, the boot check and `/sync`. A verified uninstall command is logged, not acted on (Phase 6) |
| core `report` | `/report` body from the last good sync and the build's `Capabilities` (see "Reporting" below) |
| core `store` | `Persisted` (state, usage, queue, code attempts, last report) and `DeviceSecrets` (device id, token, removal secret; `Debug` redacted). A lost or corrupt state file is rebuilt from the secrets |
| core `ipc` | Pipe messages: versioned JSON lines (`pair`, `status`), 8 KB max; no secret ever crosses the pipe |
| `eguard-win` | `http` (WinHTTP: system proxy, TLS 1.2+, redirects never followed so the token can't leak, 4 MB answer cap, timeouts), `dpapi` (machine scope + entropy), `files` (temp file + `FlushFileBuffers` + `MoveFileExW` write-through), `security` (SDDL, user SID, folder DACL), `pipe` (DACL, `PIPE_REJECT_REMOTE_CLIENTS`, `FILE_FLAG_FIRST_PIPE_INSTANCE`), `clock` (`GetTickCount64`, BootId), `sysinfo` (name, BIOS model with "Custom build" for placeholders, "Windows 11 25H2 (26200)", battery) |
| `eguard-service` | `run` (console), `install`/`uninstall` (SCM: LocalSystem, auto-start, restart 5 s / 5 s / 60 s, reset daily, also on non-crash failures), no arguments = started by the SCM. Sync loop + pipe thread (one thread per client). Log in `<data>\logs\service.log`, 1 MB, one old file |
| `eguard-agent` | Console: `pair [CODE] [--name NAME]`, `status` |
| `eguard-guard` | Stub (Phase 6) |
| `tools/dev-family.mjs` | `create` / `code` / `show` / `delete` a test family on the dev server, for pairing by hand |

Data folder: `%ProgramData%\eGuard` in a real install, its DACL set to SYSTEM + Administrators only, protected
from inheritance, on every start (any user can create folders in `ProgramData`, so one made first by someone else
must not keep their access). Console mode uses `%LOCALAPPDATA%\eGuard\dev` (`--data-dir` to change), so a
user-owned folder never ends up where a real install goes.

Pipe `\\.\pipe\eguard`: SYSTEM + Administrators in a real install (pairing comes from the elevated installer),
SYSTEM + the current user in console mode.

### Reporting: what the dashboard shows

The server counts a reported config that matches the parent's as applied, even with an `error` beside it
(`evaluate` in `~/eguard/src/lib/health.ts`). So echoing the policy back would say "on" for protections this build
doesn't enforce. Instead each report is full (`full: true`) and leaves out the AVAILABLE protections the build doesn't
enforce yet (none in Phase 2); the server then marks them not applied. UNINSTALL_PROTECTION goes as `enabled: false`
and WEB as `mode: OFF`, each with the reason. Phase 4 adds keys to `Capabilities::enforced` in
`eguard-service/src/runner.rs` as it enforces them; Phases 5 and 6 turn the guided ones on.

A report is queued after a sync that asks for one, has config requests, or changes what would be reported.

**Verified (2026-10-23, on this PC):**
- `cargo test --workspace`: 95 passed (core 71 unit + 12 fixture, win 11, service 1). The Windows tests run for real:
  DPAPI round trip and tamper rejection, atomic replace, a pipe client/server exchange, a second first-instance
  pipe refused, an unreachable server is a transport error, registry, SID, device details.
- `cargo clippy --workspace --all-targets -- -D warnings` (pedantic): clean. `cargo fmt --all --check`: clean.
- **Done when, against the dev server on :3000:** `eguard-service run` + `node tools/dev-family.mjs create` +
  `eguard-agent pair <code>` → "Paired. This computer is now Mia's on eGuard." Server log: `POST /pair 201`,
  `/sync 200`, `/report 200`. The parent API (`GET /mobile/v1/devices/{id}`, what the device page shows): platform
  WINDOWS, kind COMPUTER, "Windows 11 25H2 (26200)", model "Custom build", app 0.1.0, primary. Capabilities exactly
  as in spec 11: AVAILABLE SCREEN_TIME, BEDTIME, APP_APPROVAL, DOWNLOADS; GUIDED WEB, UNINSTALL_PROTECTION;
  UNSUPPORTED APP_RESTRICTIONS, CONTENT, LOCATION, NOTIFICATIONS. All applicable ones shown as not applied, with
  the reasons above. Test family deleted afterwards.
- Restart: the service came back paired (secrets read back through DPAPI), synced, and sent no repeat report.
  `state.json` holds no token.
- Pipe: a refused code shows the server's words ("Pairing code is invalid or expired"); a malformed code is refused
  locally; protocol version 9, an unknown message type and a 9000-byte line are each refused. A second
  `eguard-service run` fails at once: "couldn't create \\.\pipe\eguard (Access is denied)".

**Not verified (needs a VM):** `eguard-service install` and running under the SCM as LocalSystem, the recovery
actions, setting the data folder's DACL (only runs in service mode), DPAPI as SYSTEM, pairing from an elevated
session over the service-mode pipe.

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
5. **New (Phase 2): the "not applied" text on computers is the phones' wording.** A protection left out of a full
   report gets "eGuard isn't applying it. A permission it needs may be turned off." (`~/eguard/src/lib/engine.ts`,
   `processReport`, the `missing` entry). On a computer there's no permission to turn on. Suggest a
   platform-aware text there, e.g. for WINDOWS/MACOS "eGuard for this computer doesn't apply it yet." Not changed.
6. **New (Phase 2): `/sync` now sends `browserLink`** (uncommitted server change, `src/lib/browser-link.ts`, with the
   migration `20261023120000_browser_on_computer`). The core ignores fields it doesn't know, so nothing broke; it's
   Phase 5's input. Re-capture the fixtures once the server commits it.
7. **New (Phase 3): suggested catalog additions** (TRUSTED_PUBLISHER, SIGNER): `seiko epson corporation`, `lg
   electronics inc.`, `intel corp` (the Store's name for Intel; the catalog has `intel corporation`). See "What still
   shows" above. Also worth considering: `zoom communications, inc.` (Zoom's current certificate; the catalog has
   `zoom video communications, inc.`).
8. **New (Phase 3): the server's wording for a new app on a computer.** An `APP_INSTALLED` while approval is on
   reads "Mia asked to install Pixel Quest" (`events/route.ts`, `raiseAppRequest`). On a computer the child didn't
   ask; the scan found it. Suggest "Pixel Quest was found on Mia's PC and waits for you" for computers.
9. **New (Phase 3): one app, two catalog names.** The scan dedupes by name before sending, but the catalog's
   display name can differ from the Uninstall name (Steam "Counter-Strike 2" vs an Uninstall "Steam App 730"
   both merge to the catalog's name here). If the server ever renames a catalog game, the child's list keeps the
   old name and the ids merge new reports into it, so nothing doubles; noted only so a rename isn't surprising.

## Open questions: recommendations

From `~/eguard/docs/desktop-agent-open-questions.md`. None is settled in the spec yet.

| # | Recommendation | State |
|---|---|---|
| Q2 Shared PCs | At pairing, the parent ticks which Windows accounts are the child's (default: the signed-in account, if standard). Only those sessions are enforced and counted. A new local account raises an alert (needs a new TAMPER kind or alert: server change) | Pairing UI (Tauri) still to come; server part needs the owner. **Until then the scan covers every account**, so a parent's own apps on a shared PC are reported too |
| Q3 Anti-cheat | Spike at the start of Phase 4 on the VM: `TerminateProcess` on CS2, Fortnite (EAC) and Valorant (Vanguard) from SYSTEM. Fallbacks in order: IFEO `Debugger` stub for blocked exe names (paired with the id match), end the launcher, overlay + `LockWorkStation` | Phase 4 |
| Q4 Waking for removal | Short term: the server answers `nextSyncSeconds: 60` to computers always (one-line change in `sync/route.ts`), which makes acceptance test 9 ("within a minute") possible. Later: a long-poll endpoint. Today the agent can't learn of a removal for up to 5 minutes | Needs the owner (server change) |
| Q5 Guessing the code | **Built:** 5 wrong codes lock input for 15 min, doubling each lockout, capped at 24 h, persisted (`removal::CodeAttempts`, now saved in `state.json`). Telling the parent needs a new TAMPER kind `REMOVAL_CODE_GUESSED` (server change) | Core done; alert needs the owner |
| Q6 Offline clock | **Built** (`clock`), and now fed by the service: samples from `GetTickCount64` + BootId every tick (≤ 60 s), persisted with the state. Stated limit: a forward jump while offline across a reboot can end bedtime early or start a new day until the PC is back online | Done |
| Q1, Q7, Q8, Q9 | Not decided here; they need the owner (admin-account test 8, self-update design, end-of-life recovery, exclusive fullscreen) | Open |

## Next: Phase 4 (enforcement and time, spec 7 and 8)

Done when: spec acceptance tests 3 to 6 pass, each shown how it was checked. **Needs the Windows 11 VM** (a
standard child account; Steam with CS2, Roblox): ending processes as SYSTEM, the per-session agent and the overlay
can't be tested in console mode on this PC.

1. **Spike first (Q3):** on the VM, `TerminateProcess` from SYSTEM on CS2, Fortnite (EAC) and Valorant (Vanguard).
   Fallbacks in order: IFEO `Debugger` stub for blocked exe names, end the launcher, overlay + `LockWorkStation`.
2. Process start detection: ETW Kernel-Process (`Microsoft-Windows-Kernel-Process`, start events with image path)
   from the service; the 2-second `NtQuerySystemInformation`/Toolhelp sweep as fallback. Resolve a process to an app
   **by id first** (`/sync` `apps[].ids`: the Steam appid from the exe's library folder, the `EXE` id from the cached
   `ExeFacts`), then by name. The core's `rules::evaluate` decides; `scan::ExeCache` already holds signer + product.
3. Never block: Microsoft-signed under `%SystemRoot%`, eGuard itself, accessibility tools, a trusted publisher's
   non-game app (rule 3 of the classifier, already built).
4. The per-session agent: the service starts `eguard-agent` in each session (`WTSQueryUserToken` +
   `CreateProcessAsUser`), per-session pipe with the session's logon SID (replacing today's single pipe), foreground
   window + idle time → `UsageLedger`, block screen, 5- and 1-minute warnings, time-up/bedtime overlay with
   `LockWorkStation` as backstop. **Decide first:** the prompt says Tauri for the UI. Tauri's build pulls many crates
   with build scripts and needs WebView2; that's near the "ask me first" line (crates that run code at build time).
   Alternative with nothing new: a plain Win32 layered window from `eguard-win`. Recommend Win32 for the overlay and
   block screen (they must work even when WebView2 is broken or removed), Tauri later for settings screens.
5. `APP_BLOCKED`, `LIMIT_REACHED`, `TIME_REQUESTED`, `APP_REQUESTED` through the queue; `/usage` with `hourly[24]`
   from the ledger.
6. Then add the AVAILABLE keys to `Capabilities::enforced` in `runner.rs` as each is enforced, so `/report` says so.

## Gotchas

- **The dev server and Prisma.** When `~/eguard`'s schema changes, a running `pnpm dev` keeps the old Prisma
  client in memory and answers 500 on anything that touches the new columns (pairing codes and `/pair` did).
  Restart it. On 2026-10-23 the owner asked Claude to restart it: it now runs from Claude's session in the
  background (`pnpm dev` in `~/eguard`) and stops when that session ends; start it again in your own terminal then.
- The service holds the engine's lock during network calls, so a pipe request (status, pairing) can wait for a tick
  in progress (seconds; up to the 30 s timeout per request with a server that doesn't answer). Fine for now; split
  the lock if the agent UI ever feels it.
- The pipe only checks who connects, not who serves: an agent doesn't yet verify the pipe belongs to the eGuard
  service (`GetNamedPipeServerProcessId` + the service's SID). The service does refuse to share the name. Add the
  client check with the real agent (Phase 4 or 6).
- In a real install the pipe is one pipe for SYSTEM + Administrators. Per-session pipes (the logon SID of the session
  the service starts the agent in) come when the service starts agents (Phase 4).
- `AGENT_RESTARTED` isn't sent yet: that needs the guard (Phase 6) to tell a crash from a stop.
- A first scan on this PC takes about 35–50 s (it verifies ~160 signatures); later ones take a few seconds from the
  cache. Signature checks never use the network (no revocation, no URL retrieval).
- The scan reads only what the account running it can read. In console mode that's this user; as SYSTEM it will see
  every profile's folders, but other users' registry only while their hive is loaded (signed in).
- `python` is the Store alias here, but `python3` works (3.14); scripts that edit files should be run with `-I`.
- Fixtures hold a device token and removal secret of a test device that was deleted at the end of the capture.
  They're useless, but don't copy the pattern with real devices.
- The dev server on :3000 belongs to the owner's session. Dev servers always send mail to Mailpit
  (`src/lib/mail.ts`), so the capture and dev-family scripts are safe to run against it.
- `keys.rs` uses the dev key unless `EGUARD_POLICY_PUBLIC_KEYS` is set at compile time; the service's server URL is
  `http://localhost:3000` unless `EGUARD_SERVER_URL` is. Phase 7 must refuse to build a release with
  `keys::is_dev_build()`.
- Line endings: this repo is LF (rustfmt). `~/eguard` mixes CRLF/LF.
