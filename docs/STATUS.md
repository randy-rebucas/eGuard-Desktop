# Status

Updated 2026-10-23: Phase 4, then a session on the owner's decisions (below).

| Phase | What | Status |
|---|---|---|
| 1 | Core crate, no Windows APIs | Done |
| 2 | Pairing, sync and the service shell | Done |
| 3 | Scanning and identification (spec 5, 6) | Done, with the catalog gaps below for the owner |
| 4 | Enforcement and time (spec 7, 8) | **Built and checked on this PC with stand-ins** (this commit). Tests 3–5 pass in console mode; test 6 and everything that needs SYSTEM wait for the VM (below) |
| 5 | Web (spec 9) | Next |
| 6 | Removal protection and tamper (spec 10, 11) | Needs a VM |
| 7 | Hardening and release readiness | Needs the code-signing certificate |

Phases and their "Done when" gates are in `~/eguard/docs/desktop-agent-prompt.md`.

## The owner's decisions (2026-10-23, after Phase 4)

Approved and done: findings 2, 4, 5, 7, 8, 10, 11 and open questions Q2, Q4, Q5. Left open: findings 1, 12. Finding 13 was approved later the same day and built (overlay app buttons).

**`~/eguard` (server): changed and tested, NOT committed.** That repo had ~60 files of the owner's own uncommitted
work, including the files these changes touch, so a commit would have swept it in. Commit them with that work:

| File | Change |
|---|---|
| `src/app/api/device/v1/sync/route.ts` | `nextSyncSeconds` is 60 for computers (Q4, finding 10) |
| `src/app/api/device/v1/events/route.ts` | `UNINSTALL_ACK` deletes only while a removal waits; a valid code with none waiting → 409 + "A removal code was used after you kept the computer" (finding 4). TAMPER kinds `REMOVAL_CODE_GUESSED` (Q5) and `NEW_ACCOUNT` (Q2). A computer's found app reads "X was found on Mia's PC and waits for you" (finding 8) |
| `src/lib/engine.ts` | A protection a computer leaves out: "eGuard for this computer doesn't apply it yet. An update to eGuard will." (finding 5) |
| `src/lib/desktop-catalog.ts` | Trusted: `seiko epson corporation`, `lg electronics inc.`, `intel corp`, `zoom communications, inc.` (finding 7); seeded into the dev DB |
| `src/app/api/device/v1/report/route.ts`, `src/lib/mobile-views.ts`, `prisma/schema.prisma`, `prisma/migrations/20261023180000_computer_accounts/` | `/report` `accounts: [{ name, enforced }]` stored on the Device (new `accounts` JSON column), shown in `GET /devices/{id}` (Q2) |
| `tests/api/desktop-agent.test.ts` | 5 new tests, 2 changed: 35 pass with `devices.test.ts` |
| `docs/desktop-agent-spec.md` (1, 3, 4, 10, 11, 12, 13), `docs/desktop-agent-open-questions.md` (Q2, Q4, Q5 Settled), `docs/mobile-api.md` | The spec says what was decided, incl. Win32 screens (finding 11) |

Server checks: `tsc` clean, 580 unit tests pass, the desktop-agent and devices API suites pass (35). The full API
suite can't pass in one run here: sign-ups are limited to 10 an hour per IP and the suites make more (pre-existing;
`mobile-api.test.ts` alone exceeds it). The suites that use the changed routes for phones still expect the phones'
behaviour, which didn't change.

**`~/eguard-browser`:** `.env` `VITE_POLICY_PUBLIC_KEY` set to the key derived from the server's dev signing key
(finding 2). `.env` is ignored by git, so nothing to commit.

**This repo:**
- **Shared PCs (Q2).** `eguard-agent pair` lists the Windows accounts and asks which are the child's (preselected:
  the standard ones; `--accounts NAME,NAME` skips the question); pairing is refused before the code is used if that
  leaves none. `eguard-agent accounts [--set …]` shows or changes it (admin pipe). Only those accounts' sessions get an
  agent, have time counted and programs ended (`session_sids`, `Enforcer::applies_to`); session 0 and a session whose
  account can't be read are still checked (stricter). A paired-before computer (no choice saved) enforces everyone.
  A new account is reported once (`TAMPER` `NEW_ACCOUNT`) and isn't enforced; the list goes to `/report` when it
  changes. Core `accounts`, win `accounts` (`NetUserEnum`, `LookupAccountNameW`).
- **Q5:** `Engine::try_removal_code` counts attempts and sends `REMOVAL_CODE_GUESSED` once per lockout, ready for
  Phase 6's "Remove with a code".
- **Finding 6:** `SyncResponse.browser_link` kept for Phase 5; fixtures re-captured (`capture-fixtures.mjs` now also
  records the 409 for a code after Keep).

Verified live on this PC (console mode, sandbox, family deleted after): paired with `--accounts corew`; the parent's
device page listed `CodexSandboxOffline`/`CodexSandboxOnline` not limited and `corew` enforced; `nextSyncSeconds` 60;
the new catalog left Epson, LG and Intel's apps out (40 apps reported instead of 47); the stand-in CS2 was ended in
1.12 s in `corew`'s session, and after `accounts --set CodexSandboxOnline` it ran untouched. Not tried live: a new
account (creating one needs an administrator), the code lockout (no "Remove with a code" screen yet).

**For Phase 6:** online, the agent sends `UNINSTALL_ACK` with the code before removing itself and stops on 409 (the
parent kept the computer); offline, the code alone decides (spec 10).

## Phase 4: what was built

Owner's decisions (2026-10-23): **plain Win32 for the agent's screens** (block screen, warnings, overlay), not Tauri:
they must work when WebView2 is broken or removed, and nothing new is pulled in. Tauri can come later for settings
screens. And with no VM yet: **build all of Phase 4 and check it on this PC with stand-in programs**; real games,
SYSTEM and a second account wait for the VM.

| Crate / module | What it does |
|---|---|
| core `enforce` | `resolve`: a running program → an app. By the install folder the scan recorded (`scan::Place`: a renamed `cs2.exe` is still in Steam's folder for appid 730), then by id against `/sync` `apps[].ids`, then by name. Never ended: Microsoft-signed under `%SystemRoot%`, eGuard's own exes, accessibility tools (by file name and signer), a trusted publisher's non-game app (classifier rule 3; launcher games stay games). App Approval applies to scanned apps and unsigned exes outside Program Files only; anything else is untracked. `Enforcer`: `check` (what to end, `APP_BLOCKED` once per app per 10 min), `ended` (block screen per session), `heartbeat` (usage, warnings at 5 and 1 min, overlay, `LIMIT_REACHED` once per day and limit), `ask` (`APP_REQUESTED` / `TIME_REQUESTED`, once per app and reason per 10 min), `usage_due` (`/usage` every 5 min, at once after a limit). All the words on the screens are written here |
| core `rules` | `upcoming` / `upcoming_screen`: what pauses next and when (for the warnings) |
| core `ipc` | Session pipe `\\.\pipe\eguard-session-<id>`: `heartbeat` (foreground pid, idle ms), `askParent`, `askTime` → `SessionView` (overlay, block screen, warning) |
| `eguard-win` `process`, `etw` | Process list (Toolhelp), image path, session, start time, ending a tree children-first with `TerminateProcess` (exit code `0x65477561`, "eGua"), a child must be younger than its parent. ETW real-time session on Microsoft-Windows-Kernel-Process (start events, pid only) |
| `eguard-win` `authenticode` | Adds catalog signatures (`CryptCATAdmin*` + `WTD_CHOICE_CATALOG`, SHA-256 then SHA-1): most of System32 has no embedded signature |
| `eguard-win` `session`, `input`, `ui` | WTS: sessions in use, lock state, the user's logon SID, `CreateProcessAsUserW` into a session, `WTSDisconnectSession`. Foreground pid, idle time incl. XInput controllers (a pad doesn't count as input to Windows). The three screens in GDI with standard buttons (Common Controls 6 via a linker-embedded manifest in `eguard-agent/build.rs`) |
| `eguard-service` `monitor` | ETW when allowed + a sweep every second (2 s with ETW). Each program looked up once per file version; every tracked process re-checked each sweep (limits run out mid-game). New processes newest first with a 1 s budget per sweep, so a game opened at start-up isn't stuck behind 380 signature checks. A pid seen with another parent or exe name is looked up afresh (reuse) |
| `eguard-service` `sessions` | One agent per session (service: as the user via WTS; console: in this session), started again when it dies; a non-zero exit sends `TAMPER` `AGENT_RESTARTED`. One pipe per session (SYSTEM + the logon SID), requests only from `eguard-agent.exe` beside the service, in that session. A session in use with a silent agent counts as used (fail closed). Backstop while paused: 3 agent restarts in a minute or 20 s of silence disconnects the session (service mode only) |
| `eguard-service` `runner` | The enforcer has its own lock: ending a program never waits for a sync. Enforcement's events and usage go to the queue every 10 s; the state is saved on ticks (about a minute), not every 10 s. `run --sandbox DIR` |
| `eguard-agent` | `session [--dev]`: heartbeat every second, screens, buttons; believes only a session pipe served by `eguard-service.exe` beside it. `preview block\|overlay\|warning` |
| `tools/dev-family.mjs`, `tools/enforce/` | `app`, `limit`, `protect`, `screen-time` act as the parent. Stand-ins and scripts (see CLAUDE.md) |

`Capabilities::enforced` now has SCREEN_TIME, BEDTIME, APP_APPROVAL, DOWNLOADS when programs are really ended (the
service, or console mode with `--sandbox`); a console dry run still reports them as not applied.

**The overlay** covers every monitor, takes the focus back every second and stays on top. While the day's screen
time is up it steps aside when an always-allowed app that's still usable has the focus (Alt+Tab; it names those
apps); bedtime covers everything. If something else keeps the focus for 15 s anyway, the agent locks the session
(`LockWorkStation`); not in console mode, where the overlay also has a "Close (development build)" button.

**Verified (2026-10-23, on this PC, console mode, `--sandbox`, against the dev server; family deleted after):**
- `cargo test --workspace`: 142 passed, 1 ignored (core 104 unit + 12 fixture, win 24, service 2; the ignored one
  draws on the screen and was checked by screenshot instead). Clippy (pedantic) and fmt clean. The Windows tests end
  a real process tree, verify catalog signatures of notepad/cmd/taskmgr, read sessions and the logon SID, and check
  both ends of a pipe.
- **Test 3:** the stand-in `cs2.exe` in a fake Steam library (appid 730, BLOCKED by the parent) was ended in 0.26–0.92 s
  (five runs, steady state), with eGuard's exit code; the block screen showed "Counter-Strike 2 is blocked". The
  dashboard got "App blocked: Mia tried to open Counter-Strike 2, which is blocked" and, after "Ask parent", "App
  approval requested: Mia asked again for Counter-Strike 2, which you blocked."
- **Test 4:** `totally-not-cs2.exe` (a copy in the same folder) was ended in 0.80 s as Counter-Strike 2.
- **Test 5:** Gaming time 1 minute, the unsigned "Pixel Quest" (found by the scan as GAMES) kept in front with input:
  "1 minute of gaming time left today." showed at once, the game was ended after 53.5 s (52 s were left), the block
  screen said "Gaming time used up", the dashboard got "Gaming time used up: Mia reached the 1m daily limit for
  games", and "Ask for more time" gave "More time requested: Mia asked for more time on Pixel Quest, paused by a
  category limit." The answer replaces the buttons on the screen.
- **Overlay:** with daily screen time at 15 minutes (the server's minimum) and 15 used, the overlay came up within
  2 s, "Ask for more time" on it went through (queue emptied; the server folds it into the open request), and the
  dashboard got "Screen time limit reached: Mia reached the 15m daily limit."
- **Test 7 (Phase 6's, partly):** killing `eguard-agent.exe` → a new one in under 4 s, and "eGuard was closed and
  started again" on the dashboard.
- **`/usage`:** the parent's screen time showed 13 minutes with hourly buckets in Manila hours.
- **Accessibility:** the screens' buttons read as push buttons with a "Press" action through MSAA (what screen readers
  use), and pressing them that way works.
- **Never ended outside the sandbox:** the test family's App Approval left 44 of this PC's apps PENDING (Docker, Git,
  Node.js, Postman, Claude Code…); console mode logged "would end" for them and ended nothing.
- **Cost:** release build, 379 processes, no ETW: 1.2 % of one core steady; about 9 s of CPU once at start (looking up
  every running program). Right after start a new game is ended in 0.2–2.3 s.

**Not verified (needs the VM):**
- **Test 6** (moving the clock forward an hour) needs an administrator to change the clock. Covered by the core's
  tests (`moving_the_clock_forward_gains_nothing`, and Phase 2's `CLOCK_CHANGED` tests), not run live.
- Anything as SYSTEM: ETW (this PC answers "access denied" to a normal user; the sweep did all the work above),
  starting the agent with `WTSQueryUserToken` + `CreateProcessAsUserW`, the logon SID from another session's token,
  the disconnect backstop, `LockWorkStation` (console mode never locks).
- Real games and **Q3 (anti-cheat)**: `TerminateProcess` on CS2 (VAC), Fortnite (EAC) and Valorant (Vanguard) from
  SYSTEM. Still the first thing to try on the VM.
- A second (child) account, fast user switching, Remote Desktop, several monitors, a game controller.

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
2. **The browser extension's dev public key no longer matches the server's dev signing key.** **Done 2026-10-23** (see "The owner's decisions").
   `~/eguard-browser/.env` `VITE_POLICY_PUBLIC_KEY` is `MFkw…PPOg==`; the key derived from
   `~/eguard/.env.local` `BROWSER_POLICY_SIGNING_KEY` is `MFkw…5Q==` (keyId `60da38f4c654f71a`). A dev build of the
   extension would reject every policy from the local server. Not changed (not this repo).
3. **"Paired but unsynced" isn't in the spec.** The prompt refers to it. Chosen: before the first `/sync`, new apps
   wait for approval and no time limits apply. Pairing needs the network, and the first sync follows in seconds.
4. **A removal code still works after "Keep this computer".** **Done 2026-10-23** (see "The owner's decisions"). The capture did keep → `UNINSTALL_ACK` with the code
   → 200, device deleted. Inherent to offline codes (the PC can't know about the keep), but the server could refuse
   codes for a device with no removal waiting. Owner's call.
5. **New (Phase 2): the "not applied" text on computers is the phones' wording.** **Done 2026-10-23** (see "The owner's decisions"). A protection left out of a full
   report gets "eGuard isn't applying it. A permission it needs may be turned off." (`~/eguard/src/lib/engine.ts`,
   `processReport`, the `missing` entry). On a computer there's no permission to turn on. Suggest a
   platform-aware text there, e.g. for WINDOWS/MACOS "eGuard for this computer doesn't apply it yet." Not changed.
6. **New (Phase 2): `/sync` now sends `browserLink`** **Fixtures re-captured 2026-10-23**; Phase 5 uses it. (uncommitted server change, `src/lib/browser-link.ts`, with the
   migration `20261023120000_browser_on_computer`). The core ignores fields it doesn't know, so nothing broke; it's
   Phase 5's input. Re-capture the fixtures once the server commits it.
7. **New (Phase 3): suggested catalog additions** **Done 2026-10-23** (see "The owner's decisions"). (TRUSTED_PUBLISHER, SIGNER): `seiko epson corporation`, `lg
   electronics inc.`, `intel corp` (the Store's name for Intel; the catalog has `intel corporation`). See "What still
   shows" above. Also worth considering: `zoom communications, inc.` (Zoom's current certificate; the catalog has
   `zoom video communications, inc.`).
8. **New (Phase 3): the server's wording for a new app on a computer.** **Done 2026-10-23** (see "The owner's decisions"). An `APP_INSTALLED` while approval is on
   reads "Mia asked to install Pixel Quest" (`events/route.ts`, `raiseAppRequest`). On a computer the child didn't
   ask; the scan found it. Suggest "Pixel Quest was found on Mia's PC and waits for you" for computers.
9. **New (Phase 3): one app, two catalog names.** The scan dedupes by name before sending, but the catalog's
   display name can differ from the Uninstall name (Steam "Counter-Strike 2" vs an Uninstall "Steam App 730"
   both merge to the catalog's name here). If the server ever renames a catalog game, the child's list keeps the
   old name and the ids merge new reports into it, so nothing doubles; noted only so a rename isn't surprising.
10. **New (Phase 4): "Ask parent" and "Ask for more time" take up to 5 minutes to come true.** **Done 2026-10-23** (see "The owner's decisions"). The parent answers on
    the dashboard, and the computer learns of it at its next `/sync` (`nextSyncSeconds` is 300). The same server
    change as Q4 (60 s for computers, or a push) fixes it.
11. **New (Phase 4): the desktop spec says Tauri for the agent (section 3).** **Done 2026-10-23** (see "The owner's decisions"). The owner chose Win32 for the block
    screen, warnings and overlay (above). Suggest the spec say so, with Tauri kept for later settings screens.
12. **New (Phase 4): time in browsers and other trusted apps counts toward the day but isn't named in `/usage`.**
    Naming it would put "Google Chrome" on the child's list as if it could be blocked, and it can't be (trusted
    publisher, never ended). The parent sees the day's total, not "Chrome 2h". Owner's call; WEB (Phase 5) may change
    the picture.
13. **New (Phase 4): the overlay hides the taskbar.** A child reaches an always-allowed app with Alt+Tab (the overlay
    names them). A launcher row on the overlay would be friendlier; worth a design pass. **Approved and built
    2026-10-23:** see "Overlay app buttons" below.

### Overlay app buttons (finding 13)

When the day's screen time is up, the overlay has a row of standard buttons (Tab, MSAA "Press"), one per
always-allowed app still usable (not paused by its own limit), at most 6 (`enforce::OVERLAY_APPS`); none at bedtime.
`Screen.apps: [{ name, exe?, start }]` (ipc): optional, so protocol version 1 stays (an older agent skips it, an older
service sends none). The exe is the program the service last saw **in front** as that app (`Memo.exes`, by the
list's name, persisted, pruned to the child's list), so a helper or updater in the app's folder is never picked.
Names are cut to 60 characters, paths over 520 bytes left out, and the buttons kept under 4 KB of JSON, so the line
stays under 8 KB. `start` is false for a Store app (MSSTORE id or under `WindowsApps`): it's only brought forward.
The agent (`eguard-win::launch`) acts only on that path, and only if it's a plain local `X:\…\*.exe` (no share,
device path, `..`, quotes, streams): a window of that program in front (restored, `AllowSetForegroundWindow`), else
`CreateProcessW` as the child, no arguments, in its folder, never elevated. The overlay then doesn't take the focus
back for 5 s (15 s after a start) and sends a heartbeat at once; the service sees the app in front and lifts the
overlay. A button that can't do anything (never used here, or a Store app not running) is disabled.
Checked on this PC with `preview overlay`: the row draws (long name cut with "…", disabled one greyed), MSAA reads
all four as push buttons, pressing one started `charmap`, and with `charmap` already open pressed brought it to the
front without a second copy. **Needs the VM:** a real child session with the service (the overlay stepping aside
after the press, end to end). Known gap: a UWP Store app's window belongs to `ApplicationFrameHost.exe` (Windows'),
so the service never sees the app itself in front: its button stays disabled, and the overlay doesn't step aside
for it either (as before).

## Open questions: recommendations

From `~/eguard/docs/desktop-agent-open-questions.md`. None is settled in the spec yet.

| # | Recommendation | State |
|---|---|---|
| Q2 Shared PCs | At pairing, the parent picks the child's Windows accounts (preselected: the standard ones). Only those are enforced and counted; a new account raises `NEW_ACCOUNT` | **Settled and built** 2026-10-23. The scan still covers every account (a parent's apps on a shared PC are reported, though never ended) |
| Q3 Anti-cheat | First thing on the VM: `TerminateProcess` on CS2, Fortnite (EAC) and Valorant (Vanguard) from SYSTEM. Fallbacks in order: IFEO `Debugger` stub for blocked exe names (paired with the id match), end the launcher, overlay + `LockWorkStation` | Enforcement built; the spike waits for the VM |
| Q4 Waking for removal | Computers always get `nextSyncSeconds: 60`. Later, if load matters: a long-poll endpoint | **Settled and built** 2026-10-23 (server, uncommitted) |
| Q5 Guessing the code | 5 wrong codes lock input for 15 min, doubling each lockout, capped at 24 h, persisted; each lockout sends `REMOVAL_CODE_GUESSED` | **Settled and built** 2026-10-23; the screen comes in Phase 6 |
| Q6 Offline clock | **Built** (`clock`), and now fed by the service: samples from `GetTickCount64` + BootId every tick (≤ 60 s), persisted with the state. Stated limit: a forward jump while offline across a reboot can end bedtime early or start a new day until the PC is back online | Done |
| Q1, Q7, Q8, Q9 | Not decided here; they need the owner (admin-account test 8, self-update design, end-of-life recovery, exclusive fullscreen) | Open |

## Next: Phase 5 (web, spec 9)

Chrome/Edge `ExtensionInstallForcelist`, Firefox `policies.json`, the BROWSERS category for the rest. Writing browser
policies changes this PC's security settings: that's on the "ask me first" list, so it's done on the VM (or the owner
says otherwise). Inputs: `/sync` `browserLink` (finding 6), the extension's key mismatch (finding 2).

Before or alongside it, on the VM (Phase 4's open items): install the service, check ETW, agents in a child's
session, the disconnect and lock backstops, test 6, and the Q3 anti-cheat spike with real games. `tools/enforce/`
has the stand-ins.

## Gotchas

- **`~/eguard` has the owner's uncommitted work**, mixed with this repo's server changes (see "The owner's
  decisions"). Don't commit there; list what you changed.
- **The dev database is managed with `prisma db push`, not `migrate`** (`migrate deploy` answers P3005). After a
  schema change: preview with `prisma migrate diff --from-schema-datasource prisma/schema.prisma
  --to-schema-datamodel prisma/schema.prisma --script`, then `db push --skip-generate`; `prisma generate` needs the
  dev server stopped (it holds the query engine: EPERM). On 2026-10-23 the owner let Claude restart it: it runs from
  that session (`pnpm dev`) and stops with it.
- **Sign-ups are limited to 10 an hour per IP.** Test families and API suites use it up; clear `signup:*` rows in
  the dev DB's `RateLimit` table to go on.
- On this PC `corew` is an administrator and `CodexSandboxOffline`/`CodexSandboxOnline` are standard: pairing with
  the defaults would make those two the child's. Pair console tests with `--accounts corew`.

- **The dev server and Prisma.** When `~/eguard`'s schema changes, a running `pnpm dev` keeps the old Prisma
  client in memory and answers 500 on anything that touches the new columns (pairing codes and `/pair` did).
  Restart it. On 2026-10-23 the owner asked Claude to restart it: it now runs from Claude's session in the
  background (`pnpm dev` in `~/eguard`) and stops when that session ends; start it again in your own terminal then.
- The service holds the engine's lock during network calls, so a request on `\\.\pipe\eguard` (status, pairing)
  can wait for a tick in progress. Enforcement doesn't: the enforcer has its own lock, and the session pipes and
  the monitor never take the engine's. Lock order where both are held: engine, then enforcer.
- The session pipes check both ends (the agent believes only `eguard-service.exe` beside it; the service answers only
  `eguard-agent.exe` beside it, in that session). `eguard-agent pair|status|scan` on `\\.\pipe\eguard` still don't
  check who serves.
- `AGENT_RESTARTED` is sent when an agent dies with a non-zero exit code while its session goes on. The service's own
  restart still needs the guard (Phase 6) to tell a crash from a stop.
- **Console mode and the owner's own programs.** A test family has App Approval on by default, so this PC's apps are
  PENDING and would be ended. Console mode ends only inside `--sandbox` and logs the rest as "would end". Never add a
  way around that. Also: the owner may be at the PC during a live check and close the screens by hand (it happened).
- Usage counts the owner's own activity during a console run (the test family's 3-hour day and 21:30 bedtime would
  put the overlay on the owner's screen): turn bedtime off or delete the family when done.
- `GetLastInputInfo` counts injected input: `tools/enforce/play.ps1` nudges the mouse by a pixel to "play".
- PowerShell's managed UI Automation sees Win32 buttons as panes (its Win32 proxies don't load); use MSAA
  (`tools/enforce/press.ps1`), which is also what screen readers use.
- Bash heredocs with nested quotes broke twice in this session (`unexpected EOF`); write edit scripts to the
  scratchpad and run them instead.
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
