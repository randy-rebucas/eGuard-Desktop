# VM tests

What has to be checked on a Windows 11 VM, because it needs SYSTEM, a second account, real games or real browsers.
Each item says what to do, what should happen, and what to bring back. The steps come from STATUS.md's "Needs the
VM" lists (Phases 2 to 6) and the spec's acceptance tests (section 14).

Since Phase 6 part 2, eGuard is installed from `eguard.msi` and locks itself in place: an administrator can no
longer stop or delete the service by hand. Go back to the **clean** snapshot between runs; `tools\reset.ps1` takes
eGuard off through a one-off SYSTEM task when there's no snapshot.

## 1. The VM

- Windows 11 (Home or Pro), VirtualBox with the default **NAT** network (the VM then reaches this PC as
  `10.0.2.2`, with no firewall change here). Guest additions are optional.
- Two local accounts: **`parent`**, an administrator, and **`mia`**, a standard account. Sign in to both once.
- Before installing anything, take a snapshot called **clean**. Go back to it between runs rather than cleaning up
  by hand (`tools\reset.ps1` is there for when you can't).
- For Q3 (anti-cheat): Steam with CS2, the Epic launcher with Fortnite, and the Riot client with Valorant. **Use
  throwaway game accounts**: an anti-cheat that takes eGuard's ending of the game badly could flag the account.
  Valorant's Vanguard needs a reboot after installing and may refuse to run in a VM at all; write down what it says.

## 2. Build, copy, install

On this PC:

```powershell
cd C:\Users\corew\eguard-desktop
pwsh tools\vm\bundle.ps1          # or powershell; makes target\eguard-vm.zip (needs WiX 5 for eguard.msi)
# the dev server must be running here: pnpm dev in ~/eguard
```

Copy `target\eguard-vm.zip` to the VM (a shared folder, or drag and drop) and unzip it, e.g. to `C:\eguard-vm`.
On the VM, in an **administrator** PowerShell (as `parent`):

```powershell
Set-ExecutionPolicy -Scope Process Bypass
C:\eguard-vm\tools\install.ps1                    # VirtualBox NAT; with another network: -ServerHost <this PC's IP>
```

It forwards `localhost:3000` on the VM to the dev server, checks it answers, and installs `eguard.msi` silently
(its log: `%TEMP%\eguard-msi-install-*.log`). The package puts the programs in `C:\Program Files\eGuard`, then runs
`eguard-service install` as SYSTEM: the service (LocalSystem, automatic) and its permissions, Safe Mode, the guard's
task and cache, the folder's permissions. After each test, while still on the VM:

```powershell
C:\eguard-vm\tools\collect.ps1 -Label test3       # a zip on the desktop: logs, state, service, processes, policies
```

On this PC, act as the parent with `node tools/dev-family.mjs …` (create, code, show, apps, alerts, app, limit,
protect, remove, keep). Delete the family at the end.

## 3. Tests

Mark each **pass**, **fail** (with what happened) or **couldn't** (why) in the results table at the end.

### A. Service and pairing (Phase 2, acceptance test 1)

1. This PC: `node tools/dev-family.mjs create`. VM, as `parent` (administrator):
   `& "C:\Program Files\eGuard\eguard-agent.exe" pair CODE`. It lists the accounts with `mia` preselected (the
   standard one); press Enter.
   - Expect "Paired. This computer is now Mia's", and `mia` "the child's: rules apply", `parent` "not limited".
   - This PC: `dev-family show`: WINDOWS, COMPUTER, the four AVAILABLE protections **applied** (the service enforces
     them, unlike console mode), **UNINSTALL_PROTECTION applied** (`mia` is standard and the service is locked), WEB
     not applied with its reason, `accounts` as above.
2. `collect.ps1 -Label pairing`, then check:
   - `service.txt`: LocalSystem, AUTO_START, restart 5 s / 5 s / 60 s, failure flag on; `sdshow`
     `D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)`
     (administrators may stop, not change or delete).
   - `data-folder.txt`: owner SYSTEM; SYSTEM full control; Administrators read only; no one else. A `cache` folder
     with the three exes.
   - `program-files.txt`: the three exes; SYSTEM full control, Administrators and Users read and execute only.
   - `lockdown.txt`: the task `\eGuard\Guard` (SYSTEM, at boot, running), both SafeBoot keys (`(Default)` =
     `Service`), the Settings entry (`UninstallString` = `"C:\Program Files\eGuard\eguard-agent.exe" remove`,
     `NoModify` 1, `NoRepair` 1), and the package. Settings › Apps › Installed apps lists **one** eGuard.
   - `processes.txt`: `eguard-guard.exe` running (SYSTEM, session 0).
3. Restart the VM. `eguard-agent status`: still paired (the secrets read back through DPAPI as SYSTEM), last sync
   recent.
4. As `mia`: `eguard-agent status` → "This account isn't allowed to talk to eGuard's service." (the admin pipe is
   for SYSTEM and administrators).
5. Crashes (Phase 7). As `parent`: `taskkill /F /IM eguard-service.exe` → the SCM (or the guard, within 10 s)
   starts it again within ~5 s (`sc query eGuard` RUNNING, `eguard-agent status` answers). As `mia`: `& "C:\Program Files\eGuard\eguard-agent.exe"
   crash panic`, then `crash fault` (a dev build only) → exit codes 101 and `-1073741819` (0xC0000005), and
   `%LOCALAPPDATA%\eGuard\logs\agent.log` ends with "crashed: panic at …" and "crashed: exception 0xC0000005 at
   eguard-agent.exe+0x…". No "has stopped working" box, no Application Error (event 1000) in the Application log, and
   nothing new under `C:\ProgramData\Microsoft\Windows\WER` (no dump: the process ends before Windows Error
   Reporting sees it).

### B. Scanning as SYSTEM (Phase 3, acceptance test 2)

1. Install Office (or skip), Chrome, Steam with CS2, Roblox, and put an unsigned itch.io game (any small one) in
   `mia`'s Downloads. If the VM has an NVIDIA GPU passed through, its driver too (usually not possible: write it down).
2. `eguard-agent scan`, wait two minutes, `dev-family apps` and `dev-family alerts`.
   - Expect: CS2, Roblox and the itch.io game, the itch.io one "Unverified publisher". No Office, Chrome, drivers or
     runtimes. One alert for what was found.
   - Note anything else that shows up, with its publisher (the log names it).
3. As `mia`: Steam's library and Epic's are read from both accounts (the scan runs as SYSTEM): check the log's
   "scanned N candidates" and that games installed only for `mia` are found.

### C. Enforcement as SYSTEM (Phase 4, acceptance tests 3 to 7)

Sign in as `mia`. `collect.ps1` (as `parent`, through fast user switching, or after) shows an `eguard-agent.exe` in
`mia`'s session, started by the service, and the log says "watching process starts (ETW)".

1. **Stand-ins** (when the real games aren't there): as `mia`,
   `C:\eguard-vm\tools\setup.ps1 -Prebuilt C:\eguard-vm\standins`, then as `parent` `eguard-agent scan`.
2. **Test 3:** `dev-family app "Counter-Strike 2" BLOCKED`. As `mia`, start CS2 from Steam (or
   `tools\launch.ps1 <sandbox>\Steam\…\cs2.exe`).
   - Expect it ended within 2 s, the block screen "Counter-Strike 2 is blocked", and after "Ask parent" the
     dashboard's "App approval requested".
3. **Test 4:** copy `cs2.exe` to `totally-not-cs2.exe` in the same folder and start it: ended as Counter-Strike 2.
4. **Test 5:** `dev-family limit GAMES 1`, play Roblox (or `tools\play.ps1` with Pixel Quest): "1 minute of gaming
   time left today.", then ended, "Gaming time used up" on the screen and the dashboard.
5. **Test 6:** as `parent`, move the clock forward an hour (Settings › Time, automatic time off). Back as `mia`: the
   day's time didn't grow by an hour (`dev-family screen-time`), and the dashboard got "The computer's clock was
   changed". Put the clock back.
6. **Test 7:** as `mia`, `taskkill /f /im eguard-agent.exe` (it's allowed to fail: the child may only wait on it).
   Then as `parent`, Task Manager › End task on `mia`'s `eguard-agent.exe`. Expect a new agent within seconds and
   "eGuard was closed and started again" (one per 10 minutes).
7. **Q3, anti-cheat (most important):** block each game in turn and start it as `mia`: CS2 (VAC), Fortnite (Easy
   Anti-Cheat), Valorant (Vanguard). For each, write down: ended or not, how long it took, the exit code in the log,
   anything the anti-cheat or launcher said, and whether the game account got any warning later. If a game isn't
   ended, say so: the fallbacks in STATUS.md (Q3) wait on this.
8. **Overlay and its backstops:** `dev-family protect SCREEN_TIME '{"dailyMinutes":15,"weekendMinutes":15}'` and use
   15 minutes (or set bedtime to start in a few minutes). Expect the overlay on every monitor.
   - Its app buttons: mark an app ALWAYS_ALLOWED, use it once before time runs out, then press its button on the
     overlay: it comes to the front and the overlay steps aside.
   - Kill the agent three times in a minute, or keep another window in front for 15 s: the session is
     disconnected, or locked (`LockWorkStation`).
9. **Accounts:** switch to `parent` (fast user switching) and start a game blocked for `mia`: it runs (not the
   child's account). `mia`'s disconnected session isn't counted meanwhile (`screen-time` doesn't grow). Create a
   third local account: "A new account was added to the computer", and it isn't limited.
10. **Administrator child:** add `mia` to Administrators. Within a few minutes: "Your child's account is an
    administrator" on the dashboard, and the device page's removal protection says why ("mia is an administrator on
    this computer…"). Take `mia` out again: the reason changes back. (`ADMIN_ACCOUNT` repeats daily while it lasts.)
11. **Sign-out:** sign `mia` out with the overlay up: no "eGuard was closed" alert (the agent exits as the session
    ends).
12. **Cost:** Task Manager › Details: `eguard-service.exe` CPU over a few minutes with `mia` signed in.

Remote Desktop, two monitors and a game controller are worth a look if the VM allows them; mark "couldn't" if not.

### D. Web (Phase 5)

Without the extension's store ids (a plain `bundle.ps1`), only the first two:

1. `eguard-service web` (as `parent`): "no extension id in this build" for all three, and the device page's WEB
   reason says so.
2. **Pixel Browser** (stand-in, as `mia`): with WEB on in any mode, it's ended ("Pixel Browser is waiting for your
   parent"). A real Opera or Brave: the same.

With the ids (`bundle.ps1 -ChromeId … -EdgeId … -FirefoxUrl …`):

3. `chrome://policy`, `edge://policy` and Firefox's `about:policies` show every value eGuard writes; the extension is
   installed and can't be removed; `deviceLink` is there.
4. Incognito, InPrivate and Guest are gone; Firefox's Troubleshoot Mode is refused; the extension runs in Firefox's
   private windows.
5. Delete Chrome's forcelist entry in `regedit` (as `parent`): back within a minute.
6. Start Chrome with `--disable-extensions`: does the policy-installed extension still load? Write it down.

### E. Removal (Phase 6 part 1, acceptance tests 9 and 10)

1. **Wrong codes:** as `mia`, `& "C:\Program Files\eGuard\eguard-agent.exe" remove`: the "Remove eGuard" window.
   Type a wrong code five times: "4 more tries…", then "Too many wrong codes. Try again in 15 minutes.", and the
   dashboard gets "Someone is guessing eGuard's removal code".
2. **Kept:** `dev-family remove`, then `dev-family keep`, then type the printed code as `mia` (after the lockout, or
   with a fresh pairing): "your parent chose to keep eGuard…", nothing removed, and the parent's "A removal code was
   used after you kept the computer".
3. **Test 9:** `dev-family remove`. Within about a minute: the device is gone from `dev-family show`, "Device
   removed" in the alerts, the agent closed in `mia`'s session. Then **nothing is left** (as `parent`,
   `collect.ps1 -Label test9`, and look):
   - `sc.exe query eGuard`: doesn't exist (1060). No `eguard-*.exe` in Task Manager.
   - `schtasks /Query /TN \eGuard\Guard`: not found. `reg query` of both SafeBoot keys: not found.
   - Settings › Apps: no eGuard; `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\eGuard`: not found; no
     package (`lockdown.txt`).
   - `C:\Program Files\eGuard`: gone. `C:\ProgramData\eGuard`: only `logs` (kept on purpose: what happened, for
     support; no secrets). No browser policies.
   - `service.log` lists each "removed: …" step and the installer's run; the MsiInstaller events say the removal
     succeeded.
4. **Test 10:** go back to **clean**, install, pair again, then turn the VM's network off (VirtualBox › Devices ›
   Network › untick "Connect Network Adapter"). `dev-family remove` on this PC; type the printed code as `mia` in the
   window: "The code is right. eGuard is removing itself", and the same checks as test 9. The dashboard keeps showing
   "Removing" (the computer couldn't tell it: STATUS.md, Phase 6 item 1); finish with `dev-family remove now`.

### F. Every local route is blocked (Phase 6 part 2, acceptance test 8)

Paired, `mia` standard. Do each **as `mia`** and again **as `parent`** (an administrator). Each must fail and the
dashboard must get the alert (one per kind per hour: wait an hour between `mia` and `parent`, or check the log's
"tamper: …" lines for the second). Bring back `collect.ps1 -Label test8` at the end.

1. **Settings › Apps › eGuard › Uninstall:** the "Remove eGuard" window opens (not an uninstaller). Close it without a
   code → "Someone tried to uninstall eGuard". Note whether Settings asked for an administrator first.
2. **`msiexec /x {product code}`** (the code is in `lockdown.txt`; as `mia` it asks for an administrator, which is
   itself the block): as `parent` in an elevated prompt, the uninstall fails and is rolled back (exit 1603), eGuard
   still runs, "Someone tried to uninstall eGuard". The MSI log (`/l*v`) shows `msi-check` refusing.
3. **`sc stop eGuard`** → "Access is denied" (5) and "Someone tried to stop eGuard"; Services › eGuard › Stop says the
   same. **`sc delete eGuard`** and **`sc config eGuard start= disabled`** → "Access is denied" (no alert: the
   service never hears of those). Task Manager › Services › Stop: refused.
4. **Deleting the install folder:** `Remove-Item -Recurse "C:\Program Files\eGuard"` → access denied (and in use).
   As `parent`, `takeown /f "C:\Program Files\eGuard" /r` + `icacls … /grant parent:F` succeeds (an administrator
   can), but deleting a file still fails while it's held open. Then end the guard (`taskkill /f /im eguard-guard.exe`)
   and the service, and delete `eguard-agent.exe` quickly: within ~10–60 s it's back (the guard restarts from its
   task, or the service starts the task), "eGuard's files were changed", and `guard.log` says "put back".
5. **The guard's task:** `schtasks /Delete /TN \eGuard\Guard /F` and `schtasks /Change /TN \eGuard\Guard /Disable`
   as `parent`: refused? Write down what happens (the task's own permissions say SYSTEM only).
6. **Safe Mode:** as `parent`, `bcdedit /set {current} safeboot minimal`, restart, sign in as `mia`: eGuard runs
   (`tasklist` shows `eguard-service.exe`), and once back online the dashboard gets "The computer was started in Safe
   Mode". Then `bcdedit /deletevalue {current} safeboot` and restart. Try `safeboot network` too.
7. Write down for each whether the child (standard) and the administrator were stopped. An administrator can always
   win in the end (spec section 10, Q1): what counts is that each try is refused or undone, and alerts.

### G. Self-update (Phase 7, Q7)

Installed from the 0.1.0 bundle and paired (A), `mia` signed in. eGuard's real certificate doesn't exist yet, so a
development build accepts files signed by **"eGuard Dev"**: `tools\update-release.ps1` makes that certificate on the
VM and trusts it there (**VM only**: it adds a root certificate). The files are served from the VM itself
(`http://localhost:8099`, which a development build may download from); the manifest comes from the dev server.

On this PC: `powershell -File tools\vm\bundle.ps1 -Version 0.1.1` → `target\eguard-vm-0.1.1.zip`. Copy it to the VM and
unzip it to `C:\eguard-next`. Watch `C:\ProgramData\eGuard\logs\service.log` and `guard.log` throughout (as `parent`,
`Get-Content -Wait`).

1. **An update.** As `parent`, elevated: `C:\eguard-vm\tools\update-release.ps1 -Bin C:\eguard-next\bin -Version 0.1.1`
   and leave it running. Put the two lines it prints in `~/eguard/.env.local` on this PC. Within about two minutes
   (the next sync sees `minAppVersion`):
   - `service.log`: "eGuard needs version 0.1.1 …", "eGuard 0.1.1 is available", "downloading eGuard 0.1.1", "… is in
     the guard's cache; stopping so the guard can put it in place"; the server window shows three `200` lines.
   - `guard.log`: "eGuard 0.1.1 is in place of 0.1.0; starting it", then (after the new service's first sync) "eGuard
     0.1.1 works; the previous version 0.1.0 is gone. This guard ends for the new one"; within a minute a new guard
     logs "eguard-guard 0.1.1 watching …".
   - `service.log`: "eGuard 0.1.1 for …", "eGuard 0.1.1 synced and saved its state; the guard keeps it".
   - `mia`'s screens close and come back (a new agent). Write down how long the computer was without its service (the
     gap between "stopping" and "eGuard 0.1.1 for").
   - Settings › Apps shows eGuard 0.1.1; `node tools/dev-family.mjs show` shows appVersion 0.1.1; **no** alerts
     ("files were changed", "stopped and started again", "app restarted").
   - `C:\ProgramData\eGuard\cache` has the three programs (0.1.0's sizes differ) and no `previous`, `update.json` or
     `update-health.json`; `C:\Program Files\eGuard` has no `*.old-*` left once the new guard has started.
2. **Refused files.** Stop the server window (Ctrl+C). `update-release.ps1 -Bin C:\eguard-next\bin -Version 0.1.2
   -NoSign`, and its two lines in `.env.local`: `service.log` says "the update failed: eguard-service.exe carries no
   valid signature; this version carries on", three times a few minutes apart, then not again for 6 hours. Nothing
   in Program Files or the cache changes. Then the same signed, but before the agent asks, change one byte of
   `C:\eguard-release\0.1.2\eguard-agent.exe` (e.g. append a byte): "… SHA-256 doesn't match the manifest".
3. **A rollback.** Revert the VM to the snapshot taken after G1 (or restart the service so its tries start over:
   `Restart-Computer`). `update-release.ps1 -Bin C:\eguard-next\bin -Version 0.1.2 -Broken` (its
   `eguard-service.exe` is really the agent, so the new version never starts), and its lines in `.env.local`. Expected:
   the swap as in G1, then `guard.log` "eGuard's service has stopped and couldn't be started" every 10 s, and after
   10 minutes "eGuard 0.1.2: it didn't sync and save its state within 10 minutes; putting 0.1.1 back", "eGuard 0.1.1
   is back in place and started". `service.log` (0.1.1): "the update to eGuard 0.1.2 was rolled back (…); it won't
   be tried again", and no further download of 0.1.2. No "stopped and started again" alert.
4. **A swap that has to end the service.** Not reachable by hand without a debugger; skip unless G1 showed the
   service taking more than 2 minutes to stop (then `guard.log` says "ended eGuard's service … for the update").
5. **Removal after an update.** After G1 (0.1.1 running, while the package's own records still say 0.1.0): E3's
   removal from the dashboard leaves nothing behind, as E3 lists, and `msiexec`'s log shows the 0.1.1 files removed.
6. Bring back `collect.ps1 -Label update` after each of G1–G3 and G5, and the server window's lines.

Afterwards take `DESKTOP_RELEASE` and `CHILD_MIN_APP_VERSION` out of `.env.local` on this PC.

## 4. Results

Copy this table into STATUS.md with the outcome of each, and keep the zips from `collect.ps1`.

| Test | Result | Notes |
|---|---|---|
| A1 pair, capabilities | | |
| A2 service config, data folder ACL | | |
| A3 restart, DPAPI as SYSTEM | | |
| A4 child refused on the admin pipe | | |
| A5 crashes: SCM restart, last line, no dump | | |
| B2 test 2 (found apps, one alert) | | |
| B3 scan sees `mia`'s games | | |
| C2 test 3 | | |
| C3 test 4 | | |
| C4 test 5 | | |
| C5 test 6 | | |
| C6 test 7 | | |
| C7 Q3: CS2 / Fortnite / Valorant | | |
| C8 overlay, app buttons, backstops | | |
| C9 accounts, fast user switching, new account | | |
| C10 administrator child | | |
| C11 sign-out | | |
| C12 cost | | |
| D1–D2 web without ids | | |
| D3–D6 web with ids | | |
| E1 wrong codes, lockout | | |
| E2 kept | | |
| E3 test 9 (nothing left) | | |
| E4 test 10 | | |
| F1 Settings › Uninstall (child / admin) | | |
| F2 `msiexec /x` | | |
| F3 `sc stop`, `sc delete`, `sc config` | | |
| F4 deleting the install folder; guard puts back | | |
| F5 the guard's task | | |
| F6 Safe Mode (minimal / network) | | |
| G1 update 0.1.0 → 0.1.1 (gap without the service: … s) | | |
| G2 unsigned / changed files refused | | |
| G3 rollback of a version that never starts | | |
| G5 removal after an update | | |
