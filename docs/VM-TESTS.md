# VM tests

What has to be checked on a Windows 11 VM, because it needs SYSTEM, a second account, real games or real browsers.
Each item says what to do, what should happen, and what to bring back. The steps come from STATUS.md's "Needs the
VM" lists (Phases 2 to 6) and the spec's acceptance tests (section 14).

Phase 6 part 2 (the installer and what holds eGuard in place) isn't built, so acceptance test 8 and the Safe Mode
check aren't here yet.

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
pwsh tools\vm\bundle.ps1          # or powershell; makes target\eguard-vm.zip
# the dev server must be running here: pnpm dev in ~/eguard
```

Copy `target\eguard-vm.zip` to the VM (a shared folder, or drag and drop) and unzip it, e.g. to `C:\eguard-vm`.
On the VM, in an **administrator** PowerShell (as `parent`):

```powershell
Set-ExecutionPolicy -Scope Process Bypass
C:\eguard-vm\tools\install.ps1                    # VirtualBox NAT; with another network: -ServerHost <this PC's IP>
```

It forwards `localhost:3000` on the VM to the dev server, checks it answers, copies the exes to
`C:\Program Files\eGuard` and installs the service (LocalSystem, automatic). After each test, while still on the
VM:

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
     them, unlike console mode), WEB and UNINSTALL_PROTECTION not applied with their reasons, `accounts` as above.
2. `collect.ps1 -Label pairing`, then check:
   - `service.txt`: LocalSystem, AUTO_START, restart 5 s / 5 s / 60 s, failure flag on.
   - `data-folder.txt`: owner SYSTEM; SYSTEM full control; Administrators read only; no one else.
3. Restart the VM. `eguard-agent status`: still paired (the secrets read back through DPAPI as SYSTEM), last sync
   recent.
4. As `mia`: `eguard-agent status` → "This account isn't allowed to talk to eGuard's service." (the admin pipe is
   for SYSTEM and administrators).

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
   removed" in the alerts, the agent closed in `mia`'s session. As `parent`: `sc.exe query eGuard` says the service
   doesn't exist (1060); `collect.ps1 -Label test9`: no browser policies, `%ProgramData%\eGuard` holds only `logs`.
   `C:\Program Files\eGuard` is still there (removing it is part 2's installer's job).
4. **Test 10:** reinstall (`install.ps1`), pair again, then turn the VM's network off (VirtualBox › Devices ›
   Network › untick "Connect Network Adapter"). `dev-family remove` on this PC; type the printed code as `mia` in the
   window: "The code is right. eGuard is removing itself", and the same checks as test 9. The dashboard keeps showing
   "Removing" (the computer couldn't tell it: STATUS.md, Phase 6 item 1); finish with `dev-family remove now`.

## 4. Results

Copy this table into STATUS.md with the outcome of each, and keep the zips from `collect.ps1`.

| Test | Result | Notes |
|---|---|---|
| A1 pair, capabilities | | |
| A2 service config, data folder ACL | | |
| A3 restart, DPAPI as SYSTEM | | |
| A4 child refused on the admin pipe | | |
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
| E3 test 9 | | |
| E4 test 10 | | |
