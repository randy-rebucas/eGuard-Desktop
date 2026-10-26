# On the test VM, as an administrator: installs the bundle's eguard.msi (docs/VM-TESTS.md, step 2).
#
#   install.ps1 [-ServerHost 10.0.2.2] [-Bin ..\bin]
#
# The development build talks to http://localhost:3000 only (plain http is allowed for this machine alone), so
# localhost:3000 on the VM is forwarded to the dev server on the owner's PC. 10.0.2.2 is that PC as VirtualBox's NAT
# sees it; with VMware or a bridged network, give the PC's address (its firewall must then let port 3000 in, which is
# the owner's call).
#
# A bundle built for a real eGuard server (bundle.ps1 -ServerUrl) has bin\server.txt: nothing is forwarded then, and
# that server is checked instead.
param([string]$ServerHost = "10.0.2.2", [string]$Bin = (Join-Path $PSScriptRoot "..\bin"))
$ErrorActionPreference = "Stop"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "run this from an administrator PowerShell" }

# Smart App Control (a fresh Windows 11 may have it on) blocks unsigned programs, eGuard's included until it's signed:
# the package then fails at its install step. 0 off, 1 on, 2 evaluation (which doesn't block)
$sac = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
if ($sac -eq 1) { throw "Smart App Control is on and blocks unsigned programs such as this build of eGuard: turn it off in Windows Security > App & browser control (it can't be turned back on without resetting Windows; it's a test VM)" }

$serverFile = Join-Path $Bin "server.txt"
if (Test-Path $serverFile) {
    $server = (Get-Content $serverFile -TotalCount 1).Trim()
    $ServerHost = $server
} else {
    $server = "http://localhost:3000"
    # The port forward is the IP Helper service's: stopped or disabled, the rule is accepted and does nothing
    $iphlp = Get-Service iphlpsvc -ErrorAction SilentlyContinue
    if (-not $iphlp) { throw "the IP Helper service (iphlpsvc) isn't on this Windows; localhost:3000 can't be forwarded" }
    if ($iphlp.StartType -eq "Disabled") { Set-Service iphlpsvc -StartupType Automatic }
    if ($iphlp.Status -ne "Running") { Start-Service iphlpsvc }
    netsh interface portproxy delete v4tov4 listenaddress=127.0.0.1 listenport=3000 2>$null | Out-Null
    netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=3000 connectaddress=$ServerHost connectport=3000 | Out-Null
}
$status = 0
try {
    Invoke-WebRequest -UseBasicParsing -Method Post "$server/api/device/v1/sync" | Out-Null
} catch {
    # Windows PowerShell and PowerShell 7 throw different types; both carry the response, when there was one
    $response = $_.Exception.Response
    if ($response) { $status = [int]$response.StatusCode }
    $why = $_.Exception.Message
}
if ($status -ne 401) { throw "eGuard's server isn't reachable at $server ($why); is it running ($ServerHost)?" }
"eGuard's server reachable at $server"

# The package installs the programs into Program Files, then registers and locks the service, Safe Mode, the guard
# and its cache (eguard-service install, as SYSTEM). Its log goes to %TEMP%, where collect.ps1 finds it
$msi = Join-Path $Bin "..\eguard.msi"
if (-not (Test-Path $msi)) { throw "eguard.msi isn't in the bundle ($msi)" }
$log = Join-Path $env:TEMP "eguard-msi-install-$(Get-Date -Format yyyyMMdd-HHmmss).log"
$p = Start-Process msiexec.exe -ArgumentList "/i", "`"$(Resolve-Path $msi)`"", "/qn", "/norestart", "/l*v", "`"$log`"" -Wait -PassThru
if ($p.ExitCode -ne 0) {
    # The package only says "a program run as part of the setup did not finish"; eguard-service install logs why
    $serviceLog = Join-Path $env:ProgramData "eGuard\logs\service.log"
    if (Test-Path $serviceLog) {
        "--- eGuard's log ($serviceLog), last lines:"
        Get-Content $serviceLog -Tail 15
    } else {
        "--- no eGuard log at ${serviceLog}: the install step didn't get far enough to write one"
    }
    "--- the package's log, around the failure:"
    Select-String -Path $log -Pattern "Return value 3|Error 17\d\d|CustomAction" | Select-Object -First 15 | ForEach-Object { $_.Line }
    throw "installing eguard.msi failed ($($p.ExitCode)); the full log: $log"
}
sc.exe queryex eGuard
"installed. Next: pair (VM-TESTS.md, test 1)."
