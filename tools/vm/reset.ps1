# On the test VM, as an administrator: takes eGuard off between runs (docs/VM-TESTS.md). A snapshot is quicker;
# this is for when there isn't one.
#
#   reset.ps1 [-KeepProxy]
#
# Once installed, eGuard's service can't be stopped or deleted by an administrator, and its data folder is
# read-only for them. So a one-off task runs "eguard-service purge --force" as SYSTEM (a development build only:
# --force ignores whether a parent asked for the removal), which takes out everything but the program files; the
# package is then uninstalled (its check passes: nothing is paired any more). An administrator can always run
# something as SYSTEM this way, which is the limit spec section 10 states. The child's sandbox (tools\enforce\setup.ps1)
# is per user: run "setup.ps1 -Remove" as the child.
param([switch]$KeepProxy)
$dest = Join-Path $env:ProgramFiles "eGuard"
$exe = Join-Path $dest "eguard-service.exe"
if (Test-Path $exe) {
    $task = "eGuard-reset"
    schtasks /Create /TN $task /RU SYSTEM /SC ONCE /ST 23:59 /F /TR "`"$exe`" purge --force" | Out-Null
    schtasks /Run /TN $task | Out-Null
    # The task runs on its own; wait until the service is gone (or a minute has passed)
    $until = (Get-Date).AddMinutes(1)
    while ((Get-Service eGuard -ErrorAction SilentlyContinue) -and (Get-Date) -lt $until) { Start-Sleep -Seconds 2 }
    schtasks /Delete /TN $task /F | Out-Null
    if (Get-Service eGuard -ErrorAction SilentlyContinue) { "the service is still there; see C:\ProgramData\eGuard\logs\service.log" }
}
$product = Get-CimInstance Win32_Product -Filter "Name = 'eGuard'" -ErrorAction SilentlyContinue
if ($product) {
    $log = Join-Path $env:TEMP "eguard-msi-reset-$(Get-Date -Format yyyyMMdd-HHmmss).log"
    $p = Start-Process msiexec.exe -ArgumentList "/x", $product.IdentifyingNumber, "/qn", "/norestart", "/l*v", "`"$log`"" -Wait -PassThru
    if ($p.ExitCode -ne 0) { "uninstalling the package failed ($($p.ExitCode)); see $log" }
}
Get-Process eguard-agent, eguard-guard -ErrorAction SilentlyContinue | Stop-Process -Force
$data = Join-Path $env:ProgramData "eGuard"
if (Test-Path $data) {
    takeown /f $data /r /d y | Out-Null
    icacls $data /grant "*S-1-5-32-544:(OI)(CI)F" /t /q | Out-Null
    Remove-Item $data -Recurse -Force
}
Get-ChildItem $env:ProgramData -Filter "eGuard.untrusted-*" -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
if (Test-Path $dest) {
    takeown /f $dest /r /d y | Out-Null
    icacls $dest /grant "*S-1-5-32-544:(OI)(CI)F" /t /q | Out-Null
    Remove-Item $dest -Recurse -Force
}
if (-not $KeepProxy) { netsh interface portproxy delete v4tov4 listenaddress=127.0.0.1 listenport=3000 2>$null | Out-Null }
"eGuard taken off this VM"
