# On the test VM, as an administrator: takes eGuard off between runs (docs/VM-TESTS.md). A snapshot is quicker;
# this is for when there isn't one.
#
#   reset.ps1 [-KeepProxy]
#
# The service and its browser policies come out with `eguard-service uninstall`. The data folder is read-only for
# administrators (only SYSTEM writes it), so it's taken over first. The child's sandbox (tools\enforce\setup.ps1)
# is per user: run `setup.ps1 -Remove` as the child.
param([switch]$KeepProxy)
$dest = Join-Path $env:ProgramFiles "eGuard"
$exe = Join-Path $dest "eguard-service.exe"
if (Get-Service eGuard -ErrorAction SilentlyContinue) {
    if (Test-Path $exe) { & $exe uninstall } else { sc.exe stop eGuard; sc.exe delete eGuard }
}
Get-Process eguard-agent -ErrorAction SilentlyContinue | Stop-Process -Force
$data = Join-Path $env:ProgramData "eGuard"
if (Test-Path $data) {
    takeown /f $data /r /d y | Out-Null
    icacls $data /grant "*S-1-5-32-544:(OI)(CI)F" /t /q | Out-Null
    Remove-Item $data -Recurse -Force
}
Get-ChildItem $env:ProgramData -Filter "eGuard.untrusted-*" -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
if (-not $KeepProxy) { netsh interface portproxy delete v4tov4 listenaddress=127.0.0.1 listenport=3000 2>$null | Out-Null }
"eGuard taken off this VM"
