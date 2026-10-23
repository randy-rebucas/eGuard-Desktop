# On the test VM, as an administrator: installs the bundle's build as the eGuard service (docs/VM-TESTS.md, step 2).
#
#   install.ps1 [-ServerHost 10.0.2.2] [-Bin ..\bin]
#
# The development build talks to http://localhost:3000 only (plain http is allowed for this machine alone), so
# localhost:3000 on the VM is forwarded to the dev server on the owner's PC. 10.0.2.2 is that PC as VirtualBox's NAT
# sees it; with VMware or a bridged network, give the PC's address (its firewall must then let port 3000 in, which is
# the owner's call).
param([string]$ServerHost = "10.0.2.2", [string]$Bin = (Join-Path $PSScriptRoot "..\bin"))
$ErrorActionPreference = "Stop"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "run this from an administrator PowerShell" }

netsh interface portproxy delete v4tov4 listenaddress=127.0.0.1 listenport=3000 2>$null | Out-Null
netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=3000 connectaddress=$ServerHost connectport=3000 | Out-Null
$status = 0
try {
    Invoke-WebRequest -UseBasicParsing -Method Post http://localhost:3000/api/device/v1/sync | Out-Null
} catch {
    # Windows PowerShell and PowerShell 7 throw different types; both carry the response, when there was one
    $response = $_.Exception.Response
    if ($response) { $status = [int]$response.StatusCode }
    $why = $_.Exception.Message
}
if ($status -ne 401) { throw "the dev server isn't reachable through localhost:3000 ($why); is it running on ${ServerHost}:3000?" }
"dev server reachable through localhost:3000"

$dest = Join-Path $env:ProgramFiles "eGuard"
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item (Join-Path $Bin "*.exe") $dest -Force
& (Join-Path $dest "eguard-service.exe") install
if ($LASTEXITCODE -ne 0) { throw "eguard-service install failed" }
sc.exe queryex eGuard
"installed in $dest. Next: pair (VM-TESTS.md, test 1)."
