# On the test VM, as an administrator: gathers what a test left behind into one zip on the desktop, to bring back to
# the owner's PC (docs/VM-TESTS.md). Never the secrets: secrets.bin isn't copied.
#
#   collect.ps1 -Label test3
param([Parameter(Mandatory)][string]$Label)
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$out = Join-Path ([Environment]::GetFolderPath("Desktop")) "eguard-results\$stamp-$Label"
New-Item -ItemType Directory -Force $out | Out-Null
$data = Join-Path $env:ProgramData "eGuard"

function Save($name, [scriptblock]$what) {
    try { & $what *>&1 | Out-File -Encoding utf8 (Join-Path $out $name) } catch { "failed: $_" | Out-File -Encoding utf8 (Join-Path $out $name) }
}

if (Test-Path (Join-Path $data "logs")) { Copy-Item (Join-Path $data "logs") (Join-Path $out "logs") -Recurse }
foreach ($f in "state.json", "state.prev.json") {
    if (Test-Path (Join-Path $data $f)) { Copy-Item (Join-Path $data $f) $out }
}
Save "data-folder.txt" { Get-ChildItem -Force $data -Recurse | Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize | Out-String -Width 300; icacls $data }
Save "program-files.txt" { Get-ChildItem -Force (Join-Path $env:ProgramFiles "eGuard") -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String -Width 300 }
Save "service.txt" { sc.exe queryex eGuard; sc.exe qc eGuard; sc.exe qfailure eGuard; sc.exe qfailureflag eGuard; sc.exe sdshow eGuard }
Save "processes.txt" { tasklist /v /fi "imagename eq eguard*" ; query session }
Save "accounts.txt" { Get-LocalUser | Format-Table Name, Enabled | Out-String; Get-LocalGroupMember Administrators | Format-Table Name, PrincipalSource | Out-String }
Save "browser-policies.txt" {
    foreach ($k in "HKLM:\SOFTWARE\Policies\Google\Chrome", "HKLM:\SOFTWARE\Policies\Microsoft\Edge", "HKLM:\SOFTWARE\Policies\Mozilla\Firefox") {
        "== $k"
        if (Test-Path $k) { reg query ($k -replace "^HKLM:", "HKLM") /s } else { "(none)" }
    }
}
Save "scm-events.txt" {
    Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Service Control Manager"; StartTime = (Get-Date).AddHours(-6) } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match "eGuard" } | Format-List TimeCreated, Id, Message | Out-String -Width 300
}
Save "status.txt" { & (Join-Path $env:ProgramFiles "eGuard\eguard-agent.exe") status }

$zip = "$out.zip"
Compress-Archive -Path (Join-Path $out "*") -DestinationPath $zip -Force
"collected: $zip"
