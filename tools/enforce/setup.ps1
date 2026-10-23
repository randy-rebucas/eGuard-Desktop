# Phase 4's stand-ins for checking enforcement (spec acceptance tests 3 to 5) without real games:
#
#   <Dir>\Steam\steamapps\appmanifest_730.acf and ...\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe
#   <Dir>\Pixel Quest\PixelQuest.exe with UnityPlayer.dll beside it (an unsigned game)
#   <Dir>\Pixel Browser\PixelBrowser.exe importing pixel_elf.dll (Phase 5: a browser eGuard's extension can't run in)
#
# and the per-user registry entries the scan reads:
#   HKCU\Software\Valve\Steam                                 SteamPath -> the fake Steam (refused if Steam is real)
#   HKCU\...\CurrentVersion\Uninstall\eGuardTestPixelQuest    "Pixel Quest"
#   HKCU\...\CurrentVersion\Uninstall\eGuardTestPixelBrowser  "Pixel Browser"
#
# The games are standin.rs and the browser browser.rs (with browser_elf.rs), built with rustc: unsigned programs
# showing one message box. Run the service with
# `eguard-service run --sandbox <Dir>` so only these are ended.
#
#   setup.ps1 [-Dir DIR]          set up (default %TEMP%\eguard-sandbox)
#   setup.ps1 -Remove [-Dir DIR]  remove the registry entries and the folder
param([string]$Dir = (Join-Path $env:TEMP "eguard-sandbox"), [switch]$Remove)
$steamKey = "HKCU:\Software\Valve\Steam"
$pqKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\eGuardTestPixelQuest"
$pbKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\eGuardTestPixelBrowser"
if ($Remove) {
    if (Test-Path $pqKey) { Remove-Item $pqKey -Recurse }
    if (Test-Path $pbKey) { Remove-Item $pbKey -Recurse }
    # Only the key this script made: one pointing at this sandbox's fake Steam
    $fake = (Join-Path $Dir "Steam") -replace '\\', '/'
    if ((Test-Path $steamKey) -and (Get-ItemProperty $steamKey).SteamPath -eq $fake) { Remove-Item $steamKey -Recurse }
    if ((Test-Path "HKCU:\Software\Valve") -and -not (Get-ChildItem "HKCU:\Software\Valve")) { Remove-Item "HKCU:\Software\Valve" }
    if (Test-Path $Dir) { Remove-Item $Dir -Recurse -Force }
    "removed"
    return
}
if (Test-Path $steamKey) { throw "HKCU\Software\Valve\Steam already exists; not touching a real Steam" }
New-Item -ItemType Directory -Force $Dir | Out-Null
$standin = Join-Path $Dir "standin.exe"
rustc -O --edition 2024 -o $standin (Join-Path $PSScriptRoot "standin.rs")
if (-not $?) { throw "building standin.exe failed" }
$cs2dir = Join-Path $Dir "Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64"
New-Item -ItemType Directory -Force $cs2dir | Out-Null
Copy-Item $standin (Join-Path $cs2dir "cs2.exe")
@"
"AppState"
{
	"appid"		"730"
	"name"		"Counter-Strike 2"
	"installdir"		"Counter-Strike Global Offensive"
	"StateFlags"		"4"
}
"@ | Set-Content -Encoding ascii (Join-Path $Dir "Steam\steamapps\appmanifest_730.acf")
$pq = Join-Path $Dir "Pixel Quest"
New-Item -ItemType Directory -Force $pq | Out-Null
Copy-Item $standin (Join-Path $pq "PixelQuest.exe")
New-Item -ItemType File -Force (Join-Path $pq "UnityPlayer.dll") | Out-Null
New-Item -Force $steamKey | Out-Null
Set-ItemProperty $steamKey -Name SteamPath -Value ((Join-Path $Dir "Steam") -replace '\\', '/')
New-Item -Force $pqKey | Out-Null
Set-ItemProperty $pqKey -Name DisplayName -Value "Pixel Quest"
Set-ItemProperty $pqKey -Name InstallLocation -Value $pq
Set-ItemProperty $pqKey -Name DisplayIcon -Value (Join-Path $pq "PixelQuest.exe")
Set-ItemProperty $pqKey -Name UninstallString -Value "`"$(Join-Path $pq 'PixelQuest.exe')`" /uninstall"
$pb = Join-Path $Dir "Pixel Browser"
New-Item -ItemType Directory -Force $pb | Out-Null
rustc -O --edition 2024 --crate-type cdylib -o (Join-Path $pb "pixel_elf.dll") (Join-Path $PSScriptRoot "browser_elf.rs")
if (-not $?) { throw "building pixel_elf.dll failed" }
rustc -O --edition 2024 -o (Join-Path $pb "PixelBrowser.exe") (Join-Path $PSScriptRoot "browser.rs")
if (-not $?) { throw "building PixelBrowser.exe failed" }
New-Item -Force $pbKey | Out-Null
Set-ItemProperty $pbKey -Name DisplayName -Value "Pixel Browser"
Set-ItemProperty $pbKey -Name InstallLocation -Value $pb
Set-ItemProperty $pbKey -Name DisplayIcon -Value (Join-Path $pb "PixelBrowser.exe")
Set-ItemProperty $pbKey -Name UninstallString -Value "`"$(Join-Path $pb 'PixelBrowser.exe')`" /uninstall"
"sandbox ready at $Dir"
