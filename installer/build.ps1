# Builds eGuard's Windows Installer package from a folder with the three programs (WiX 5: dotnet tool install
# --global wix --version 5.0.2).
#
#   build.ps1 -Bin target\vm-bundle\bin [-Out target\eguard.msi] [-Version 0.1.1]
#
# The version is the workspace's (Cargo.toml), or -Version (the programs' EGUARD_VERSION, tools\vm\bundle.ps1).
# Unsigned: signing waits for the certificate (the owner's).
param([Parameter(Mandatory)][string]$Bin, [string]$Out, [string]$Version)
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
if (-not $Out) { $Out = Join-Path $root "target\eguard.msi" }
$version = if ($Version) { $Version } else {
    (Select-String -Path (Join-Path $root "Cargo.toml") -Pattern '^version = "(.+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
}
foreach ($exe in "eguard-service.exe", "eguard-agent.exe", "eguard-guard.exe") {
    if (-not (Test-Path (Join-Path $Bin $exe))) { throw "$exe isn't in $Bin" }
}
$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) {
    $tool = Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"
    if (-not (Test-Path $tool)) { throw "WiX isn't installed: dotnet tool install --global wix --version 5.0.2" }
    $wix = $tool
}
& $wix build (Join-Path $PSScriptRoot "eguard.wxs") -arch x64 -d "BinDir=$(Resolve-Path $Bin)" -d "Version=$version" -o $Out
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
Remove-Item ([IO.Path]::ChangeExtension($Out, ".wixpdb")) -ErrorAction SilentlyContinue
"built $Out ($version)"
