# Builds what the Windows 11 test VM needs into target\vm-bundle and target\eguard-vm.zip (docs/VM-TESTS.md):
#
#   bin\       eguard-service.exe, eguard-agent.exe, eguard-guard.exe: a development build (the dev signing key, the
#              server at http://localhost:3000, which install.ps1 forwards to this PC), linked with the C runtime
#              inside, so a clean Windows needs no Visual C++ redistributable
#   standins\  standin.exe, pixel_elf.dll, PixelBrowser.exe for tools\enforce\setup.ps1 -Prebuilt
#   tools\     tools\vm\*.ps1 and tools\enforce\*.ps1
#   VM-TESTS.md
#
#   bundle.ps1                                   no extension ids: nothing is forced in browsers (Phase 5 waits)
#   bundle.ps1 -ChromeId ID -EdgeId ID -FirefoxUrl URL   the extension's real store ids, once they exist
#
# Its own target folder (target\vm), so the static C runtime doesn't rebuild everyday builds.
param([string]$ChromeId, [string]$EdgeId, [string]$FirefoxUrl)
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$out = Join-Path $root "target\vm-bundle"
$ids = @{ EGUARD_CHROME_EXTENSION_ID = $ChromeId; EGUARD_EDGE_EXTENSION_ID = $EdgeId; EGUARD_FIREFOX_EXTENSION_URL = $FirefoxUrl }
if (($ids.Values | Where-Object { $_ }).Count -notin 0, 3) { throw "give all three extension ids, or none" }

$saved = @{ RUSTFLAGS = $env:RUSTFLAGS }
foreach ($k in $ids.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k) }
try {
    $env:RUSTFLAGS = "-C target-feature=+crt-static"
    foreach ($k in $ids.Keys) { [Environment]::SetEnvironmentVariable($k, $ids[$k]) }
    cargo build --workspace --bins --target-dir (Join-Path $root "target\vm") --manifest-path (Join-Path $root "Cargo.toml")
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
} finally {
    foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
}

if (Test-Path $out) { Remove-Item $out -Recurse -Force }
$bin = New-Item -ItemType Directory -Force (Join-Path $out "bin")
foreach ($exe in "eguard-service.exe", "eguard-agent.exe", "eguard-guard.exe") {
    Copy-Item (Join-Path $root "target\vm\debug\$exe") $bin
}

$standins = New-Item -ItemType Directory -Force (Join-Path $out "standins")
$enforce = Join-Path $root "tools\enforce"
$static = "-C", "target-feature=+crt-static"
rustc -O --edition 2024 @static -o (Join-Path $standins "standin.exe") (Join-Path $enforce "standin.rs")
if ($LASTEXITCODE -ne 0) { throw "building standin.exe failed" }
rustc -O --edition 2024 @static --crate-type cdylib -o (Join-Path $standins "pixel_elf.dll") (Join-Path $enforce "browser_elf.rs")
if ($LASTEXITCODE -ne 0) { throw "building pixel_elf.dll failed" }
rustc -O --edition 2024 @static -o (Join-Path $standins "PixelBrowser.exe") (Join-Path $enforce "browser.rs")
if ($LASTEXITCODE -ne 0) { throw "building PixelBrowser.exe failed" }
Get-ChildItem $standins -Include *.pdb, *.exp, *.lib -Recurse | Remove-Item

$tools = New-Item -ItemType Directory -Force (Join-Path $out "tools")
Copy-Item (Join-Path $root "tools\vm\*.ps1"), (Join-Path $enforce "*.ps1") $tools -Exclude bundle.ps1
Copy-Item (Join-Path $root "docs\VM-TESTS.md") $out

$zip = Join-Path $root "target\eguard-vm.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path (Join-Path $out "*") -DestinationPath $zip
"bundle: $zip ($([math]::Round((Get-Item $zip).Length / 1MB, 1)) MB). Copy it to the VM and follow VM-TESTS.md."
