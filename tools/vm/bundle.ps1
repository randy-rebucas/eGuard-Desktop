# Builds what the Windows 11 test VM needs into target\vm-bundle and target\eguard-vm.zip (docs/VM-TESTS.md):
#
#   eguard.msi the installer package made from bin\ (installer\build.ps1; WiX 5 must be installed here)
#   bin\       eguard-service.exe, eguard-agent.exe, eguard-guard.exe: a development build (the dev signing key, the
#              server at http://localhost:3000, which install.ps1 forwards to this PC), linked with the C runtime
#              inside, so a clean Windows needs no Visual C++ redistributable
#   standins\  standin.exe, pixel_elf.dll, PixelBrowser.exe for tools\enforce\setup.ps1 -Prebuilt
#   tools\     tools\vm\*.ps1 and tools\enforce\*.ps1
#   VM-TESTS.md
#
#   bundle.ps1                                   no extension ids: nothing is forced in browsers (Phase 5 waits)
#   bundle.ps1 -ChromeId ID -EdgeId ID -FirefoxUrl URL   the extension's real store ids, once they exist
#   bundle.ps1 -Version 0.1.1                    a newer version (EGUARD_VERSION), to test updates (VM-TESTS.md G):
#                                                target\eguard-vm-0.1.1.zip; its bin\ is what update-release.ps1 offers
#   bundle.ps1 -ServerUrl https://… -PublicKeys KEY      a build for a real eGuard server instead of this PC's dev
#                                                server: its https address and its policy-signing public key (base64
#                                                SPKI, as the extension's VITE_POLICY_PUBLIC_KEY; never the private key).
#                                                Both or neither: the dev key can't check a real server's signatures
#
# Its own target folder (target\vm), so the static C runtime doesn't rebuild everyday builds.
param([string]$ChromeId, [string]$EdgeId, [string]$FirefoxUrl, [string]$ServerUrl, [string]$PublicKeys, [string]$Version)
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$out = Join-Path $root "target\vm-bundle"
$ids = @{ EGUARD_CHROME_EXTENSION_ID = $ChromeId; EGUARD_EDGE_EXTENSION_ID = $EdgeId; EGUARD_FIREFOX_EXTENSION_URL = $FirefoxUrl }
if (($ids.GetEnumerator() | Where-Object { $_.Value }).Count -notin 0, 3) { throw "give all three extension ids, or none" }
if ([bool]$ServerUrl -ne [bool]$PublicKeys) { throw "give -ServerUrl and -PublicKeys together, or neither" }
if ($ServerUrl -and -not $ServerUrl.StartsWith("https://")) { throw "-ServerUrl must be https://" }
$ids["EGUARD_SERVER_URL"] = $ServerUrl
$ids["EGUARD_POLICY_PUBLIC_KEYS"] = $PublicKeys
if ($Version -and $Version -notmatch '^\d+(\.\d+){0,3}$') { throw "-Version is numbers with dots, like 0.1.1" }
$ids["EGUARD_VERSION"] = $Version

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

# The installer package, made from the same programs (installer\build.ps1, WiX 5)
& (Join-Path $root "installer\build.ps1") -Bin $bin -Out (Join-Path $out "eguard.msi") -Version $Version

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

$zip = Join-Path $root $(if ($Version) { "target\eguard-vm-$Version.zip" } else { "target\eguard-vm.zip" })
if (Test-Path $zip) { Remove-Item $zip }
if ($ServerUrl) { $ServerUrl | Set-Content -Encoding ascii (Join-Path $out "bin\server.txt") }
Compress-Archive -Path (Join-Path $out "*") -DestinationPath $zip
"bundle: $zip ($([math]::Round((Get-Item $zip).Length / 1MB, 1)) MB). Copy it to the VM and follow VM-TESTS.md."
