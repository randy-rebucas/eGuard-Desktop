# Builds the release installer: the three programs optimized, against production (https://www.eguard.family, the
# service's default for a build with the production key), linked with the C runtime inside, then target\eguard.msi
# from them (build.ps1). Run it here; never install the MSI on this PC.
#
#   release.ps1 -PublicKeys KEY -Signer ORG -ChromeId ID -EdgeId ID -FirefoxUrl URL [-Version 0.1.1] [-ServerUrl https://…]
#
#   -PublicKeys  eGuard's production policy-signing public key (base64 SPKI, as the extension's VITE_POLICY_PUBLIC_KEY;
#                never the private key); several separated by commas during a rotation
#   -Signer      the organisation on eGuard's code-signing certificate, exactly (updates are checked against it)
#   -ChromeId, -EdgeId, -FirefoxUrl   the extension's store ids
#   -ServerUrl   only to point a release somewhere other than production
#
# Unsigned: signing the exes and the MSI waits for the certificate (the owner's).
param(
    [Parameter(Mandatory)][string]$PublicKeys, [Parameter(Mandatory)][string]$Signer,
    [Parameter(Mandatory)][string]$ChromeId, [Parameter(Mandatory)][string]$EdgeId, [Parameter(Mandatory)][string]$FirefoxUrl,
    [string]$Version, [string]$ServerUrl
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
if ($ServerUrl -and -not $ServerUrl.StartsWith("https://")) { throw "-ServerUrl must be https://" }
if ($Version -and $Version -notmatch '^\d+(\.\d+){0,3}$') { throw "-Version is numbers with dots, like 0.1.1" }
$vars = @{
    EGUARD_POLICY_PUBLIC_KEYS = $PublicKeys; EGUARD_UPDATE_SIGNER = $Signer
    EGUARD_CHROME_EXTENSION_ID = $ChromeId; EGUARD_EDGE_EXTENSION_ID = $EdgeId; EGUARD_FIREFOX_EXTENSION_URL = $FirefoxUrl
    EGUARD_VERSION = $Version; EGUARD_SERVER_URL = $ServerUrl
    # A stray one from a local build would make a release that trusts the dev key's checks
    EGUARD_DEV_RELEASE = $null
}

$saved = @{ RUSTFLAGS = $env:RUSTFLAGS }
foreach ($k in $vars.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k) }
try {
    $env:RUSTFLAGS = "-C target-feature=+crt-static"
    foreach ($k in $vars.Keys) { [Environment]::SetEnvironmentVariable($k, $vars[$k]) }
    cargo build --workspace --bins --release --target-dir (Join-Path $root "target\release-static") --manifest-path (Join-Path $root "Cargo.toml")
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
} finally {
    foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
}

$bin = Join-Path $root "target\release-static\release"
& (Join-Path $PSScriptRoot "build.ps1") -Bin $bin -Out (Join-Path $root "target\eguard.msi") -Version $Version
"release: target\eguard.msi for $(if ($ServerUrl) { $ServerUrl } else { 'https://www.eguard.family' }). Never install it on this PC."
