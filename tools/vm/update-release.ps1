# On the VM only: never on the owner's PC (it makes a code-signing certificate and trusts it machine-wide). Makes a
# release of eGuard's programs for the update test (docs/VM-TESTS.md G), the way the release pipeline will once
# eGuard's certificate exists, and serves it.
#
#   update-release.ps1 -Bin C:\eguard-next\bin -Version 0.1.1      sign, print DESKTOP_RELEASE, serve until Ctrl+C
#   update-release.ps1 -Bin … -Version 0.1.2 -NoSign               unsigned: the agent refuses it (G2)
#   update-release.ps1 -Bin … -Version 0.1.2 -Broken               eguard-service.exe is really the agent, so the new
#                                                                  version never starts: rolled back after 10 min (G3)
#
# 1. A self-signed code-signing certificate "eGuard Dev" (its CN and O), made once in LocalMachine\My and trusted in
#    LocalMachine\Root and TrustedPublisher: the signer a development build accepts (eguard_core::update::SIGNER).
# 2. The three programs copied to C:\eguard-release\<version> and signed with it (SHA-256, no timestamp: offline).
# 3. DESKTOP_RELEASE for the dev server's .env.local, printed and saved beside them: each file's size, SHA-256 and
#    http://localhost:<port>/<version>/<name> (a development build downloads over plain http from this computer only).
# 4. C:\eguard-release served at http://localhost:<port>/ until Ctrl+C.
param(
    [Parameter(Mandatory)][string]$Bin,
    [Parameter(Mandatory)][string]$Version,
    [int]$Port = 8099,
    [switch]$NoSign,
    [switch]$Broken
)
$ErrorActionPreference = "Stop"
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "run this as an administrator, on the VM" }
if ($Version -notmatch '^\d+(\.\d+){0,3}$') { throw "-Version is numbers with dots, like 0.1.1" }

$programs = "eguard-service.exe", "eguard-agent.exe", "eguard-guard.exe"
$root = "C:\eguard-release"
$dir = Join-Path $root $Version
New-Item -ItemType Directory -Force $dir | Out-Null
foreach ($p in $programs) { Copy-Item (Join-Path $Bin $p) $dir -Force }
if ($Broken) { Copy-Item (Join-Path $Bin "eguard-agent.exe") (Join-Path $dir "eguard-service.exe") -Force }

if (-not $NoSign) {
    $subject = "CN=eGuard Dev, O=eGuard Dev"
    $cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert | Where-Object Subject -eq $subject | Select-Object -First 1
    if (-not $cert) {
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(1)
        foreach ($name in "Root", "TrustedPublisher") {
            $store = New-Object Security.Cryptography.X509Certificates.X509Store($name, "LocalMachine")
            $store.Open("ReadWrite")
            $store.Add($cert)
            $store.Close()
        }
        "made the certificate '$subject' and trusted it on this computer ($($cert.Thumbprint))"
    }
    foreach ($p in $programs) {
        $signed = Set-AuthenticodeSignature -FilePath (Join-Path $dir $p) -Certificate $cert -HashAlgorithm SHA256
        if ($signed.Status -ne "Valid") { throw "signing $p failed: $($signed.StatusMessage)" }
    }
}

$files = foreach ($p in $programs) {
    $f = Get-Item (Join-Path $dir $p)
    [ordered]@{ name = $p; size = $f.Length; sha256 = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower(); url = "http://localhost:$Port/$Version/$p" }
}
$release = [ordered]@{ version = $Version; files = @($files) } | ConvertTo-Json -Compress -Depth 4
$release | Set-Content -Encoding ascii (Join-Path $dir "DESKTOP_RELEASE.txt")
""
"On the owner's PC, put these two lines in ~/eguard/.env.local (the dev server reloads it; restart it if it doesn't):"
"DESKTOP_RELEASE='$release'"
"CHILD_MIN_APP_VERSION=`"windows:$Version`""
""

$listener = New-Object Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()
"serving $root at http://localhost:$Port/ (Ctrl+C stops)"
try {
    while ($listener.IsListening) {
        # Waits in short steps, so Ctrl+C is heard between them
        $next = $listener.GetContextAsync()
        while (-not $next.Wait(500)) {}
        $ctx = $next.Result
        $rel = [Uri]::UnescapeDataString($ctx.Request.Url.AbsolutePath.TrimStart("/")) -replace "/", "\"
        $full = [IO.Path]::GetFullPath((Join-Path $root $rel))
        if ($full.StartsWith("$root\", [StringComparison]::OrdinalIgnoreCase) -and (Test-Path $full -PathType Leaf)) {
            $bytes = [IO.File]::ReadAllBytes($full)
            $ctx.Response.ContentLength64 = $bytes.Length
            $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            "$(Get-Date -Format T) 200 /$rel ($($bytes.Length) bytes)"
        } else {
            $ctx.Response.StatusCode = 404
            "$(Get-Date -Format T) 404 /$rel"
        }
        $ctx.Response.Close()
    }
} finally {
    $listener.Stop()
}
