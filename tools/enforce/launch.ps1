param([string]$Exe, [string]$Shot)
# Launches $Exe, reports how long until something ended it (or that it's still running after 10 s), then
# captures the main monitor to $Shot.
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type @"
using System.Runtime.InteropServices;
public static class Dpi { [DllImport("user32.dll")] public static extern bool SetProcessDPIAware(); }
"@
[Dpi]::SetProcessDPIAware() | Out-Null
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath $Exe -PassThru
$ended = $p.WaitForExit(10000)
$sw.Stop()
if ($ended) { "ended after {0:N2} s (exit code 0x{1:X})" -f $sw.Elapsed.TotalSeconds, $p.ExitCode } else { "still running after 10 s (pid $($p.Id))" }
Start-Sleep -Milliseconds 1500
if ($Shot) {
    $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
    $bmp.Save($Shot, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}
