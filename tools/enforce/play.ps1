param([string]$Exe, [int]$Seconds = 75, [string]$ShotDir)
# "Plays" $Exe: starts it, keeps its window in front, and nudges the mouse by one pixel and back every half second
# (input, so the foreground time counts). Stops when it's ended or after $Seconds. Screenshots: when the warning
# should be up (3 s in) and 2 s after the program was ended.
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class P {
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, IntPtr pid);
    [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool attach);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
    [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] public static extern void mouse_event(uint f, int dx, int dy, uint d, IntPtr e);
    public static void Front(IntPtr h) {
        IntPtr fg = GetForegroundWindow();
        if (fg == h) return;
        uint t = GetWindowThreadProcessId(fg, IntPtr.Zero), me = GetCurrentThreadId();
        AttachThreadInput(me, t, true); BringWindowToTop(h); SetForegroundWindow(h); AttachThreadInput(me, t, false);
    }
    public static void Nudge() { mouse_event(1, 1, 0, 0, IntPtr.Zero); mouse_event(1, -1, 0, 0, IntPtr.Zero); }
}
"@
[P]::SetProcessDPIAware() | Out-Null
function Shot($name) {
    if (-not $ShotDir) { return }
    $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
    $bmp.Save((Join-Path $ShotDir $name), [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}
$p = Start-Process -FilePath $Exe -PassThru
$sw = [Diagnostics.Stopwatch]::StartNew()
while (-not $p.HasExited -and $p.MainWindowHandle -eq 0 -and $sw.Elapsed.TotalSeconds -lt 10) { Start-Sleep -Milliseconds 100; $p.Refresh() }
$shotTaken = $false
while (-not $p.HasExited -and $sw.Elapsed.TotalSeconds -lt $Seconds) {
    $p.Refresh()
    if ($p.MainWindowHandle -ne 0) { [P]::Front($p.MainWindowHandle) }
    [P]::Nudge()
    if (-not $shotTaken -and $sw.Elapsed.TotalSeconds -gt 3) { Shot "play-warning.png"; $shotTaken = $true }
    Start-Sleep -Milliseconds 500
}
if ($p.HasExited) { "ended after {0:N1} s of play (exit code 0x{1:X})" -f $sw.Elapsed.TotalSeconds, $p.ExitCode } else { "still running after $Seconds s"; Stop-Process -Id $p.Id }
Start-Sleep -Seconds 2
Shot "play-ended.png"
