param([int]$Seconds = 300, [string]$Shot)
# Waits until eguard-agent's full-screen overlay is visible (or $Seconds pass), then captures the main monitor.
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class O {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    public static bool Up() {
        bool up = false;
        EnumWindows((h, l) => {
            uint pid; GetWindowThreadProcessId(h, out pid);
            RECT r; GetWindowRect(h, out r);
            try {
                var p = System.Diagnostics.Process.GetProcessById((int)pid);
                if (p.ProcessName == "eguard-agent" && IsWindowVisible(h) && r.R - r.L >= 1000) up = true;
            } catch {}
            return true;
        }, IntPtr.Zero);
        return up;
    }
}
"@
[O]::SetProcessDPIAware() | Out-Null
$sw = [Diagnostics.Stopwatch]::StartNew()
while (-not [O]::Up() -and $sw.Elapsed.TotalSeconds -lt $Seconds) { Start-Sleep -Seconds 1 }
if (-not [O]::Up()) { "no overlay after $Seconds s"; return }
"overlay up after {0:N0} s" -f $sw.Elapsed.TotalSeconds
Start-Sleep -Seconds 1
if ($Shot) {
    $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
    $bmp.Save($Shot, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}
