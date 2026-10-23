param([string]$Label, [switch]$List)
# Presses the button labelled $Label in one of eguard-agent's windows through its accessible object (MSAA
# accDoDefaultAction: what a screen reader's "press" does), after checking it reads as a push button.
Add-Type -ReferencedAssemblies Accessibility @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class Acc {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc f, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr p, EnumProc f, IntPtr l);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("oleacc.dll")] static extern int AccessibleObjectFromWindow(IntPtr h, uint id, ref Guid iid, [MarshalAs(UnmanagedType.IUnknown)] out object o);
    public static List<string> Run(uint agent, string label, bool list) {
        var o = new List<string>();
        EnumWindows((h, l) => {
            uint pid; GetWindowThreadProcessId(h, out pid);
            if (pid != agent || !IsWindowVisible(h)) return true;
            EnumChildWindows(h, (c, l2) => {
                if (!IsWindowVisible(c)) return true;
                Guid iid = new Guid("618736E0-3C3D-11CF-810C-00AA00389B71");
                object obj;
                if (AccessibleObjectFromWindow(c, 0xFFFFFFFC, ref iid, out obj) != 0) return true;
                var a = (Accessibility.IAccessible)obj;
                string name = a.get_accName(0);
                int role = Convert.ToInt32(a.get_accRole(0));
                string action = a.get_accDefaultAction(0);
                if (list) o.Add(String.Format("'{0}' role={1} (43 = push button) action='{2}'", name, role, action));
                else if (name == label) { a.accDoDefaultAction(0); o.Add("pressed '" + label + "' (role " + role + ")"); }
                return true;
            }, IntPtr.Zero);
            return true;
        }, IntPtr.Zero);
        return o;
    }
}
"@
$out = @()
foreach ($agent in Get-Process eguard-agent) { $out += [Acc]::Run([uint32]$agent.Id, $Label, [bool]$List) }
if ($out.Count) { $out } else { "no visible '$Label' button" }
