using System.Runtime.InteropServices;

namespace MemoryMirror.Shared;

public static class SnapshotModuleHelper
{
    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEENTRY32 {
        internal uint dwSize;
        internal uint th32ModuleID;
        internal uint th32ProcessID;
        internal uint GlblcntUsage;
        internal uint ProccntUsage;
        internal IntPtr modBaseAddr;
        internal IntPtr modBaseSize;
        internal IntPtr hModule;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        internal string szModule;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        internal string szExePath;
    }

    [DllImport("kernel32.dll")]
    static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll")]
    static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

    public static IEnumerable<ProcessMemoryModule> EnumerateModules(IntPtr snapshotHandle) {
        var module = getFirstModule(snapshotHandle);
        var modules = new List<ProcessMemoryModule>();

        do {
            modules.Add(new ProcessMemoryModule(module.szModule, module.modBaseAddr, module.modBaseSize));
        } while (getNextModule(snapshotHandle, out module));

        return modules;
    }

    private static MODULEENTRY32 getFirstModule(IntPtr snapshotHandle) {
        var moduleEntry = getNewModuleEntry();
        if (!Module32First(snapshotHandle, ref moduleEntry)) {
            // TODO: introduce specialized exception types for this
            throw new Exception("Could not acquire first module entry");
        }

        return moduleEntry;
    }

    private static bool getNextModule(IntPtr snapshotHandle, out MODULEENTRY32 moduleEntry) {
        moduleEntry = getNewModuleEntry();
        if (!Module32Next(snapshotHandle, ref moduleEntry)) {
            var lastError = ProcessUtilities.GetLastError();
            // Skip access violations
            if (lastError == 0x12) {
                return false;
            }

            // TODO: introduce specialized exception types for this
            throw new Exception("Could not acquire next module entry");
        }

        return true;
    }

    private static MODULEENTRY32 getNewModuleEntry() {
        var moduleEntry = new MODULEENTRY32();
        moduleEntry.dwSize = (uint) Marshal.SizeOf(moduleEntry);
        return moduleEntry;
    }
}

public record ProcessMemoryModule(string Name, IntPtr Address, IntPtr Size);