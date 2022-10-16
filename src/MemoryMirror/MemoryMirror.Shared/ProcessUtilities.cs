using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MemoryMirror.Shared;

public static class ProcessUtilities {
    [Flags]
    private enum ThreadAccess {
        SUSPEND_RESUME = 0x0002,
    }
    
    [Flags]
    private enum SnapshotFlags : uint {
        HeapList = 0x00000001,
        Process = 0x00000002,
        Thread = 0x00000004,
        Module = 0x00000008,
        Module32 = 0x00000010,
        Inherit = 0x80000000,
        All = 0x0000001F,
        NoHeaps = 0x40000000
    }
    
    [Flags]
    private enum VMAccess : uint {
        PROCESS_WM_READ = 0x10,
    }
    
    [Flags]
    public enum VMState : uint {
        MEM_COMMIT = 0x1000,
        MEM_FREE = 0x10000,
        MEM_RESERVE = 0x2000,
    }
    
    [Flags]
    public enum VMType : uint {
        MEM_IMAGE = 0x1000000,
        MEM_MAPPED = 0x40000,
        MEM_PRIVATE = 0x20000,
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public VMState State;
        public uint Protect;
        public VMType Type;
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll")]
    static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    static extern int ResumeThread(IntPtr hThread);
    
    [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, UInt32 th32ProcessID);
    
    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
    
    [DllImport("kernel32.dll")]
    static extern int VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, IntPtr dwSize, out IntPtr lpNumberOfBytesRead);

    public static void Suspend(this Process process) {
        foreach (ProcessThread thread in process.Threads) {
            var pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
            if (pOpenThread == IntPtr.Zero) {
                throw new InvalidOperationException($"Could not pause process. pOpenThread = IntPtr.Zero");
            }
            SuspendThread(pOpenThread);
        }
    }

    public static void Resume(this Process process) {
        foreach (ProcessThread thread in process.Threads) {
            var pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
            if (pOpenThread == IntPtr.Zero) {
                throw new InvalidOperationException($"Could not resume process. pOpenThread = IntPtr.Zero");
            }
            ResumeThread(pOpenThread);
        }
    }
    
    public static IntPtr CreateSnapshot(this Process process) {
         IntPtr snapshotHandle = CreateToolhelp32Snapshot(SnapshotFlags.All, (uint)process.Id);
         if (GetLastError() != 0 || snapshotHandle == IntPtr.Zero) {
             // TODO: introduce specialized exception types for this
             throw new Exception("Could not create snapshot");
         }

         return snapshotHandle;
    }

    public static IEnumerable<ProcessMemorySegment> EnumerateMemorySegments(this Process process) {
        var maxAddress = (IntPtr) 0x7fffffffffffffff;
        var currentAddress = (UIntPtr) 0;
        var previousAddress = (UIntPtr) 0;
        MEMORY_BASIC_INFORMATION currentEntry;
        var memorySegments = new List<ProcessMemorySegment>();

        do {
            VirtualQueryEx(
                process.Handle,
                currentAddress,
                out currentEntry,
                (uint) Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))
            );

            if (currentEntry.State != VMState.MEM_FREE) {
                memorySegments.Add(new ProcessMemorySegment(currentEntry.AllocationBase, currentEntry.RegionSize));
            }

            previousAddress = currentAddress;
            currentAddress = (UIntPtr)((Int64)currentEntry.BaseAddress + (Int64)currentEntry.RegionSize);
        } while ((long) currentAddress <= (long) maxAddress && previousAddress != currentAddress);

        return memorySegments;
    }
    
    public static IntPtr GetReadHandle(this Process process) {
        return OpenProcess((int) VMAccess.PROCESS_WM_READ, false, process.Id);
    }

    public static byte[] ReadMemoryToBuffer(IntPtr readHandle, IntPtr address, IntPtr size) {
        var buffer = new byte[(UInt64) size];
        if (!ReadProcessMemory(readHandle, address, buffer, size, out var bytesRead)) {
            return Array.Empty<byte>();
        }
        return buffer;
    }
    
    public record ProcessMemorySegment(IntPtr Address, IntPtr Size);
}

