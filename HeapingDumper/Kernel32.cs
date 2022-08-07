using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace HeapingDumper;

public static class Kernel32
{
    #region Constants from winnt.h
        public const uint PAGE_NOACCESS = 0x01;
        public const uint PAGE_READONLY = 0x02;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_WRITECOPY = 0x08;
        public const uint PAGE_EXECUTE = 0x10;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint PAGE_GUARD = 0x100;
        public const uint PAGE_NOCACHE = 0x200;
        public const uint PAGE_WRITECOMBINE = 0x400;
        public const uint PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000;
        public const uint PAGE_REVERT_TO_FILE_MAP = 0x80000000;
        public const uint PAGE_TARGETS_NO_UPDATE = 0x40000000;
        public const uint PAGE_TARGETS_INVALID = 0x40000000;
        public const uint PAGE_ENCLAVE_UNVALIDATED = 0x20000000;
        public const uint PAGE_ENCLAVE_DECOMMIT = 0x10000000;
        public const uint MEM_COMMIT = 0x00001000;
        public const uint MEM_RESERVE = 0x00002000;
        public const uint MEM_REPLACE_PLACEHOLDER = 0x00004000;
        public const uint MEM_RESERVE_PLACEHOLDER = 0x00040000;
        public const uint MEM_RESET = 0x00080000;
        public const uint MEM_TOP_DOWN = 0x00100000;
        public const uint MEM_WRITE_WATCH = 0x00200000;
        public const uint MEM_PHYSICAL = 0x00400000;
        public const uint MEM_ROTATE = 0x00800000;
        public const uint MEM_DIFFERENT_IMAGE_BASE_OK = 0x00800000;
        public const uint MEM_RESET_UNDO = 0x01000000;
        public const uint MEM_LARGE_PAGES = 0x20000000;
        public const uint MEM_4MB_PAGES = 0x80000000;
        public const uint MEM_64K_PAGES = MEM_LARGE_PAGES | MEM_PHYSICAL;
        public const uint MEM_UNMAP_WITH_TRANSIENT_BOOST = 0x00000001;
        public const uint MEM_COALESCE_PLACEHOLDERS = 0x00000001;
        public const uint MEM_PRESERVE_PLACEHOLDER = 0x00000002;
        public const uint MEM_DECOMMIT = 0x00004000;
        public const uint MEM_RELEASE = 0x00008000;
        public const uint MEM_FREE = 0x00010000;
        #endregion
        
    [Flags]
    public enum ThreadAccess : int
    {
        TERMINATE = (0x0001),
        SUSPEND_RESUME = (0x0002),
        GET_CONTEXT = (0x0008),
        SET_CONTEXT = (0x0010),
        SET_INFORMATION = (0x0020),
        QUERY_INFORMATION = (0x0040),
        SET_THREAD_TOKEN = (0x0080),
        IMPERSONATE = (0x0100),
        DIRECT_IMPERSONATION = (0x0200)
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        internal ushort wProcessorArchitecture;
        internal ushort wReserved;
        internal uint dwPageSize;
        internal IntPtr lpMinimumApplicationAddress;
        internal IntPtr lpMaximumApplicationAddress;
        internal IntPtr dwActiveProcessorMask;
        internal uint dwNumberOfProcessors;
        internal uint dwProcessorType;
        internal uint dwAllocationGranularity;
        internal ushort wProcessorLevel;
        internal ushort wProcessorRevision;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct HEAPLIST32 
    {
        public UIntPtr dwSize;
        public uint th32ProcessID;
        public UIntPtr th32HeapID;
        public uint dwFlags;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct HEAPENTRY32
    {
        public UIntPtr  dwSize;
        public IntPtr hHandle;
        public UIntPtr dwAddress;
        public UIntPtr  dwBlockSize;
        public uint dwFlags;
        public uint dwLockCount;
        public uint dwResvd;
        public uint th32ProcessID;
        public UIntPtr th32HeapID;
    }
    
    [Flags]
    public enum SnapshotFlags : uint
    {
        HeapList = 0x00000001,
        Process = 0x00000002,
        Thread = 0x00000004,
        Module = 0x00000008,
        Module32 = 0x00000010,
        Inherit = 0x80000000,
        All = 0x0000001F,
        NoHeaps = 0x40000000
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
    [DllImport("kernel32.dll")]
    static extern uint SuspendThread(IntPtr hThread);
    [DllImport("kernel32.dll")]
    static extern int ResumeThread(IntPtr hThread);
    [DllImport("kernel32", CharSet = CharSet.Auto,SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, ref IntPtr lpNumberOfBytesRead);
    [DllImport("kernel32.dll")]
    public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQueryEx(IntPtr hProcess, 
        IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool Heap32ListFirst(IntPtr hSnapshot, ref HEAPLIST32 lphl);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool Heap32ListNext(IntPtr hSnapshot, ref HEAPLIST32 lphl);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool Heap32First(ref HEAPENTRY32 lphl, uint th32ProcessID, UIntPtr th32HeapID);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool Heap32Next(ref HEAPENTRY32 lphl);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);
    
    public static byte[] ReadBytes(IntPtr handle, IntPtr address, uint length)
    {
        byte[] bytes = new byte[length];
        IntPtr bytesRead = IntPtr.Zero;
        ReadProcessMemory(handle, address, bytes, (IntPtr)length, ref bytesRead);
        return bytes;
    }
    
    public static void SuspendProcess(int pid)
    {
        var process = Process.GetProcessById(pid); // throws exception if process does not exist

        foreach (ProcessThread pT in process.Threads)
        {
            IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);

            if (pOpenThread == IntPtr.Zero)
            {
                continue;
            }

            SuspendThread(pOpenThread);

            CloseHandle(pOpenThread);
        }
    }

    public static void ResumeProcess(int pid)
    {
        var process = Process.GetProcessById(pid);

        if (process.ProcessName == string.Empty)
            return;

        foreach (ProcessThread pT in process.Threads)
        {
            IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);

            if (pOpenThread == IntPtr.Zero)
            {
                continue;
            }

            var suspendCount = 0;
            do
            {
                suspendCount = ResumeThread(pOpenThread);
            } while (suspendCount > 0);

            CloseHandle(pOpenThread);
        }
    }
}