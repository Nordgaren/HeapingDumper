using System.Runtime.InteropServices;

namespace MemoryMirror.Shared;

public static class SnapshotHeapHelper {
    [StructLayout(LayoutKind.Sequential)]
    private struct HEAPLIST32 {
        public UIntPtr dwSize;
        public uint th32ProcessID;
        public UIntPtr th32HeapID;
        public uint dwFlags;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct HEAPENTRY32 {
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

    [DllImport("kernel32.dll")]
    static extern bool Heap32ListFirst(IntPtr hSnapshot, ref HEAPLIST32 lphl);
    
    [DllImport("kernel32.dll")]
    static extern bool Heap32ListNext(IntPtr hSnapshot, ref HEAPLIST32 lphl);
    
    [DllImport("kernel32.dll")]
    static extern bool Heap32First(ref HEAPENTRY32 lphe, UInt32 th32ProcessID, UIntPtr th32HeapID);
    
    [DllImport("kernel32.dll")]
    static extern bool Heap32Next(ref HEAPENTRY32 lphe);

    public static IEnumerable<ProcessMemoryHeapEntry> EnumerateHeapEntries(IntPtr snapshotHandle) {
        var heapList = getFirstHeapList(snapshotHandle);
        var heapEntry = getFirstHeapEntry(heapList);
        var heapEntries = new List<ProcessMemoryHeapEntry>();

        do {
            do {
                heapEntries.Add(new ProcessMemoryHeapEntry(heapEntry.dwAddress, heapEntry.dwSize));
            } while (getNextHeapEntry(ref heapEntry));
        } while (getNextHeapList(snapshotHandle, out heapList));
        
        return heapEntries;
    }

    private static HEAPLIST32 getFirstHeapList(IntPtr snapshotHandle) {
        var heapList = getNewHeapList();
        if (!Heap32ListFirst(snapshotHandle, ref heapList)) {
             // TODO: introduce specialized exception types for this
             throw new Exception("Could not acquire first heap list entry");
        }

        return heapList;
    }
    
    private static bool getNextHeapList(IntPtr snapshotHandle, out HEAPLIST32 heapList) {
        heapList = getNewHeapList();
        if (!Heap32ListNext(snapshotHandle, ref heapList)) {
            var lastError = ProcessUtilities.GetLastError();
            // Skip over things where we get an invalid access error
            if (lastError == 0x12) {
                return false;
            }
            
            // TODO: introduce specialized exception types for this
            throw new Exception("Could not acquire next heap list entry");
        }

        return true;
    }

    private static HEAPLIST32 getNewHeapList() {
        var heaplist = new HEAPLIST32();
        heaplist.dwSize = (UIntPtr) Marshal.SizeOf(heaplist);
        return heaplist;
    }
    
    private static HEAPENTRY32 getFirstHeapEntry(HEAPLIST32 heapList) {
        var heapEntry = getNewHeapEntry();
        if (!Heap32First(ref heapEntry, heapList.th32ProcessID, heapList.th32HeapID)) {
             // TODO: introduce specialized exception types for this
             throw new Exception("Could not acquire first heap entry");
        }

        return heapEntry;
    }
    
    private static bool getNextHeapEntry(ref HEAPENTRY32 heapEntry) {
        if (!Heap32Next(ref heapEntry)) {
             // TODO: introduce specialized exception types for this
             throw new Exception("Could not acquire next heap entry");
        }

        return true;
    }
    
    private static HEAPENTRY32 getNewHeapEntry() {
        var heapEntry = new HEAPENTRY32();
        heapEntry.dwSize = (UIntPtr) Marshal.SizeOf(heapEntry);

        return heapEntry;
    }
}

public record ProcessMemoryHeapEntry(UIntPtr Address, UIntPtr Size);
