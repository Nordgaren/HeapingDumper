using System;

namespace HeapingDumper; 

public class PE32Section {
    public readonly string SectionName;
    public readonly IntPtr VirtualAddress;
    public readonly uint VirtualSize;

    public PE32Section(string sectionName, IntPtr virtualAddress, uint virtualSize) {
        SectionName = sectionName;
        VirtualAddress = virtualAddress;
        VirtualSize = virtualSize;
    }
}