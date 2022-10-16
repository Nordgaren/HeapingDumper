using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using static HeapingDumper.PE32;

namespace HeapingDumper; 

//This is an attempt to port Scylla dumping to C#.
public class PEParser {
    private Process _selectedProcess;
    private ProcessModule _selectedModule;
    uint AlignValue(uint badValue, uint alignTo) {
            return (((badValue + alignTo - 1) / alignTo) * alignTo);
        }

        private unsafe void RealignSectionHeaders(byte[] bytes) {
            byte[] overlayData = null;
            fixed (byte* pHeader = bytes) {
                PE32.IMAGE_DOS_HEADER* dosHeader = (PE32.IMAGE_DOS_HEADER*) pHeader;
                PE32.IMAGE_NT_HEADERS64* ntHeaders = (PE32.IMAGE_NT_HEADERS64*) (pHeader + dosHeader->e_lfanew);

                //readPeSectionsFromProcess
                PE32.IMAGE_SECTION_HEADER*[] sectionHeaders =
                    new PE32.IMAGE_SECTION_HEADER*[ntHeaders->FileHeader.NumberOfSections];
                PE32.IMAGE_SECTION_HEADER* pSectionHeaders = (PE32.IMAGE_SECTION_HEADER*) ((IntPtr) pHeader +
                    dosHeader->e_lfanew + Marshal.SizeOf(typeof(PE32.IMAGE_NT_HEADERS64)));
                for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
                    sectionHeaders[i] = pSectionHeaders + i;
                }

                //setDefaultFileAlignment
                ntHeaders->OptionalHeader.FileAlignment = FileAlignmentConstant;

                //setEntryPointVa
                ulong entryAddr = (ulong) _selectedModule.EntryPointAddress;
                ulong baseAddr = (ulong) _selectedModule.BaseAddress;
                ntHeaders->OptionalHeader.AddressOfEntryPoint = (uint) (entryAddr - baseAddr);

                //alignAllSectionHeaders
                uint sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
                uint fileAlignment = ntHeaders->OptionalHeader.FileAlignment;
                SortSectionHeadersDataPtrAscending(sectionHeaders, ntHeaders->FileHeader.NumberOfSections);
                
                uint newFileSize = (uint) (dosHeader->e_lfanew + Marshal.SizeOf(typeof(uint)) +
                                           Marshal.SizeOf(typeof(PE32.IMAGE_FILE_HEADER)) +
                                           ntHeaders->FileHeader.SizeOfOptionalHeader +
                                           (ntHeaders->FileHeader.NumberOfSections *
                                            Marshal.SizeOf(typeof(PE32.IMAGE_SECTION_HEADER))));
                
                
                for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
                    IntPtr readOffset = (IntPtr) (sectionHeaders[i]->VirtualAddress + (long)_selectedModule.BaseAddress);
                    uint normalSize = sectionHeaders[i]->VirtualSize;
                    uint dataSize = 0;

                    if (normalSize != 0 && readOffset != IntPtr.Zero) {
                        if (normalSize <= MAX_READ_SIZE) {
                            dataSize = normalSize;
                        }
                    }
                    
                    sectionHeaders[i]->VirtualAddress = AlignValue(sectionHeaders[i]->VirtualAddress, sectionAlignment);
                    sectionHeaders[i]->VirtualSize = AlignValue(sectionHeaders[i]->SizeOfRawData, sectionAlignment);

                    sectionHeaders[i]->PointerToRawData = AlignValue(newFileSize, fileAlignment);
                    sectionHeaders[i]->SizeOfRawData = AlignValue(dataSize, fileAlignment);
                    
                    newFileSize = pSectionHeaders[i].PointerToRawData + pSectionHeaders[i].SizeOfRawData;
                }

                SortSectionHeadersVirtualAddrAscending(sectionHeaders, ntHeaders->FileHeader.NumberOfSections);

                //fixPeHeader
                ntHeaders->OptionalHeader.BoundImport.VirtualAddress = 0;
                ntHeaders->OptionalHeader.BoundImport.Size = 0;

                PE32.IMAGE_DATA_DIRECTORY** dataDirectory = (PE32.IMAGE_DATA_DIRECTORY**)&ntHeaders->OptionalHeader.ExportTable;

                for (uint i = ntHeaders->OptionalHeader.NumberOfRvaAndSizes;
                     i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
                     i++) {
                    dataDirectory[i]->Size = 0;
                    dataDirectory[i]->VirtualAddress = 0;
                }

                ntHeaders->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
                ntHeaders->FileHeader.SizeOfOptionalHeader = (ushort) Marshal.SizeOf(typeof(PE32.IMAGE_OPTIONAL_HEADER64));

                ntHeaders->OptionalHeader.SizeOfImage =
                    GetSectionHeaderBasedSizeOfImage(sectionHeaders, ntHeaders->FileHeader.NumberOfSections);

                if (_selectedModule.BaseAddress != IntPtr.Zero) {
                    ntHeaders->OptionalHeader.ImageBase = (ulong) _selectedModule.BaseAddress;
                }

                uint dwSize = (uint) (dosHeader->e_lfanew + sizeof(uint) + Marshal.SizeOf(typeof(PE32.IMAGE_FILE_HEADER)));
                ntHeaders->OptionalHeader.SizeOfHeaders = AlignValue(
                    (uint) (dwSize + ntHeaders->FileHeader.SizeOfOptionalHeader +
                            (ntHeaders->OptionalHeader.NumberOfRvaAndSizes *
                             Marshal.SizeOf(typeof(PE32.IMAGE_SECTION_HEADER)))), ntHeaders->OptionalHeader.FileAlignment);

                //removeIatDirectory
                uint searchAddress = ntHeaders->OptionalHeader.IAT.VirtualAddress;
                ntHeaders->OptionalHeader.IAT.VirtualAddress = 0;
                ntHeaders->OptionalHeader.IAT.Size = 0;

                if (searchAddress > 0) {
                    for (uint i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
                        if ((sectionHeaders[i]->VirtualAddress <= searchAddress) &&
                            ((sectionHeaders[i]->VirtualAddress + sectionHeaders[i]->VirtualSize) > searchAddress)) {
                            //section must be read and writable
                            sectionHeaders[i]->Characteristics |=
                                (uint) (PE32.DataSectionFlags.MemoryRead | PE32.DataSectionFlags.MemoryWrite);
                        }
                    }
                }

                //getFileOverlay
                uint numberOfBytesRead;
                if (!HasOverlayData(sectionHeaders, ntHeaders->FileHeader.NumberOfSections)) {
                    return;
                }

                FileInfo fileInfo = new (_selectedModule.FileName);
                long overlayOffset =
                    GetSectionHeaderBasedFileSize(sectionHeaders, ntHeaders->FileHeader.NumberOfSections);
                long fileSize = fileInfo.Length;
                uint overlaySize = (uint) (fileSize - overlayOffset);

                overlayData = Kernel32.ReadBytes(_selectedProcess.Handle,
                    _selectedModule.BaseAddress + (int) overlayOffset, overlaySize);

                //end of fixed scope
            }

            if (overlayData != null) bytes.Concat(overlayData);
        }

        private unsafe bool HasOverlayData(PE32.IMAGE_SECTION_HEADER*[] sectionHeaders, ushort numberOfSections) {
            if (_selectedModule.FileName == null) return false;

            long fileSize = new FileInfo(_selectedModule.FileName).Length;
            return (fileSize > GetSectionHeaderBasedFileSize(sectionHeaders, numberOfSections));
        }

        private unsafe long GetSectionHeaderBasedFileSize(PE32.IMAGE_SECTION_HEADER*[] sectionHeaders,
            ushort numberOfSections) {
            uint lastRawOffset = 0, lastRawSize = 0;

            //this is needed if the sections aren't sorted by their RawOffset (e.g. Petite)
            for (uint i = 0; i < numberOfSections; i++) {
                if ((sectionHeaders[i]->PointerToRawData + sectionHeaders[i]->SizeOfRawData) >
                    (lastRawOffset + lastRawSize)) {
                    lastRawOffset = sectionHeaders[i]->PointerToRawData;
                    lastRawSize = sectionHeaders[i]->SizeOfRawData;
                }
            }

            return lastRawSize + lastRawOffset;
        }

        private unsafe uint GetSectionHeaderBasedSizeOfImage(PE32.IMAGE_SECTION_HEADER*[] sectionHeaders, ushort count) {
            uint lastVirtualOffset = 0, lastVirtualSize = 0;

            for (int i = 0; i < count; i++) {
                if ((sectionHeaders[i]->VirtualAddress + sectionHeaders[i]->VirtualSize) >
                    (lastVirtualOffset + lastVirtualSize)) {
                    lastVirtualOffset = sectionHeaders[i]->VirtualAddress;
                    lastVirtualSize = sectionHeaders[i]->VirtualSize;
                }
            }

            return lastVirtualSize + lastVirtualOffset;
        }

        private unsafe void SortSectionHeadersDataPtrAscending(PE32.IMAGE_SECTION_HEADER*[] sectionHeaders, ushort count) {
            for (int i = 0; i < count - 1; i++) {
                for (int j = 0; j < count - i - 1; j++) {
                    if (sectionHeaders[j]->PointerToRawData < sectionHeaders[j + 1]->PointerToRawData) continue;
                    PE32.IMAGE_SECTION_HEADER* temp = sectionHeaders[j + 1];
                    sectionHeaders[j + 1] = sectionHeaders[j];
                    sectionHeaders[j] = temp;
                }
            }
        }

        private unsafe void SortSectionHeadersVirtualAddrAscending(PE32.IMAGE_SECTION_HEADER*[] sectionHeaders, ushort count) {
            for (int i = 0; i < count - 1; i++) {
                for (int j = 0; j < count - i - 1; j++) {
                    if (sectionHeaders[j]->VirtualAddress < sectionHeaders[j + 1]->VirtualAddress) continue;
                    PE32.IMAGE_SECTION_HEADER* temp = sectionHeaders[j + 1];
                    sectionHeaders[j + 1] = sectionHeaders[j];
                    sectionHeaders[j] = temp;
                }
            }
        }

}