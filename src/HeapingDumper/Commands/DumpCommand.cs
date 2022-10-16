﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;
using MemoryMirror.Shared;
using Microsoft.Win32;

namespace HeapingDumper.Commands;

public class DumpCommand : CommandBase {
    private readonly MainWindowViewModel _mainWindowViewModel;

    public DumpCommand(MainWindowViewModel mainWindowViewModel) {
        _mainWindowViewModel = mainWindowViewModel;
    }
    
    [DllImport("Scylla.dll")]
    static extern bool ScyllaDumpProcessW(int pid, [MarshalAs(UnmanagedType.LPWStr)] string fileToDump,
        IntPtr imagebase, IntPtr entrypoint, [MarshalAs(UnmanagedType.LPWStr)] string fileResult);

    public override void Execute(object? parameter) {
        
        Process? selectedProcess = _mainWindowViewModel.SelectedProcess;
        ProcessModule? selectedModule = _mainWindowViewModel.SelectedModule;
        
        if (selectedProcess is null || selectedModule is null) return;
        
        string fileName = Path.GetFileNameWithoutExtension(selectedModule.FileName) ?? throw new InvalidOperationException("Module file name invalid");
        string filePath = Path.GetDirectoryName(selectedModule.FileName) ?? throw new InvalidOperationException("Module file path invalid");
        OpenFileDialog ofd = new() {
            Title = "Select Dump Output Path",
            InitialDirectory = filePath,
            FileName = $"{fileName}_dump.exe",
            CheckFileExists = false,
            CheckPathExists = false
        };
        
        if (!ofd.ShowDialog().Value) {
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(ofd.FileName) ?? throw new InvalidOperationException("Dump output path invalid"));
        
        selectedProcess.SuspendProcess();

        ScyllaDumpProcessW(selectedProcess.Id, null, selectedModule.BaseAddress, selectedModule.EntryPointAddress,
            ofd.FileName);

        RunMemoryMirror(selectedProcess);

        selectedProcess.ResumeProcess();
    }

    public record DumpableChunk(string? Name, IntPtr Size, List<ProcessUtilities.ProcessMemorySegment> Segments);

    private void RunMemoryMirror(Process selectedProcess) {
        
        var memorySegments = selectedProcess.EnumerateMemorySegments();
        var snapshot = selectedProcess.CreateSnapshot();
        var modules = SnapshotModuleHelper.EnumerateModules(snapshot);

        var chunks = new Dictionary<IntPtr, DumpableChunk>();
        foreach (var segment in memorySegments.OrderBy(m => m.Address)) {
            // Mach anything that is between the start and the end of the module
            var associatedModule = modules.FirstOrDefault(
                m =>
                    (Int64) m.Address <= (Int64) segment.Address &&
                    (Int64) m.Address + (Int64) m.Size >= (Int64) segment.Address
            );

            var chunkAddress = associatedModule?.Address ?? segment.Address;
            var chunkSize = associatedModule?.Size ?? segment.Size;
            if (chunks.ContainsKey(chunkAddress)) {
                chunks[chunkAddress].Segments.Add(segment);
            } else {
                var chunk = new DumpableChunk(
                    associatedModule?.Name,
                    chunkSize,
                    new List<ProcessUtilities.ProcessMemorySegment> {segment}
                );
                chunks[chunkAddress] = chunk;
            }
        }

        var readHandle = selectedProcess.GetReadHandle();
        foreach (var chunk in chunks) {
            var baseAddress = chunk.Key;
            var segments = chunk.Value.Segments;

            string path = $"./dump/{chunk.Key:X}-{chunk.Value.Name ?? "UNKNOWN"}.dmp";
            var fileStream = File.OpenWrite(path);

            foreach (var segment in segments) {
                var segmentOffset = (UInt64) segment.Address - (UInt64) baseAddress;
                var takenSize = (UInt64) 0x0;

                while (takenSize < (UInt64) segment.Size) {
                    // Chunk by max 1GB
                    var currentChunkedSize =
                        (UInt64) segment.Size > 0x3B9ACA00 ? 0x3B9ACA00 : (UInt64) segment.Size;
                    var chunkedSegmentBuffer = ProcessUtilities.ReadMemoryToBuffer(
                        readHandle,
                        (IntPtr) ((UInt64) segment.Address + takenSize),
                        (IntPtr) currentChunkedSize
                    );

                    fileStream.Seek(0, SeekOrigin.Begin);
                    fileStream.Seek((long) (segmentOffset + takenSize), SeekOrigin.Begin);
                    fileStream.Write(chunkedSegmentBuffer);

                    takenSize += currentChunkedSize;
                }
            }

            Console.WriteLine($"Written dump to {path} ({chunk.Value.Size})");
        }
    }
}