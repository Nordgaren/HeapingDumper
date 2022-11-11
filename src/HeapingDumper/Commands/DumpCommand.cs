using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using MemoryMirror.Shared;
using Microsoft.Win32;
using System.Globalization;

namespace HeapingDumper.Commands;

public class DumpCommand : AsyncCommandBase {
    private readonly MainWindowViewModel _mainWindowViewModel;

    public DumpCommand(MainWindowViewModel mainWindowViewModel) {
        _mainWindowViewModel = mainWindowViewModel;
        _mainWindowViewModel.PropertyChanged += MainWindowPropertyChanged;
    }

    public override bool CanExecute(object? parameter) {
        if (_mainWindowViewModel.SelectedProcess is null || _mainWindowViewModel.SelectedModule is null) return false;
        return base.CanExecute(parameter);
    }

    [DllImport("Scylla.dll")]
    static extern bool ScyllaDumpProcessW(int pid, [MarshalAs(UnmanagedType.LPWStr)] string fileToDump,
        IntPtr imagebase, IntPtr entrypoint, [MarshalAs(UnmanagedType.LPWStr)] string fileResult);

    public async void Execute(object? parameter) {
        try {
            await ExecuteAsync(parameter);
        } catch (Exception ex) {
            _mainWindowViewModel.LogException(ex);
        }
    }

    public override Task ExecuteAsync(object? parameter) {
        return Task.Run(async () => {
            int logLength = _mainWindowViewModel.Log.Length;

            Process? selectedProcess = _mainWindowViewModel.SelectedProcess;
            ProcessModule? selectedModule = _mainWindowViewModel.SelectedModule;

            string fileName = Path.GetFileNameWithoutExtension(selectedModule.FileName) ??
                              throw new InvalidOperationException("Module file name invalid");
            string filePath = Path.GetDirectoryName(selectedModule.FileName) ??
                              throw new InvalidOperationException("Module file path invalid");
            OpenFileDialog ofd = new() {
                Title = "Select Dump Output Path",
                InitialDirectory = filePath,
                FileName = $"{fileName}_dump.exe",
                CheckFileExists = false,
                CheckPathExists = false
            };

            if (!ofd.ShowDialog().Value) {
                _mainWindowViewModel.AppendLog("No file selected...");
                return;
            }

            string outputPath = Path.GetDirectoryName(ofd.FileName) ??
                                throw new InvalidOperationException("Dump output path invalid");
            Directory.CreateDirectory(outputPath);
            string outputFile = Path.GetFileName(ofd.FileName);
            _mainWindowViewModel.AppendLog("Begin Dumping...");
            string[] files = Array.Empty<string>();
            try {
                using (SuspendedProcess p = new (selectedProcess)) {
                    p.Suspend();
                    
                    //Calls Scylla dll to dump the exe from memory
                    ScyllaDumpProcessW(
                        selectedProcess.Id,
                        null,
                        selectedModule.BaseAddress,
                        selectedModule.EntryPointAddress,
                        $"{outputPath}\\{outputFile}"
                    );

                    //Calls MemoryMirror library to dump heap memory segments
                    files = RunMemoryMirror(selectedProcess, outputPath);
                }
                
            } catch (Exception ex) {
                _mainWindowViewModel.LogException(ex);
            }
            
            _mainWindowViewModel.AppendLog("Renaming Files...");
            //RenameDumpFiles(outputPath, files);
            _mainWindowViewModel.AppendLog("Finished Dumping...");
            
            File.WriteAllText(
                $"{Path.GetFileNameWithoutExtension(outputFile)} {DateTime.Now:M-d-y HH-mm-ss} DumpLog.txt",
                _mainWindowViewModel.Log.Substring(logLength));
        });
    }
    private void RenameDumpFiles(string outputPath, string[] files) {
        foreach (string path in files) {
            string[] parts = Path.GetFileName(path).Split("-");
            long start = long.Parse(parts[0], NumberStyles.HexNumber);
            FileInfo f = new FileInfo(path);
            File.Move(path, $"{outputPath}\\{parts[0]}-{start + f.Length:X2}-{parts[1]}");
        }
    }

    public record DumpableChunk(string? Name, IntPtr Size, List<ProcessUtilities.ProcessMemorySegment> Segments);

    private string[] RunMemoryMirror(Process selectedProcess, string outputPath) {
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
        List<string> paths = new List<string>();
        foreach (var chunk in chunks) {
            IntPtr baseAddress = chunk.Key;
            var segments = chunk.Value.Segments;
            string path = $"{outputPath}\\{chunk.Key:X}-{chunk.Key.ToInt64() + chunk.Value.Size.ToInt64():X2}-{chunk.Value.Name ?? "UNKNOWN"}.dmp";
            paths.Add(path);
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
            
            _mainWindowViewModel.AppendLog($"Written dump to {path} (0x{chunk.Value.Size:X2})");
        }

        return paths.ToArray();
    }


    private void MainWindowPropertyChanged(object? sender, PropertyChangedEventArgs e) {
        if (e.PropertyName is nameof(MainWindowViewModel.SelectedProcess)
            or nameof(MainWindowViewModel.SelectedModule)) {
            OnCanExecuteChanged();
        }
    }
}