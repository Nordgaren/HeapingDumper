using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using MemoryMirror.Shared;

namespace HeapingDumper {
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window, INotifyPropertyChanged {
        public MainWindow() {
            InitializeComponent();
            DataContext = this;
            Processes = new(Process.GetProcesses());
        }

        private void Refresh(object sender, RoutedEventArgs e) {
            Processes = new(Process.GetProcesses());
        }

        private ObservableCollection<Process> _processes;

        public ObservableCollection<Process> Processes {
            get => _processes;
            set {
                if (SetField(ref _processes, value)) {
                    OnPropertyChanged(nameof(ProcessCollectionView));
                    ProcessCollectionView.Filter += FilterProcesses;
                }
            }
        }

        public ICollectionView ProcessCollectionView => CollectionViewSource.GetDefaultView(Processes);

        private bool FilterProcesses(object obj) {
            if (obj is Process process) {
                return process.ProcessName.ToLower().Contains(ProcessFilter);
            }

            return false;
        }

        private string _processFilter = string.Empty;

        public string ProcessFilter {
            get => _processFilter;
            set {
                if (SetField(ref _processFilter, value)) {
                    ProcessCollectionView.Refresh();
                }
            }
        }

        private Process _selectedProcess;

        public Process? SelectedProcess {
            get => _selectedProcess;
            set {
                if (SetField(ref _selectedProcess, value)) {
                    Modules = new();
                    try {
                        ProcessModuleCollection modules = SelectedProcess.Modules;
                        foreach (ProcessModule module in modules) {
                            Modules.Add(module);
                        }

                        SelectedModule =
                            Modules.FirstOrDefault(x => x.ModuleName.Contains(SelectedProcess.ProcessName));
                        ModuleCollectionView.Refresh();
                    } catch { } finally {
                        OnPropertyChanged(nameof(ModuleCollectionView));
                        ModuleCollectionView.Filter += FilterModules;
                    }
                }
            }
        }

        private ObservableCollection<ProcessModule> _modules;

        public ObservableCollection<ProcessModule> Modules { get => _modules; set => SetField(ref _modules, value); }

        public ICollectionView ModuleCollectionView => CollectionViewSource.GetDefaultView(Modules);

        private bool FilterModules(object obj) {
            if (obj is ProcessModule module) {
                return module.ModuleName.ToLower().Contains(ModuleFilter);
            }

            return false;
        }

        private string _moduleFilter = string.Empty;

        public string ModuleFilter {
            get => _moduleFilter;
            set {
                if (SetField(ref _moduleFilter, value)) {
                    ModuleCollectionView.Refresh();
                }
            }
        }

        public ProcessModule? SelectedModule { get; set; }

        [DllImport("Scylla.dll")]
        static extern bool ScyllaDumpProcessW(int pid, [MarshalAs(UnmanagedType.LPWStr)] string  fileToDump, IntPtr imagebase, IntPtr entrypoint, [MarshalAs(UnmanagedType.LPWStr)] string fileResult);
        private void Dump(object sender, RoutedEventArgs e) {
            if (SelectedProcess is null || SelectedModule is null) return;

            SelectedProcess.SuspendProcess();

            //Do the dump
            //DumpSelectedModule();
            ScyllaDumpProcessW(SelectedProcess.Id,null, SelectedModule.BaseAddress, SelectedModule.EntryPointAddress, @"C:\Users\Nord\source\repos\CSharp\HeapingDumper\src\HeapingDumper\bin\Debug\net6.0-windows\dump\eldenring_dump_heapingdumper.exe");
            
            // byte[] bytes = Kernel32.ReadBytes(SelectedProcess.Handle, SelectedModule.BaseAddress,
            //     (uint) SelectedModule.ModuleMemorySize);
            //RealignSectionHeaders(bytes);
            RunMemoryMirror();

            SelectedProcess.ResumeProcess();
        }
        public record DumpableChunk(string? Name, IntPtr Size, List<ProcessUtilities.ProcessMemorySegment> Segments);
        private void RunMemoryMirror() {

            var memorySegments = SelectedProcess.EnumerateMemorySegments();
            var snapshot = SelectedProcess.CreateSnapshot();
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

            var readHandle = SelectedProcess.GetReadHandle();
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

        public void DumpSelectedModule() {
            Process process = SelectedProcess;

            IntPtr processHandle = process.Handle;

            IntPtr snapshotHandle =
                Kernel32.CreateToolhelp32Snapshot(Kernel32.SnapshotFlags.HeapList, (uint) process.Id);
            uint error = Kernel32.GetLastError();

            Vanara.PInvoke.Kernel32.HEAPLIST32 heaplist32 = Vanara.PInvoke.Kernel32.HEAPLIST32.Default;
            bool success = Vanara.PInvoke.Kernel32.Heap32ListFirst(snapshotHandle, ref heaplist32);
            error = Kernel32.GetLastError();
            if (error == 0x12) return;

            if (!success) {
                Debug.WriteLine(error);
                throw new Exception($"{nameof(Kernel32.Heap32ListFirst)}  failed");
            }

            do {
                Vanara.PInvoke.Kernel32.HEAPENTRY32 he = Vanara.PInvoke.Kernel32.HEAPENTRY32.Default;

                success = Vanara.PInvoke.Kernel32.Heap32First(ref he, (uint) process.Id, heaplist32.th32HeapID);
                error = Kernel32.GetLastError();

                if (error == 0x12) return;

                if (!success) {
                    Debug.WriteLine(error);
                    throw new Exception($"{nameof(Kernel32.Heap32First)} failed");
                }

                //Write the heap to disk
                do {
                    IntPtr bytesRead = IntPtr.Zero;

                    byte[] bytes = new byte[(int) he.dwBlockSize];
                    success = Kernel32.ReadProcessMemory(processHandle,
                        (IntPtr) he.dwAddress.ToUInt64(), bytes, (IntPtr) bytes.Length,
                        ref bytesRead);
                    error = Kernel32.GetLastError();

                    if (!success) {
                        Debug.WriteLine(error);
                        throw new Exception($"{nameof(Kernel32.ReadProcessMemory)} failed");
                    }

                    File.WriteAllBytes($"{process.ProcessName}-{he.dwAddress:X}.dmp", bytes);

                    he.dwSize = Marshal.SizeOf(he);
                } while (Vanara.PInvoke.Kernel32.Heap32Next(ref he));


                heaplist32.dwSize = Marshal.SizeOf(heaplist32);
            } while (Vanara.PInvoke.Kernel32.Heap32ListNext(snapshotHandle, ref heaplist32));
        }

        private const uint PageExecuteAny = Kernel32.PAGE_EXECUTE | Kernel32.PAGE_EXECUTE_READ |
                                            Kernel32.PAGE_EXECUTE_READWRITE | Kernel32.PAGE_EXECUTE_WRITECOPY;

        private void DumpSelectedModuleFirst() {
            Process process = SelectedProcess;
            List<Kernel32.MEMORY_BASIC_INFORMATION> memRegions = new List<Kernel32.MEMORY_BASIC_INFORMATION>();
            IntPtr memRegionAddr = process.MainModule.BaseAddress;
            IntPtr mainModuleEnd = process.MainModule.BaseAddress + process.MainModule.ModuleMemorySize;
            uint queryResult;

            do {
                var memInfo = new Kernel32.MEMORY_BASIC_INFORMATION();
                queryResult = (uint) Kernel32.VirtualQueryEx(process.Handle, memRegionAddr, out memInfo,
                    (uint) Marshal.SizeOf(memInfo));
                if (queryResult != 0) {
                    if ((memInfo.State & Kernel32.MEM_COMMIT) != 0 && (memInfo.Protect & Kernel32.PAGE_GUARD) == 0 &&
                        (memInfo.Protect & PageExecuteAny) != 0)
                        memRegions.Add(memInfo);
                    memRegionAddr = (IntPtr) (memInfo.BaseAddress + (int) memInfo.RegionSize);
                }
            } while (queryResult != 0 && (ulong) memRegionAddr < (ulong) mainModuleEnd);

            Dictionary<IntPtr, byte[]> readMemory = new Dictionary<IntPtr, byte[]>();
            foreach (Kernel32.MEMORY_BASIC_INFORMATION memRegion in memRegions)
                readMemory[(IntPtr) memRegion.BaseAddress] = Kernel32.ReadBytes(process.Handle,
                    (IntPtr) memRegion.BaseAddress, (uint) memRegion.RegionSize);

            foreach (KeyValuePair<IntPtr, byte[]> pair in readMemory) {
                File.WriteAllBytes($"{process.ProcessName}-{pair.Key:X}", pair.Value);
            }
        }


        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string? name = null) {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null) {
            if (EqualityComparer<T>.Default.Equals(field, value)) return false;
            field = value;
            OnPropertyChanged(propertyName ?? "");
            return true;
        }
    }
}