﻿using System;
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
                    } catch { } finally {
                        OnPropertyChanged(nameof(ModuleCollectionView));
                        ModuleCollectionView.Filter += FilterModules;
                    }
                }
            }
        }

        private void Dump(object sender, RoutedEventArgs e) {
            if (SelectedProcess is null || SelectedModule is null) return;

            // Kernel32.SuspendProcess(SelectedProcess.Id);

            //Do the dump
            DumpSelectedModule();

            //Kernel32.ResumeProcess(SelectedProcess.Id);
        }

        public void DumpSelectedModule() {
            Process process = SelectedProcess;

            IntPtr processHandle = process.Handle;

            IntPtr snapshotHandle =
                Kernel32.CreateToolhelp32Snapshot(Kernel32.SnapshotFlags.HeapList, (uint) process.Id);
            uint error = Kernel32.GetLastError();

            Kernel32.HEAPLIST32 heaplist32 = new() {
                dwSize = (UIntPtr) Marshal.SizeOf(typeof(Kernel32.HEAPLIST32))
            };

            bool success = Kernel32.Heap32ListFirst(snapshotHandle, ref heaplist32);
            error = Kernel32.GetLastError();
            if (error == 0x12) return;

            if (!success) {
                Debug.WriteLine(error);
                throw new Exception($"{nameof(Kernel32.Heap32ListFirst)}  failed");
            }

            do
            {
                Kernel32.HEAPENTRY32 he = new() {
                    dwSize = (UIntPtr) Marshal.SizeOf(typeof(Kernel32.HEAPENTRY32))
                };

                success = Kernel32.Heap32First(ref he, (uint) process.Id, heaplist32.th32HeapID);
                error = Kernel32.GetLastError();

                if (error == 0x12) return;

                if (!success) {
                    Debug.WriteLine(error);
                    throw new Exception($"{nameof(Kernel32.Heap32First)} failed");
                }

                //Write the heap to disk
                do 
                {
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

                    he.dwSize = (UIntPtr) Marshal.SizeOf(he);
                } while (Kernel32.Heap32Next(ref he));


                heaplist32.dwSize = (UIntPtr) Marshal.SizeOf(heaplist32);
            } while (Kernel32.Heap32ListNext(snapshotHandle, ref heaplist32));
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

            // File.WriteAllBytes("ER_Dump.exe", bytes);
            // MemoryStream stream = new MemoryStream(bytes);
            // PEHeaders peHeaders = new PEHeaders(stream);
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