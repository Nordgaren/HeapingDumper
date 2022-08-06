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

namespace HeapingDumper
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        public MainWindow()
        {
            InitializeComponent();
            DataContext = this;
            Processes = new(Process.GetProcesses());
        }

        private void Refresh(object sender, RoutedEventArgs e)
        {
            Processes = new(Process.GetProcesses());
        }

        private ObservableCollection<Process> _processes;

        public ObservableCollection<Process> Processes
        {
            get => _processes;
            set
            {
                if (SetField(ref _processes, value))
                {
                    OnPropertyChanged(nameof(ProcessCollectionView));
                    ProcessCollectionView.Filter += FilterProcesses;
                }
            }
        }

        public ICollectionView ProcessCollectionView => CollectionViewSource.GetDefaultView(Processes);

        private bool FilterProcesses(object obj)
        {
            if (obj is Process process)
            {
                return process.ProcessName.ToLower().Contains(ProcessFilter);
            }

            return false;
        }

        private string _processFilter = string.Empty;

        public string ProcessFilter
        {
            get => _processFilter;
            set
            {
                if (SetField(ref _processFilter, value))
                {
                    ProcessCollectionView.Refresh();
                }
            }
        }

        private Process _selectedProcess;

        public Process? SelectedProcess
        {
            get => _selectedProcess;
            set
            {
                if (SetField(ref _selectedProcess, value))
                {
                    Modules = new();
                    try
                    {
                        ProcessModuleCollection modules = SelectedProcess.Modules;
                        foreach (ProcessModule module in modules)
                        {
                            Modules.Add(module);
                        }
                    }
                    catch
                    {
                    }
                    finally
                    {
                        
                        OnPropertyChanged(nameof(ModuleCollectionView));
                        ModuleCollectionView.Filter += FilterModules;
                    }

                }
            }
        }

        private void Dump(object sender, RoutedEventArgs e)
        {
            if (SelectedProcess is null || SelectedModule is null) return;
            
            Kernel32.SuspendProcess(SelectedProcess.Id);
            
            //Do the dump
            DumpSelectedModule();
            
            Kernel32.ResumeProcess(SelectedProcess.Id);
        }

        public void DumpSelectedModule()
        {
            // getting minimum & maximum address
            
            Kernel32.SYSTEM_INFO sysInfo = new Kernel32.SYSTEM_INFO();
            Kernel32.GetSystemInfo(out sysInfo);  

            IntPtr procMinAddress = sysInfo.lpMinimumApplicationAddress;
            IntPtr procMaxAddress = sysInfo.lpMaximumApplicationAddress;

            // saving the values as long ints so I won't have to do a lot of casts later
            long procMinAddressL = (long)procMinAddress;
            long procMaxAddressL = (long)procMaxAddress;

            Process process = SelectedProcess;

            // opening the process with desired access level
            IntPtr processHandle = SelectedProcess.Handle;
            //OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, process.Id);

            // this will store any information we get from VirtualQueryEx()
            Kernel32.MEMORY_BASIC_INFORMATION memBasicInfo = new Kernel32.MEMORY_BASIC_INFORMATION();

            IntPtr bytesRead = IntPtr.Zero;  // number of bytes read with ReadProcessMemory

            while (procMinAddressL < procMaxAddressL)
            {
                List<byte> bytes = new();
                // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                Kernel32.VirtualQueryEx(processHandle, procMinAddress, out memBasicInfo, (IntPtr)28);
                
                // if this memory chunk is accessible
                if (memBasicInfo.Protect == 
                Kernel32.PAGE_READWRITE && memBasicInfo.State == Kernel32.MEM_COMMIT)
                {
                    byte[] buffer = new byte[(int)memBasicInfo.RegionSize];

                    // read everything in the buffer above
                    Kernel32.ReadProcessMemory(processHandle, 
                    memBasicInfo.BaseAddress, buffer, memBasicInfo.RegionSize, ref bytesRead);

                    // then output this in the file
                    File.WriteAllBytes($"{process.ProcessName}-{memBasicInfo.BaseAddress:X}",buffer);
                    
                }

                // move to the next memory chunk
                procMinAddressL += (long)memBasicInfo.RegionSize;
                procMinAddress = new IntPtr(procMinAddressL);
            }
            
        }
        
        private const uint PageExecuteAny = Kernel32.PAGE_EXECUTE | Kernel32.PAGE_EXECUTE_READ | Kernel32.PAGE_EXECUTE_READWRITE | Kernel32.PAGE_EXECUTE_WRITECOPY;
        private void DumpSelectedModuleFirst()
        {
            Process process = SelectedProcess;
            List<Kernel32.MEMORY_BASIC_INFORMATION> memRegions = new List<Kernel32.MEMORY_BASIC_INFORMATION>();
            IntPtr memRegionAddr = process.MainModule.BaseAddress;
            IntPtr mainModuleEnd = process.MainModule.BaseAddress + process.MainModule.ModuleMemorySize;
            uint queryResult;
            
            do
            {
                var memInfo = new Kernel32.MEMORY_BASIC_INFORMATION();
                queryResult = Kernel32.VirtualQueryEx(process.Handle, memRegionAddr, out memInfo, (IntPtr)Marshal.SizeOf(memInfo));
                if (queryResult != 0)
                {
                    if ((memInfo.State & Kernel32.MEM_COMMIT) != 0 && (memInfo.Protect & Kernel32.PAGE_GUARD) == 0 && (memInfo.Protect & PageExecuteAny) != 0)
                        memRegions.Add(memInfo);
                    memRegionAddr = memInfo.BaseAddress + (int)memInfo.RegionSize;
                }
            } while (queryResult != 0 && (ulong)memRegionAddr < (ulong)mainModuleEnd);
            
            Dictionary<IntPtr, byte[]> readMemory = new Dictionary<IntPtr, byte[]>();
            foreach (Kernel32.MEMORY_BASIC_INFORMATION memRegion in memRegions)
                readMemory[memRegion.BaseAddress] = Kernel32.ReadBytes(process.Handle, memRegion.BaseAddress, (uint)memRegion.RegionSize);

            foreach (KeyValuePair<IntPtr,byte[]> pair in readMemory)
            {
                File.WriteAllBytes($"{process.ProcessName}-{pair.Key:X}",pair.Value);
            }
            
            // File.WriteAllBytes("ER_Dump.exe", bytes);
            // MemoryStream stream = new MemoryStream(bytes);
            // PEHeaders peHeaders = new PEHeaders(stream);
            
            
        }

        private ObservableCollection<ProcessModule> _modules;

        public ObservableCollection<ProcessModule> Modules
        {
            get => _modules;
            set => SetField(ref _modules, value);
        }

        public ICollectionView ModuleCollectionView => CollectionViewSource.GetDefaultView(Modules);

        private bool FilterModules(object obj)
        {
            if (obj is ProcessModule module)
            {
                return module.ModuleName.ToLower().Contains(ModuleFilter);
            }

            return false;
        }

        private string _moduleFilter = string.Empty;

        public string ModuleFilter
        {
            get => _moduleFilter;
            set
            {
                if (SetField(ref _moduleFilter, value))
                {
                    ModuleCollectionView.Refresh();
                }
            }
        }

        public ProcessModule? SelectedModule { get; set; }


        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string? name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }


        protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value)) return false;
            field = value;
            OnPropertyChanged(propertyName ?? "");
            return true;
        }
    }
}