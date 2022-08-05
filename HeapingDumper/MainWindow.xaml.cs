using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
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
            if (SelectedProcess is null || SelectedModule is null)
                return;
            
            Kernel32.SuspendProcess(SelectedProcess.Id);
            
            //Do the dump
            DumpSelectedModule();
            
            Kernel32.ResumeProcess(SelectedProcess.Id);
        }

        private void DumpSelectedModule()
        {
            long length = SelectedModule.ModuleMemorySize - SelectedModule.BaseAddress.ToInt64();
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