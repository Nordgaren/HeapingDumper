using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using HeapingDumper.Commands;
using MemoryMirror.Shared;

namespace HeapingDumper;

public class MainWindowViewModel : INotifyPropertyChanged {
    private ObservableCollection<Process> _processes;

    public ObservableCollection<Process> Processes {
        get => _processes;
        set {
            if (setField(ref _processes, value)) {
                onPropertyChanged(nameof(ProcessCollectionView));
                ProcessCollectionView.Filter += filterProcesses;
            }
        }
    }

    private Process? _selectedProcess;

    public Process? SelectedProcess {
        get => _selectedProcess;
        set {
            if (setField(ref _selectedProcess, value)) {
                setSelectedModule();
            }
        }
    }

    private void setSelectedModule() {
        Modules = new();
        try {
            ProcessModuleCollection modules = SelectedProcess.Modules;
            foreach (ProcessModule module in modules) {
                Modules.Add(module);
            }

            SelectedModule =
                Modules.FirstOrDefault(x => x.ModuleName.Contains(SelectedProcess.ProcessName));
            ModuleCollectionView.Refresh();
        } catch (Exception ex) {
            LogException(ex);
        } finally {
            onPropertyChanged(nameof(ModuleCollectionView));
            ModuleCollectionView.Filter += filterModules;
        }
    }

    public ICollectionView ProcessCollectionView => CollectionViewSource.GetDefaultView(Processes);

    private ProcessModule? _processModule;
    public ProcessModule? SelectedModule { get => _processModule; set => setField(ref _processModule, value); }
    private ObservableCollection<ProcessModule> _modules;
    public ObservableCollection<ProcessModule> Modules { get => _modules; set => setField(ref _modules, value); }
    public ICollectionView ModuleCollectionView => CollectionViewSource.GetDefaultView(Modules);

    public ICommand RefreshCommand { get; }
    public ICommand DumpCommand { get; }

    public MainWindowViewModel() {
        RefreshCommand = new RefreshCommand(this);
        DumpCommand = new DumpCommand(this);

        //Global
        AppDomain.CurrentDomain.UnhandledException += globalExceptionHandler;

        //WPF specific - setting this event as handled can prevent crashes
        Dispatcher.CurrentDispatcher.UnhandledException += wpfExceptionHandler;

        Processes = new(Process.GetProcesses());
        waitForProcess();
    }

    private string _log = string.Empty;
    public string Log { get => _log; set => setField(ref _log, value); }

    public void AppendLog(string message) {
        Log += $"{message}\n";
    }

    void waitForProcess() {
        ManagementEventWatcher startWatch = new ManagementEventWatcher(
            new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
        startWatch.EventArrived += startWatch_EventArrived;
        startWatch.Start();

        ManagementEventWatcher stopWatch = new ManagementEventWatcher(
            new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace"));
        stopWatch.EventArrived += stopWatch_EventArrived;
        stopWatch.Start();
    }

    void startWatch_EventArrived(object sender, EventArrivedEventArgs e) {
        AppendLog(string.Format("Process started: {0}"
            , e.NewEvent.Properties["ProcessName"].Value));

        Process process = Process.GetProcessById((int) (uint) e.NewEvent.Properties["ProcessID"].Value);
        if (Processes.Any(x => x.Id == process.Id)) return;
        Application.Current.Dispatcher.Invoke(() => { Processes.Add(process); });
    }

    void stopWatch_EventArrived(object sender, EventArrivedEventArgs e) {
        AppendLog(string.Format("Process ended: {0}"
            , e.NewEvent.Properties["ProcessName"].Value));

        Process? process = Processes.FirstOrDefault(x => x.Id == (int) (uint) e.NewEvent.Properties["ProcessID"].Value);
        if (process != null) {
            Application.Current.Dispatcher.Invoke(() => { Processes.Remove(process); });
        }
    }

    private bool filterProcesses(object obj) {
        if (obj is Process process) {
            return process.ProcessName.ToLower().Contains(ProcessFilter);
        }

        return false;
    }

    private string _processFilter = string.Empty;

    public string ProcessFilter {
        get => _processFilter;
        set {
            if (setField(ref _processFilter, value)) {
                ProcessCollectionView.Refresh();
            }
        }
    }

    private bool filterModules(object obj) {
        if (obj is ProcessModule module) {
            return module.ModuleName.ToLower().Contains(ModuleFilter);
        }

        return false;
    }

    private string _moduleFilter = string.Empty;

    public string ModuleFilter {
        get => _moduleFilter;
        set {
            if (setField(ref _moduleFilter, value)) {
                ModuleCollectionView.Refresh();
            }
        }
    }


    public event PropertyChangedEventHandler? PropertyChanged;

    protected void onPropertyChanged([CallerMemberName] string? name = null) {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    protected bool setField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null) {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        onPropertyChanged(propertyName ?? "");
        return true;
    }

    void globalExceptionHandler(object sender, UnhandledExceptionEventArgs e) {
        try {
            Exception? ex = (Exception) e.ExceptionObject;
            LogException(ex);
        } catch (Exception ex) {
            LogException(ex);
        }
    }

    public void LogException(Exception e) {
        AppendLog($"Exception: {e.Message}");
        File.AppendAllText("DumpException.txt", $"Exception: {DateTime.Now:g}\n" +
                                                $"{e}");
    }


    private void wpfExceptionHandler(object sender, DispatcherUnhandledExceptionEventArgs e) {
        try {
            LogException(e.Exception);
        } catch (Exception ex) {
            LogException(ex);
        }
    }
}