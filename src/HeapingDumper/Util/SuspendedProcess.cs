using System;
using System.Diagnostics;

namespace HeapingDumper.Commands;
public class SuspendedProcess : IDisposable {
    private readonly Process _selectedProcess;
    private bool _attemptedSuspend;
    public SuspendedProcess(Process selectedProcess) {
        _selectedProcess = selectedProcess;
    }
    public void Suspend() {
        _attemptedSuspend = true;
        _selectedProcess.SuspendProcess();
    }
    public void Dispose() {
        if (_attemptedSuspend) _selectedProcess.ResumeProcess();
    }
}