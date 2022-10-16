using System.Diagnostics;

namespace HeapingDumper.Commands; 

public class RefreshCommand : CommandBase {
    private readonly MainWindowViewModel _mainWindowViewModel;

    public RefreshCommand(MainWindowViewModel mainWindowViewModel) {
        _mainWindowViewModel = mainWindowViewModel;
    }

    public override void Execute(object? parameter) {
        _mainWindowViewModel.Processes = new(Process.GetProcesses());

    }
}