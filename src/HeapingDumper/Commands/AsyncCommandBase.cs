using System;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows.Input;

namespace HeapingDumper.Commands;

public abstract class AsyncCommandBase : ICommand {
    public event EventHandler? CanExecuteChanged;

    public virtual bool CanExecute(object? parameter) {
        return true;
    }

    public async void Execute(object? parameter) {
            await ExecuteAsync(parameter);
    }

    public abstract Task ExecuteAsync(object? parameter);

    protected void OnCanExecuteChanged() {
        System.Windows.Application.Current.Dispatcher.Invoke(
            () => { CanExecuteChanged?.Invoke(this, new EventArgs()); });
    }
}