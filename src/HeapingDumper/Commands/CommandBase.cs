using System;
using System.ComponentModel;
using System.Windows.Input;

namespace HeapingDumper.Commands;

public abstract class CommandBase : ICommand {
    public event EventHandler? CanExecuteChanged;

    public virtual bool CanExecute(object? parameter) {
        return true;
    }

    public abstract void Execute(object? parameter);

    protected void OnCanExecuteChanged() {
        System.Windows.Application.Current.Dispatcher.Invoke(
            () => { CanExecuteChanged?.Invoke(this, new EventArgs()); });
    }

}