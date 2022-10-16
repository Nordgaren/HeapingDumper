using System.Diagnostics;
using System.Windows;

namespace HeapingDumper {
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window {
        public MainWindow() {
            InitializeComponent();
            DataContextChanged += OnDataContextChanged;
        }

        private MainWindowViewModel _mainWindowViewModel;

        private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e) {
            if (DataContext is MainWindowViewModel vm) {
                _mainWindowViewModel = vm;
            }
        }
    }
}