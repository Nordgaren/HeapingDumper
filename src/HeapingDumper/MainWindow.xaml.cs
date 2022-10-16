using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;

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

        private void TextChanged(object sender, TextChangedEventArgs e) {
            if (sender is TextBox tb) tb.ScrollToEnd();
        }
    }
}