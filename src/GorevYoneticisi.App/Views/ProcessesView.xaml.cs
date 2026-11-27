using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using GorevYoneticisi.App.ViewModels;

namespace GorevYoneticisi.App.Views;

public partial class ProcessesView : UserControl
{
    public ProcessesView()
    {
        InitializeComponent();
    }

    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.F && Keyboard.Modifiers == ModifierKeys.Control)
        {
            SearchBox.Focus();
            SearchBox.SelectAll();
            e.Handled = true;
            return;
        }
        base.OnPreviewKeyDown(e);
    }

    /// <summary>Right-click selects the row under the mouse first, so the menu acts on it.</summary>
    private void Grid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        var dep = e.OriginalSource as DependencyObject;
        while (dep is not null && dep is not DataGridRow)
            dep = dep is Visual or System.Windows.Media.Media3D.Visual3D ? VisualTreeHelper.GetParent(dep) : LogicalTreeHelper.GetParent(dep);
        if (dep is DataGridRow row)
        {
            row.IsSelected = true;
            row.Focus();
        }
    }

    private void CloseDetails_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is ProcessesViewModel vm) vm.Selected = null;
    }
}
