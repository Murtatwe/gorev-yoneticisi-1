using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using GorevYoneticisi.App.ViewModels;

namespace GorevYoneticisi.App.Views;

public partial class ProcessesView : UserControl
{
    private const double SideBySideWidth = 1060;

    public ProcessesView()
    {
        InitializeComponent();
        SizeChanged += (_, _) => PlaceDetails();
        Loaded += (_, _) => PlaceDetails();
    }

    /// <summary>
    /// Wide window: details in their own column. Narrow window: details float over the right edge of the list,
    /// so the list keeps all its columns readable.
    /// </summary>
    private void PlaceDetails()
    {
        bool wide = ActualWidth >= SideBySideWidth;
        System.Windows.Controls.Grid.SetColumn(DetailsPanel, wide ? 1 : 0);
        DetailsPanel.HorizontalAlignment = wide ? HorizontalAlignment.Stretch : HorizontalAlignment.Right;
        DetailsPanel.Margin = wide ? new Thickness(12, 0, 0, 0) : new Thickness(0, 0, 4, 4);
    }

    /// <summary>Clicking an app row also selects its biggest process, so its details open right away.</summary>
    private void GroupHeader_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: CollectionViewGroup group } && DataContext is ProcessesViewModel vm)
        {
            var top = group.Items.OfType<ProcessRow>().OrderByDescending(r => r.Memory).FirstOrDefault();
            if (top is not null) vm.Selected = top;
        }
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
