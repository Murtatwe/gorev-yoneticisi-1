using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using GorevYoneticisi.App.ViewModels;
using Wpf.Ui.Controls;

namespace GorevYoneticisi.App;

public partial class MainWindow : FluentWindow
{
    private readonly AppSettings _settings;

    public MainWindow(AppSettings settings)
    {
        _settings = settings;
        InitializeComponent();

        Width = settings.WindowWidth;
        Height = settings.WindowHeight;
        if (settings.WindowLeft is double left && settings.WindowTop is double top && IsOnScreen(left, top))
        {
            WindowStartupLocation = WindowStartupLocation.Manual;
            Left = left;
            Top = top;
        }
        Topmost = settings.AlwaysOnTop;
        Loaded += (_, _) =>
        {
            if (settings.WindowMaximized) WindowState = WindowState.Maximized;
            settings.ApplyTheme(this);
        };
    }

    private static bool IsOnScreen(double left, double top) =>
        left >= SystemParameters.VirtualScreenLeft - 50 && top >= SystemParameters.VirtualScreenTop - 50 &&
        left < SystemParameters.VirtualScreenLeft + SystemParameters.VirtualScreenWidth - 100 &&
        top < SystemParameters.VirtualScreenTop + SystemParameters.VirtualScreenHeight - 100;

    protected override void OnClosing(CancelEventArgs e)
    {
        var bounds = WindowState == WindowState.Normal ? new Rect(Left, Top, Width, Height) : RestoreBounds;
        _settings.WindowMaximized = WindowState == WindowState.Maximized;
        if (!bounds.IsEmpty)
        {
            _settings.WindowLeft = bounds.Left;
            _settings.WindowTop = bounds.Top;
            _settings.WindowWidth = bounds.Width;
            _settings.WindowHeight = bounds.Height;
        }
        if (DataContext is MainViewModel vm) _settings.LastPage = vm.Pages.ToList().IndexOf(vm.SelectedPage);
        _settings.Save();
        base.OnClosing(e);
    }

    /// <summary>Ctrl+1…6 switches pages.</summary>
    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        if (Keyboard.Modifiers == ModifierKeys.Control && DataContext is MainViewModel vm)
        {
            int index = e.Key switch
            {
                Key.D1 or Key.NumPad1 => 0, Key.D2 or Key.NumPad2 => 1, Key.D3 or Key.NumPad3 => 2,
                Key.D4 or Key.NumPad4 => 3, Key.D5 or Key.NumPad5 => 4, Key.D6 or Key.NumPad6 => 5,
                _ => -1,
            };
            if (index >= 0 && index < vm.Pages.Count)
            {
                vm.SelectedPage = vm.Pages[index];
                e.Handled = true;
                return;
            }
        }
        base.OnPreviewKeyDown(e);
    }

    private void SecurityCard_Click(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is MainViewModel vm) vm.ShowPage(vm.Security);
    }
}
