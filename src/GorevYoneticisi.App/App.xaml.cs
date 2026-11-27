using System.Windows;
using System.Windows.Threading;
using GorevYoneticisi.App.Services;
using GorevYoneticisi.App.ViewModels;

namespace GorevYoneticisi.App;

public partial class App : Application
{
    private MonitorService? _monitor;

    public static string DataFolder { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GorevYoneticisi");

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnDispatcherException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) => Log(args.ExceptionObject as Exception, "Arka plan hatası");
        TaskScheduler.UnobservedTaskException += (_, args) => { Log(args.Exception, "Görev hatası"); args.SetObserved(); };

        var settings = AppSettings.Load();
        settings.ApplyTheme();

        try
        {
            _monitor = new MonitorService
            {
                Interval = TimeSpan.FromMilliseconds(settings.RefreshMilliseconds),
                SecurityInterval = TimeSpan.FromSeconds(settings.SecurityScanSeconds),
            };
        }
        catch (Exception ex)
        {
            Log(ex, "Başlatma hatası");
            MessageBox.Show($"Görev Yöneticisi başlatılamadı:\n\n{ex.Message}\n\nAyrıntılar: {LogPath}",
                "Görev Yöneticisi", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        var vm = new MainViewModel(_monitor, settings);
        var window = new MainWindow { DataContext = vm };
        MainWindow = window;
        window.Show();
        _monitor.Start();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _monitor?.Dispose();
        base.OnExit(e);
    }

    private void OnDispatcherException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Log(e.Exception, "Arayüz hatası");
        e.Handled = true; // keep running; the error is logged
    }

    public static string LogPath => Path.Combine(DataFolder, "hata.log");

    public static void Log(Exception? ex, string context)
    {
        try
        {
            Directory.CreateDirectory(DataFolder);
            File.AppendAllText(LogPath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {context}: {ex}\n\n");
        }
        catch { /* logging must never crash the app */ }
    }
}
