using System.Diagnostics;
using System.Windows;
using System.Windows.Threading;
using GorevYoneticisi.App.Services;
using GorevYoneticisi.App.ViewModels;

namespace GorevYoneticisi.App;

public partial class App : Application
{
    private MonitorService? _monitor;
    private bool _smoke;
    private int _uiErrorShown;

    public static string DataFolder { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GorevYoneticisi");

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnDispatcherException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) => Log(args.ExceptionObject as Exception, "Arka plan hatası");
        TaskScheduler.UnobservedTaskException += (_, args) => { Log(args.Exception, "Görev hatası"); args.SetObserved(); };

        _smoke = e.Args.Length > 0 && e.Args[0] == "--smoke-test";
        if (_smoke)
        {
            try { File.Delete(LogPath); } catch { }
        }

        var settings = AppSettings.Load();
        settings.ApplyTheme();

        MainViewModel vm;
        MainWindow window;
        try
        {
            _monitor = new MonitorService
            {
                Interval = TimeSpan.FromMilliseconds(settings.RefreshMilliseconds),
                SecurityInterval = TimeSpan.FromSeconds(settings.SecurityScanSeconds),
            };
            vm = new MainViewModel(_monitor, settings);
            window = new MainWindow(settings) { DataContext = vm };
            MainWindow = window;
            window.Show();
        }
        catch (Exception ex)
        {
            Fatal(ex);
            return;
        }

        _monitor.Start();
        if (_smoke) SmokeTest.Run(window, vm, _monitor, e.Args.Length > 1 ? e.Args[1] : Path.Combine(DataFolder, "duman-testi"));
    }

    /// <summary>Startup failed: tell the user (never leave an invisible elevated process behind) and exit.</summary>
    private void Fatal(Exception ex)
    {
        Log(ex, "Başlatma hatası");
        if (!_smoke)
        {
            MessageBox.Show($"Görev Yöneticisi başlatılamadı:\n\n{ex.Message}\n\nAyrıntılar şu dosyaya yazıldı:\n{LogPath}",
                "Görev Yöneticisi", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        _monitor?.Dispose();
        Shutdown(3);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _monitor?.Dispose();
        base.OnExit(e);
    }

    private void OnDispatcherException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        e.Handled = true;
        if (MainWindow is null || !MainWindow.IsLoaded)
        {
            Fatal(e.Exception);
            return;
        }
        Log(e.Exception, "Arayüz hatası");
        // Show the first error once so a broken page is not silently empty; later ones only go to the log.
        if (!_smoke && Interlocked.Exchange(ref _uiErrorShown, 1) == 0)
        {
            MessageBox.Show($"Beklenmeyen bir hata oluştu; program çalışmaya devam ediyor.\n\n{e.Exception.Message}\n\nAyrıntılar: {LogPath}",
                "Görev Yöneticisi", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    public static string LogPath => Path.Combine(DataFolder, "hata.log");

    private static readonly object LogLock = new();

    public static void Log(Exception? ex, string context)
    {
        try
        {
            lock (LogLock)
            {
                Directory.CreateDirectory(DataFolder);
                File.AppendAllText(LogPath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {context}: {ex}\n\n");
            }
        }
        catch { /* logging must never crash the app */ }
    }

    /// <summary>Starts a new elevated copy of the app and closes this one.</summary>
    public static void RestartAsAdmin()
    {
        try
        {
            string? exe = Environment.ProcessPath;
            if (exe is null) return;
            Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas" });
            Current.Shutdown();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // The user said "No" to the UAC prompt.
        }
    }
}
