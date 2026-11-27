using System.Text.Json;
using System.Windows;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace GorevYoneticisi.App;

public sealed class AppSettings
{
    public static readonly int[] RefreshChoices = { 500, 1000, 2000, 5000 };
    public static readonly int[] ScanChoices = { 10, 30, 60, 300 };

    public int RefreshMilliseconds { get; set; } = 1000;
    public int SecurityScanSeconds { get; set; } = 30;
    /// <summary>"Koyu", "Açık" or "Sistem".</summary>
    public string Theme { get; set; } = "Koyu";
    public bool HideMicrosoftStartupItems { get; set; } = true;
    public bool GroupProcessesByApp { get; set; } = true;
    public bool AlwaysOnTop { get; set; }
    public int LastPage { get; set; }
    public double WindowWidth { get; set; } = 1280;
    public double WindowHeight { get; set; } = 820;
    public double? WindowLeft { get; set; }
    public double? WindowTop { get; set; }
    public bool WindowMaximized { get; set; }

    private static string FilePath => Path.Combine(App.DataFolder, "ayarlar.json");

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var s = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath));
                if (s is not null)
                {
                    // Snap hand-edited values to the choices the Settings page offers.
                    s.RefreshMilliseconds = Nearest(RefreshChoices, s.RefreshMilliseconds);
                    s.SecurityScanSeconds = Nearest(ScanChoices, s.SecurityScanSeconds);
                    s.WindowWidth = Math.Clamp(s.WindowWidth, 960, 10000);
                    s.WindowHeight = Math.Clamp(s.WindowHeight, 600, 10000);
                    return s;
                }
            }
        }
        catch (Exception ex)
        {
            App.Log(ex, "Ayarlar okunamadı");
        }
        return new AppSettings();
    }

    private static int Nearest(int[] choices, int value) => choices.OrderBy(c => Math.Abs(c - value)).First();

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(App.DataFolder);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            App.Log(ex, "Ayarlar kaydedilemedi");
        }
    }

    public void ApplyTheme(Window? window = null)
    {
        try
        {
            if (window is not null) SystemThemeWatcher.UnWatch(window);
            switch (Theme)
            {
                case "Açık":
                    ApplicationThemeManager.Apply(ApplicationTheme.Light);
                    break;
                case "Sistem":
                    ApplicationThemeManager.ApplySystemTheme();
                    // Follow Windows light/dark changes while the app runs.
                    if (window is not null) SystemThemeWatcher.Watch(window, WindowBackdropType.Mica, true);
                    break;
                default:
                    ApplicationThemeManager.Apply(ApplicationTheme.Dark);
                    break;
            }
        }
        catch (Exception ex)
        {
            App.Log(ex, "Tema uygulanamadı");
        }
    }
}
