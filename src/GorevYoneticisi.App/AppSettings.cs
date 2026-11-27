using System.Text.Json;
using Wpf.Ui.Appearance;

namespace GorevYoneticisi.App;

public sealed class AppSettings
{
    public int RefreshMilliseconds { get; set; } = 1000;
    public int SecurityScanSeconds { get; set; } = 30;
    /// <summary>"Koyu", "Açık" or "Sistem".</summary>
    public string Theme { get; set; } = "Koyu";
    public bool HideMicrosoftStartupItems { get; set; } = true;

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
                    s.RefreshMilliseconds = Math.Clamp(s.RefreshMilliseconds, 250, 10000);
                    s.SecurityScanSeconds = Math.Clamp(s.SecurityScanSeconds, 5, 600);
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

    public void ApplyTheme()
    {
        try
        {
            switch (Theme)
            {
                case "Açık":
                    ApplicationThemeManager.Apply(ApplicationTheme.Light);
                    break;
                case "Sistem":
                    ApplicationThemeManager.ApplySystemTheme();
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
