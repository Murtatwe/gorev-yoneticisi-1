using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GorevYoneticisi.App.Services;

namespace GorevYoneticisi.App.ViewModels;

public sealed record Choice<T>(string Label, T Value);

public sealed class SettingsViewModel : ObservableObject
{
    private readonly MonitorService _monitor;
    private readonly AppSettings _settings;

    public SettingsViewModel(MonitorService monitor, AppSettings settings)
    {
        _monitor = monitor;
        _settings = settings;
        OpenLogCommand = new RelayCommand(() =>
        {
            Directory.CreateDirectory(App.DataFolder);
            ProcessesViewModel.OpenUrl(App.DataFolder);
        });
        OpenReleasesCommand = new RelayCommand(() => ProcessesViewModel.OpenUrl("https://github.com/Murtatwe/gorev-yoneticisi-1/releases"));
    }

    public IReadOnlyList<Choice<int>> RefreshOptions { get; } = new[]
    {
        new Choice<int>("Çok hızlı (0,5 sn)", 500),
        new Choice<int>("Normal (1 sn)", 1000),
        new Choice<int>("Yavaş (2 sn)", 2000),
        new Choice<int>("Çok yavaş (5 sn)", 5000),
    };

    public IReadOnlyList<Choice<int>> ScanOptions { get; } = new[]
    {
        new Choice<int>("Her 10 saniyede", 10),
        new Choice<int>("Her 30 saniyede", 30),
        new Choice<int>("Her dakika", 60),
        new Choice<int>("Her 5 dakikada", 300),
    };

    public IReadOnlyList<string> Themes { get; } = new[] { "Koyu", "Açık", "Sistem" };

    public Choice<int> Refresh
    {
        get => RefreshOptions.FirstOrDefault(o => o.Value == _settings.RefreshMilliseconds) ?? RefreshOptions[1];
        set
        {
            if (value is null) return;
            _settings.RefreshMilliseconds = value.Value;
            _monitor.Interval = TimeSpan.FromMilliseconds(value.Value);
            _settings.Save();
            OnPropertyChanged();
        }
    }

    public Choice<int> Scan
    {
        get => ScanOptions.FirstOrDefault(o => o.Value == _settings.SecurityScanSeconds) ?? ScanOptions[1];
        set
        {
            if (value is null) return;
            _settings.SecurityScanSeconds = value.Value;
            _monitor.SecurityInterval = TimeSpan.FromSeconds(value.Value);
            _settings.Save();
            OnPropertyChanged();
        }
    }

    public string Theme
    {
        get => _settings.Theme;
        set
        {
            if (value is null || value == _settings.Theme) return;
            _settings.Theme = value;
            _settings.ApplyTheme();
            _settings.Save();
            OnPropertyChanged();
        }
    }

    public string Version => typeof(SettingsViewModel).Assembly.GetName().Version?.ToString(3) ?? "?";
    public string DataFolder => App.DataFolder;
    public bool IsElevated => _monitor.DebugPrivilege;

    public RelayCommand OpenLogCommand { get; }
    public RelayCommand OpenReleasesCommand { get; }
}
