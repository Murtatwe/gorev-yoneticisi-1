using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GorevYoneticisi.App.Services;
using GorevYoneticisi.Core.Security;

namespace GorevYoneticisi.App.ViewModels;

public sealed class StartupRow : ObservableObject
{
    private string _signature = "…";
    private bool _isMicrosoft;
    private RiskLevel _risk;
    private int _score;
    private IReadOnlyList<string> _reasons = Array.Empty<string>();

    private System.Windows.Media.ImageSource? _icon;

    public StartupRow(StartupEntry e)
    {
        Entry = e;
        string? path = e.TargetPath is { } t && System.IO.Path.IsPathFullyQualified(t) ? t : null;
        _icon = Ui.IconCache.GetOrQueue(path, img => Icon = img);
    }

    public StartupEntry Entry { get; }
    public System.Windows.Media.ImageSource? Icon { get => _icon; private set => SetProperty(ref _icon, value); }
    public string Name => Entry.Name;
    public string Category => Entry.Category;
    public string Location => Entry.Location;
    public string Command => Entry.Command;
    public string Target => Entry.TargetPath ?? "(çözümlenemedi)";
    public string EnabledText => Entry.Enabled ? "Etkin" : "Devre dışı";

    public string Signature { get => _signature; set => SetProperty(ref _signature, value); }
    public bool IsMicrosoft { get => _isMicrosoft; set => SetProperty(ref _isMicrosoft, value); }
    public RiskLevel Risk { get => _risk; set => SetProperty(ref _risk, value); }
    public int RiskScore { get => _score; set => SetProperty(ref _score, value); }
    public IReadOnlyList<string> Reasons { get => _reasons; set => SetProperty(ref _reasons, value); }
}

public sealed class StartupViewModel : ObservableObject
{
    private readonly MonitorService _monitor;
    private readonly AppSettings _settings;
    private bool _loaded, _isLoading, _stale;
    private string _search = "", _summary = "";
    private StartupRow? _selected;

    public StartupViewModel(MonitorService monitor, AppSettings settings)
    {
        _monitor = monitor;
        _settings = settings;
        View = (ListCollectionView)CollectionViewSource.GetDefaultView(Rows);
        View.SortDescriptions.Add(new SortDescription(nameof(StartupRow.RiskScore), ListSortDirection.Descending));
        View.SortDescriptions.Add(new SortDescription(nameof(StartupRow.Name), ListSortDirection.Ascending));
        View.Filter = Filter;
        RefreshCommand = new AsyncRelayCommand(LoadAsync, () => !IsLoading);
        OpenLocationCommand = new RelayCommand(OpenLocation, () => Selected?.Entry.TargetPath is not null);
        VirusTotalCommand = new AsyncRelayCommand(async () =>
        {
            if (Selected?.Entry.TargetPath is not { } p) return;
            string? hash = await ProcessesViewModel.HashFileAsync(p);
            if (hash is not null) ProcessesViewModel.OpenUrl($"https://www.virustotal.com/gui/file/{hash}");
        }, () => Selected?.Entry.TargetPath is not null);
    }

    public ObservableCollection<StartupRow> Rows { get; } = new();
    public ListCollectionView View { get; }
    public AsyncRelayCommand RefreshCommand { get; }
    public RelayCommand OpenLocationCommand { get; }
    public AsyncRelayCommand VirusTotalCommand { get; }

    public bool IsLoading
    {
        get => _isLoading;
        private set { if (SetProperty(ref _isLoading, value)) RefreshCommand.NotifyCanExecuteChanged(); }
    }

    public string Summary { get => _summary; private set => SetProperty(ref _summary, value); }
    public string Search { get => _search; set { if (SetProperty(ref _search, value)) View.Refresh(); } }

    public bool HideMicrosoft
    {
        get => _settings.HideMicrosoftStartupItems;
        set
        {
            if (_settings.HideMicrosoftStartupItems == value) return;
            _settings.HideMicrosoftStartupItems = value;
            _settings.Save();
            OnPropertyChanged();
            View.Refresh();
        }
    }

    public StartupRow? Selected
    {
        get => _selected;
        set
        {
            if (!SetProperty(ref _selected, value)) return;
            OpenLocationCommand.NotifyCanExecuteChanged();
            VirusTotalCommand.NotifyCanExecuteChanged();
        }
    }

    /// <summary>Called when the page becomes visible.</summary>
    public void Activate()
    {
        if (!_loaded)
        {
            _loaded = true;
            _ = LoadAsync();
        }
        else if (_stale)
        {
            RefreshSignatures();
        }
    }

    /// <summary>New signature results arrived while the page was hidden; refresh on next visit.</summary>
    public void MarkStale() => _stale = true;

    private async Task LoadAsync()
    {
        IsLoading = true;
        Summary = "Başlangıç öğeleri okunuyor…";
        try
        {
            var entries = await Task.Run(() => new StartupItems().Read());
            using (View.DeferRefresh())
            {
                Rows.Clear();
                foreach (var e in entries) Rows.Add(new StartupRow(e));
            }
            RefreshSignatures(force: true);
        }
        catch (Exception ex)
        {
            App.Log(ex, "Başlangıç öğeleri okunamadı");
            Summary = "Başlangıç öğeleri okunamadı.";
        }
        finally
        {
            IsLoading = false;
        }
    }

    /// <summary>Re-evaluates signatures and risk (called when background signature checks finish).</summary>
    public void RefreshSignatures(bool force = false)
    {
        _stale = false;
        if (Rows.Count == 0) return;
        bool changed = force;
        foreach (var row in Rows)
        {
            bool wasMicrosoft = row.IsMicrosoft;
            int oldScore = row.RiskScore;
            var path = row.Entry.TargetPath;
            var sig = _monitor.GetSignature(path, highPriority: false);
            row.Signature = path is null || !System.IO.Path.IsPathFullyQualified(path) ? "" : sig.Display;
            // Windows' own tasks whose file cannot be resolved (COM handlers etc.) count as Microsoft items too.
            row.IsMicrosoft = (sig.Status == SignatureStatus.Signed && (sig.Signer?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ?? false))
                || (path is null && row.Entry.ExtraScore == 0 && row.Entry.Location.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase));
            string name = path is null ? row.Name : System.IO.Path.GetFileName(path);
            var risk = _monitor.AssessStartupFile(name, path, row.Entry.ExtraScore, row.Entry.ExtraReasons);
            row.Risk = risk.Level;
            row.RiskScore = risk.Score;
            if (!row.Reasons.SequenceEqual(risk.Reasons)) row.Reasons = risk.Reasons;
            changed |= wasMicrosoft != row.IsMicrosoft || oldScore != row.RiskScore;
        }
        // A full refresh regenerates the grid (scroll jumps), so only do it when sorting/filtering is affected.
        if (changed) View.Refresh();
        int risky = Rows.Count(r => r.Risk >= RiskLevel.Medium);
        int visible = View.Count;
        Summary = $"{Rows.Count} öğe ({visible} gösteriliyor)" + (risky > 0 ? $" · {risky} tanesi dikkat istiyor" : "");
    }

    private bool Filter(object o)
    {
        if (o is not StartupRow r) return false;
        if (HideMicrosoft && r.IsMicrosoft && r.Risk < RiskLevel.Medium) return false;
        if (_search.Length == 0) return true;
        return r.Name.Contains(_search, StringComparison.OrdinalIgnoreCase)
            || r.Command.Contains(_search, StringComparison.OrdinalIgnoreCase)
            || r.Category.Contains(_search, StringComparison.OrdinalIgnoreCase);
    }

    private void OpenLocation()
    {
        if (Selected?.Entry.TargetPath is not { } path) return;
        try
        {
            if (File.Exists(path)) Process.Start("explorer.exe", $"/select,\"{path}\"");
            else if (System.IO.Path.GetDirectoryName(path) is { } dir && Directory.Exists(dir)) Process.Start("explorer.exe", $"\"{dir}\"");
        }
        catch (Exception ex)
        {
            App.Log(ex, "Klasör açılamadı");
        }
    }
}
