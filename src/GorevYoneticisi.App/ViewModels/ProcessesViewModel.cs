using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GorevYoneticisi.App.Services;
using GorevYoneticisi.Core;
using GorevYoneticisi.Core.Security;

namespace GorevYoneticisi.App.ViewModels;

public sealed class ProcessRow : ObservableObject
{
    private string? _path;
    private double _cpu, _gpu, _io;
    private long _memory, _gpuMemory;
    private int _threads, _handles;
    private string _signature = "…";
    private RiskLevel _risk;
    private int _riskScore;
    private IReadOnlyList<string> _reasons = Array.Empty<string>();
    private bool _isHidden;
    private ImageSource? _icon;

    public ProcessRow(ProcessInfo p)
    {
        Pid = p.Pid;
        CreateTime = p.CreateTime;
        Name = p.Name;
        ParentPid = p.ParentPid;
        Update(p);
    }

    public int Pid { get; }
    public long CreateTime { get; }
    public string Name { get; }
    public int ParentPid { get; }

    public string? Path
    {
        get => _path;
        private set
        {
            if (SetProperty(ref _path, value)) Icon = Ui.IconCache.Get(value);
        }
    }

    public ImageSource? Icon { get => _icon ??= Ui.IconCache.Get(_path); private set => SetProperty(ref _icon, value); }

    public double Cpu { get => _cpu; private set { if (SetProperty(ref _cpu, value)) OnPropertyChanged(nameof(CpuText)); } }
    public string CpuText => Format.Percent(_cpu);

    public long Memory { get => _memory; private set { if (SetProperty(ref _memory, value)) OnPropertyChanged(nameof(MemoryText)); } }
    public string MemoryText => Format.Bytes(_memory);

    public double Gpu { get => _gpu; private set { if (SetProperty(ref _gpu, value)) OnPropertyChanged(nameof(GpuText)); } }
    public string GpuText => _gpu <= 0 ? "" : Format.Percent(_gpu);

    public long GpuMemory { get => _gpuMemory; private set { if (SetProperty(ref _gpuMemory, value)) OnPropertyChanged(nameof(GpuMemoryText)); } }
    public string GpuMemoryText => _gpuMemory <= 0 ? "" : Format.Bytes(_gpuMemory);

    public double Io { get => _io; private set { if (SetProperty(ref _io, value)) OnPropertyChanged(nameof(IoText)); } }
    public string IoText => _io < 1 ? "" : Format.Rate(_io);

    public int Threads { get => _threads; private set => SetProperty(ref _threads, value); }
    public int Handles { get => _handles; private set => SetProperty(ref _handles, value); }
    public string Signature { get => _signature; private set => SetProperty(ref _signature, value); }
    public RiskLevel Risk { get => _risk; private set => SetProperty(ref _risk, value); }
    public int RiskScore { get => _riskScore; private set => SetProperty(ref _riskScore, value); }
    public IReadOnlyList<string> Reasons { get => _reasons; private set => SetProperty(ref _reasons, value); }
    public bool IsHidden { get => _isHidden; private set => SetProperty(ref _isHidden, value); }

    public void Update(ProcessInfo p)
    {
        Path = p.Path;
        Cpu = Math.Round(p.CpuPercent, 1);
        Memory = p.PrivateWorkingSet;
        Gpu = Math.Round(p.GpuPercent, 1);
        GpuMemory = p.GpuMemory;
        Io = Math.Round(p.IoBytesPerSecond);
        Threads = p.Threads;
        Handles = p.Handles;
        Signature = p.Path is null ? "" : p.Signature.Display;
        Risk = p.Risk.Level;
        RiskScore = p.Risk.Score;
        if (!_reasons.SequenceEqual(p.Risk.Reasons)) Reasons = p.Risk.Reasons;
        IsHidden = p.Hidden?.Kind == HiddenKind.HiddenFromAllLists;
    }
}

public sealed class ProcessesViewModel : ObservableObject
{
    private static readonly HashSet<string> CriticalNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss.exe", "wininit.exe", "smss.exe", "services.exe", "lsass.exe", "winlogon.exe", "System", "Registry",
        "svchost.exe", "dwm.exe", "fontdrvhost.exe", "Secure System", "Memory Compression",
    };

    private readonly MonitorService _monitor;
    private readonly Dictionary<(int, long), ProcessRow> _rows = new();
    private string _search = "";
    private bool _onlyRisky;
    private ProcessRow? _selected;
    private string? _commandLine;
    private string _summary = "";
    private string _message = "";

    public ProcessesViewModel(MonitorService monitor)
    {
        _monitor = monitor;
        View = (ListCollectionView)CollectionViewSource.GetDefaultView(Rows);
        View.IsLiveSorting = true;
        foreach (var p in new[] { nameof(ProcessRow.Cpu), nameof(ProcessRow.Memory), nameof(ProcessRow.Gpu), nameof(ProcessRow.GpuMemory),
                                  nameof(ProcessRow.Io), nameof(ProcessRow.RiskScore), nameof(ProcessRow.Threads), nameof(ProcessRow.Handles) })
            View.LiveSortingProperties.Add(p);
        View.IsLiveFiltering = true;
        View.LiveFilteringProperties.Add(nameof(ProcessRow.Risk));
        View.SortDescriptions.Add(new SortDescription(nameof(ProcessRow.Cpu), ListSortDirection.Descending));
        View.Filter = Filter;

        KillCommand = new RelayCommand(Kill, () => Selected is not null);
        OpenLocationCommand = new RelayCommand(OpenLocation, () => Selected?.Path is not null);
        VirusTotalCommand = new AsyncRelayCommand(VirusTotalAsync, () => Selected?.Path is not null);
        CopyPathCommand = new RelayCommand(() => { if (Selected?.Path is { } p) Clipboard.SetText(p); }, () => Selected?.Path is not null);
    }

    public ObservableCollection<ProcessRow> Rows { get; } = new();
    public ListCollectionView View { get; }

    public RelayCommand KillCommand { get; }
    public RelayCommand OpenLocationCommand { get; }
    public AsyncRelayCommand VirusTotalCommand { get; }
    public RelayCommand CopyPathCommand { get; }

    public string Search
    {
        get => _search;
        set { if (SetProperty(ref _search, value)) View.Refresh(); }
    }

    public bool OnlyRisky
    {
        get => _onlyRisky;
        set { if (SetProperty(ref _onlyRisky, value)) View.Refresh(); }
    }

    public string Summary { get => _summary; private set => SetProperty(ref _summary, value); }
    public string Message { get => _message; private set => SetProperty(ref _message, value); }
    public string? CommandLine { get => _commandLine; private set => SetProperty(ref _commandLine, value); }

    public ProcessRow? Selected
    {
        get => _selected;
        set
        {
            if (!SetProperty(ref _selected, value)) return;
            KillCommand.NotifyCanExecuteChanged();
            OpenLocationCommand.NotifyCanExecuteChanged();
            VirusTotalCommand.NotifyCanExecuteChanged();
            CopyPathCommand.NotifyCanExecuteChanged();
            Message = "";
            CommandLine = null;
            if (value is not null) _ = LoadCommandLineAsync(value);
        }
    }

    private async Task LoadCommandLineAsync(ProcessRow row)
    {
        string? cmd = await Task.Run(() => MonitorService.GetCommandLine(row.Pid));
        if (Selected == row) CommandLine = string.IsNullOrEmpty(cmd) ? "(okunamadı)" : cmd;
    }

    private bool Filter(object o)
    {
        if (o is not ProcessRow r) return false;
        if (_onlyRisky && r.Risk < RiskLevel.Medium) return false;
        if (_search.Length == 0) return true;
        return r.Name.Contains(_search, StringComparison.OrdinalIgnoreCase)
            || r.Pid.ToString() == _search
            || (r.Path?.Contains(_search, StringComparison.OrdinalIgnoreCase) ?? false);
    }

    public void Update(MonitorSnapshot s)
    {
        var seen = new HashSet<(int, long)>();
        foreach (var p in s.Processes)
        {
            if (p.Pid == 0) continue; // System Idle Process: its "CPU" is free capacity, confusing in the list
            var key = (p.Pid, p.CreateTime);
            seen.Add(key);
            if (_rows.TryGetValue(key, out var row))
            {
                row.Update(p);
            }
            else
            {
                row = new ProcessRow(p);
                _rows[key] = row;
                Rows.Add(row);
            }
        }

        foreach (var key in _rows.Keys.Where(k => !seen.Contains(k)).ToList())
        {
            var row = _rows[key];
            _rows.Remove(key);
            Rows.Remove(row);
            if (Selected == row) Selected = null;
        }

        int risky = _rows.Values.Count(r => r.Risk >= RiskLevel.Medium);
        Summary = risky > 0 ? $"{_rows.Count} işlem · {risky} tanesi dikkat istiyor" : $"{_rows.Count} işlem";
    }

    private void Kill()
    {
        var row = Selected;
        if (row is null) return;
        string warning = CriticalNames.Contains(row.Name)
            ? $"\"{row.Name}\" Windows'un çalışması için gerekli bir işlem olabilir. Sonlandırmak bilgisayarın donmasına ya da yeniden başlamasına yol açabilir.\n\nYine de sonlandırılsın mı?"
            : $"\"{row.Name}\" (PID {row.Pid}) sonlandırılsın mı?\n\nKaydedilmemiş veriler kaybolabilir.";
        var answer = System.Windows.MessageBox.Show(warning, "İşlemi sonlandır", MessageBoxButton.YesNo,
            CriticalNames.Contains(row.Name) ? MessageBoxImage.Warning : MessageBoxImage.Question);
        if (answer != MessageBoxResult.Yes) return;
        string? error = ProcessEnumeration.Terminate(row.Pid);
        Message = error ?? $"{row.Name} sonlandırıldı.";
    }

    private void OpenLocation()
    {
        if (Selected?.Path is not { } path) return;
        try
        {
            if (File.Exists(path)) Process.Start("explorer.exe", $"/select,\"{path}\"");
            else if (System.IO.Path.GetDirectoryName(path) is { } dir && Directory.Exists(dir)) Process.Start("explorer.exe", $"\"{dir}\"");
            else Message = "Dosya bulunamadı.";
        }
        catch (Exception ex)
        {
            Message = $"Klasör açılamadı: {ex.Message}";
        }
    }

    private async Task VirusTotalAsync()
    {
        if (Selected?.Path is not { } path) return;
        Message = "Dosyanın parmak izi (SHA-256) hesaplanıyor…";
        string? hash = await HashFileAsync(path);
        if (hash is null)
        {
            Message = "Dosya okunamadı.";
            return;
        }
        Message = $"SHA-256: {hash}. Tarayıcıda VirusTotal açılıyor (dosyanın kendisi gönderilmez).";
        OpenUrl($"https://www.virustotal.com/gui/file/{hash}");
    }

    public static async Task<string?> HashFileAsync(string path)
    {
        try
        {
            return await Task.Run(() =>
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            });
        }
        catch
        {
            return null;
        }
    }

    public static void OpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            App.Log(ex, "Tarayıcı açılamadı");
        }
    }
}
