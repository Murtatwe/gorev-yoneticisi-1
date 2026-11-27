using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
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

/// <summary>All processes of one app (same executable), summed, for the grouped view.</summary>
public sealed class AppGroup : ObservableObject
{
    private double _cpu, _gpu, _io;
    private long _memory;
    private int _count;
    private RiskLevel _risk;

    public AppGroup(string key, string name, string? path)
    {
        Key = key;
        Name = name;
        _icon = Ui.IconCache.GetOrQueue(path, img => Icon = img);
    }

    private ImageSource? _icon;

    public string Key { get; }
    public string Name { get; }
    public ImageSource? Icon { get => _icon; private set => SetProperty(ref _icon, value); }
    public double Cpu { get => _cpu; set { if (SetProperty(ref _cpu, value)) OnPropertyChanged(nameof(CpuText)); } }
    public long Memory { get => _memory; set { if (SetProperty(ref _memory, value)) OnPropertyChanged(nameof(MemoryText)); } }
    public double Gpu { get => _gpu; set { if (SetProperty(ref _gpu, value)) OnPropertyChanged(nameof(GpuText)); } }
    public double Io { get => _io; set { if (SetProperty(ref _io, value)) OnPropertyChanged(nameof(IoText)); } }
    public int Count { get => _count; set { if (SetProperty(ref _count, value)) OnPropertyChanged(nameof(CountText)); } }
    public RiskLevel Risk { get => _risk; set => SetProperty(ref _risk, value); }
    public string CpuText => Format.Percent(_cpu);
    public string MemoryText => Format.Bytes(_memory);
    public string GpuText => _gpu <= 0 ? "" : Format.Percent(_gpu);
    public string IoText => _io < 1 ? "" : Format.Rate(_io);
    public string CountText => _count == 1 ? "" : $"({_count})";
    public override string ToString() => Name;
}

public sealed class ProcessRow : ObservableObject
{
    private string? _path;
    private double _cpu, _gpu, _io, _memoryPercent, _groupCpu;
    private long _memory, _gpuMemory;
    private int _threads, _handles;
    private string _signature = "…";
    private RiskLevel _risk;
    private int _riskScore;
    private IReadOnlyList<string> _reasons = Array.Empty<string>();
    private bool _isHidden;
    private ImageSource? _icon;
    private AppGroup? _group;

    public ProcessRow(ProcessInfo p)
    {
        Pid = p.Pid;
        CreateTime = p.CreateTime;
        Name = p.Name;
        ParentPid = p.ParentPid;
        StartedAt = p.CreateTime > 0 ? DateTime.FromFileTime(p.CreateTime) : null;
        Update(p, 1);
    }

    public int Pid { get; }
    public long CreateTime { get; }
    public string Name { get; }
    public int ParentPid { get; }
    public DateTime? StartedAt { get; }
    public string StartedText => StartedAt is { } t ? $"{t:dd.MM.yyyy HH:mm:ss} (çalışma süresi {Format.Duration(DateTime.Now - t)})" : "bilinmiyor";
    public string GroupKey => string.IsNullOrEmpty(_path) ? Name.ToLowerInvariant() : _path.ToLowerInvariant();

    public string? Path
    {
        get => _path;
        private set
        {
            if (SetProperty(ref _path, value)) Icon = Ui.IconCache.GetOrQueue(value, img => { if (_path == value) Icon = img; });
        }
    }

    public ImageSource? Icon { get => _icon; private set => SetProperty(ref _icon, value); }

    public AppGroup? Group { get => _group; set => SetProperty(ref _group, value); }
    /// <summary>The group's CPU, copied here so live sorting can order groups by it.</summary>
    public double GroupCpu { get => _groupCpu; set => SetProperty(ref _groupCpu, value); }

    public double Cpu { get => _cpu; private set { if (SetProperty(ref _cpu, value)) OnPropertyChanged(nameof(CpuText)); } }
    public string CpuText => Format.Percent(_cpu);

    public long Memory { get => _memory; private set { if (SetProperty(ref _memory, value)) OnPropertyChanged(nameof(MemoryText)); } }
    public string MemoryText => Format.Bytes(_memory);
    public double MemoryPercent { get => _memoryPercent; private set => SetProperty(ref _memoryPercent, value); }

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

    public void Update(ProcessInfo p, long totalMemory)
    {
        Path = p.Path;
        Cpu = Math.Round(p.CpuPercent, 1);
        Memory = p.PrivateWorkingSet;
        MemoryPercent = totalMemory > 0 ? p.PrivateWorkingSet * 100.0 / totalMemory : 0;
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
        "svchost.exe", "dwm.exe", "fontdrvhost.exe", "Secure System", "Memory Compression", "explorer.exe",
    };

    private readonly MonitorService _monitor;
    private readonly AppSettings _settings;
    private readonly Dictionary<(int, long), ProcessRow> _rows = new();
    private readonly Dictionary<string, AppGroup> _groups = new();
    private string _search = "";
    private bool _onlyRisky;
    private ProcessRow? _selected;
    private string? _commandLine;
    private string _summary = "";
    private string _message = "";
    private string _cpuHeader = "CPU", _memHeader = "Bellek", _gpuHeader = "GPU", _ioHeader = "Disk";
    private long _totalMemory = 1;

    public ProcessesViewModel(MonitorService monitor, AppSettings settings)
    {
        _monitor = monitor;
        _settings = settings;
        View = (ListCollectionView)CollectionViewSource.GetDefaultView(Rows);
        View.IsLiveSorting = true;
        foreach (var p in new[] { nameof(ProcessRow.Cpu), nameof(ProcessRow.Memory), nameof(ProcessRow.Gpu), nameof(ProcessRow.GpuMemory),
                                  nameof(ProcessRow.Io), nameof(ProcessRow.RiskScore), nameof(ProcessRow.GroupCpu) })
            View.LiveSortingProperties.Add(p);
        View.IsLiveFiltering = true;
        View.LiveFilteringProperties.Add(nameof(ProcessRow.Risk));
        View.Filter = Filter;
        ApplyGrouping();

        KillCommand = new RelayCommand(Kill, () => Selected is not null);
        KillTreeCommand = new RelayCommand(KillTree, () => Selected is not null);
        OpenLocationCommand = new RelayCommand(OpenLocation, () => Selected?.Path is not null);
        VirusTotalCommand = new AsyncRelayCommand(VirusTotalAsync, () => Selected?.Path is not null);
        CopyPathCommand = new RelayCommand(() => { if (Selected?.Path is { } p) TrySetClipboard(p); }, () => Selected?.Path is not null);
        SearchOnlineCommand = new RelayCommand(() =>
        {
            if (Selected is { } r) OpenUrl("https://www.bing.com/search?q=" + Uri.EscapeDataString($"{r.Name} {(r.Signature.Length > 1 ? r.Signature : "")} nedir".Trim()));
        }, () => Selected is not null);
        PropertiesCommand = new RelayCommand(() => { if (Selected?.Path is { } p) ShowFileProperties(p); }, () => Selected?.Path is not null);
        ClearSearchCommand = new RelayCommand(() => Search = "");
    }

    public ObservableCollection<ProcessRow> Rows { get; } = new();
    public ListCollectionView View { get; }

    public RelayCommand KillCommand { get; }
    public RelayCommand KillTreeCommand { get; }
    public RelayCommand OpenLocationCommand { get; }
    public AsyncRelayCommand VirusTotalCommand { get; }
    public RelayCommand CopyPathCommand { get; }
    public RelayCommand SearchOnlineCommand { get; }
    public RelayCommand PropertiesCommand { get; }
    public RelayCommand ClearSearchCommand { get; }

    public string Search
    {
        get => _search;
        set { if (SetProperty(ref _search, value ?? "")) View.Refresh(); }
    }

    public bool OnlyRisky
    {
        get => _onlyRisky;
        set { if (SetProperty(ref _onlyRisky, value)) View.Refresh(); }
    }

    public bool GroupByApp
    {
        get => _settings.GroupProcessesByApp;
        set
        {
            if (_settings.GroupProcessesByApp == value) return;
            _settings.GroupProcessesByApp = value;
            _settings.Save();
            OnPropertyChanged();
            ApplyGrouping();
        }
    }

    public string CpuHeader { get => _cpuHeader; private set => SetProperty(ref _cpuHeader, value); }
    public string MemoryHeader { get => _memHeader; private set => SetProperty(ref _memHeader, value); }
    public string GpuHeader { get => _gpuHeader; private set => SetProperty(ref _gpuHeader, value); }
    public string IoHeader { get => _ioHeader; private set => SetProperty(ref _ioHeader, value); }

    public string Summary { get => _summary; private set => SetProperty(ref _summary, value); }
    public string Message { get => _message; private set => SetProperty(ref _message, value); }
    public string? CommandLine { get => _commandLine; private set => SetProperty(ref _commandLine, value); }

    public ProcessRow? Selected
    {
        get => _selected;
        set
        {
            if (!SetProperty(ref _selected, value)) return;
            foreach (var c in new IRelayCommand[] { KillCommand, KillTreeCommand, OpenLocationCommand, VirusTotalCommand, CopyPathCommand, SearchOnlineCommand, PropertiesCommand })
                c.NotifyCanExecuteChanged();
            OnPropertyChanged(nameof(HasSelection));
            OnPropertyChanged(nameof(ParentText));
            Message = "";
            CommandLine = null;
            if (value is not null) _ = LoadCommandLineAsync(value);
        }
    }

    public bool HasSelection => _selected is not null;

    public string ParentText
    {
        get
        {
            if (_selected is null) return "";
            var parent = _rows.Values.FirstOrDefault(r => r.Pid == _selected.ParentPid);
            return parent is null ? $"PID {_selected.ParentPid} (artık çalışmıyor)" : $"{parent.Name} (PID {parent.Pid})";
        }
    }

    /// <summary>Selects a process by PID (used by the Security page) and clears filters that would hide it.</summary>
    public void Reveal(int pid)
    {
        Search = "";
        OnlyRisky = false;
        Selected = _rows.Values.FirstOrDefault(r => r.Pid == pid);
    }

    private void ApplyGrouping()
    {
        using (View.DeferRefresh())
        {
            View.GroupDescriptions.Clear();
            View.SortDescriptions.Clear();
            if (_settings.GroupProcessesByApp)
            {
                View.GroupDescriptions.Add(new PropertyGroupDescription(nameof(ProcessRow.Group)));
                View.SortDescriptions.Add(new SortDescription(nameof(ProcessRow.GroupCpu), ListSortDirection.Descending));
            }
            View.SortDescriptions.Add(new SortDescription(nameof(ProcessRow.Cpu), ListSortDirection.Descending));
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
            || (r.Path?.Contains(_search, StringComparison.OrdinalIgnoreCase) ?? false)
            || r.Signature.Contains(_search, StringComparison.OrdinalIgnoreCase);
    }

    public void Update(MonitorSnapshot s)
    {
        _totalMemory = (long)Math.Max(1, s.Totals.MemoryTotal);
        var seen = new HashSet<(int, long)>();
        foreach (var p in s.Processes)
        {
            if (p.Pid == 0) continue; // System Idle Process: its "CPU" is free capacity, confusing in the list
            var key = (p.Pid, p.CreateTime);
            seen.Add(key);
            if (_rows.TryGetValue(key, out var row))
            {
                row.Update(p, _totalMemory);
            }
            else
            {
                row = new ProcessRow(p);
                row.Update(p, _totalMemory);
                _rows[key] = row;
                AssignGroup(row);
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

        UpdateGroups();

        var t = s.Totals;
        double memPct = t.MemoryTotal == 0 ? 0 : (t.MemoryTotal - t.MemoryAvailable) * 100.0 / t.MemoryTotal;
        CpuHeader = $"CPU\n{Format.Percent(t.CpuPercent)}";
        MemoryHeader = $"Bellek\n{Format.Percent(memPct)}";
        GpuHeader = t.GpuAvailable ? $"GPU\n{Format.Percent(t.GpuPercent)}" : "GPU\n—";
        IoHeader = $"Disk\n{Format.Percent(t.DiskActivePercent)}";

        int risky = _rows.Values.Count(r => r.Risk >= RiskLevel.Medium);
        string apps = _groups.Count == _rows.Count ? "" : $" · {_groups.Count} uygulama";
        Summary = $"{_rows.Count} işlem{apps}" + (risky > 0 ? $" · {risky} tanesi dikkat istiyor" : "");
    }

    private void AssignGroup(ProcessRow row)
    {
        string key = row.GroupKey;
        if (!_groups.TryGetValue(key, out var g))
        {
            g = new AppGroup(key, row.Name, row.Path);
            _groups[key] = g;
        }
        row.Group = g;
    }

    private void UpdateGroups()
    {
        var byGroup = _rows.Values.Where(r => r.Group is not null).GroupBy(r => r.Group!).ToList();
        var alive = new HashSet<string>();
        foreach (var grp in byGroup)
        {
            var g = grp.Key;
            alive.Add(g.Key);
            g.Cpu = Math.Round(grp.Sum(r => r.Cpu), 1);
            g.Memory = grp.Sum(r => r.Memory);
            g.Gpu = Math.Round(Math.Min(100, grp.Sum(r => r.Gpu)), 1);
            g.Io = grp.Sum(r => r.Io);
            g.Count = grp.Count();
            g.Risk = grp.Max(r => r.Risk);
            foreach (var r in grp) r.GroupCpu = g.Cpu;
        }
        foreach (var key in _groups.Keys.Where(k => !alive.Contains(k)).ToList()) _groups.Remove(key);
    }

    private bool ConfirmKill(ProcessRow row, string what)
    {
        bool critical = CriticalNames.Contains(row.Name);
        string text = critical
            ? $"\"{row.Name}\" Windows'un çalışması için gerekli bir program olabilir. {what} bilgisayarın donmasına ya da yeniden başlamasına yol açabilir.\n\nYine de devam edilsin mi?"
            : $"{what}: \"{row.Name}\" (PID {row.Pid})\n\nKaydedilmemiş veriler kaybolabilir. Devam edilsin mi?";
        return System.Windows.MessageBox.Show(text, "Görevi sonlandır", MessageBoxButton.YesNo,
            critical ? MessageBoxImage.Warning : MessageBoxImage.Question) == MessageBoxResult.Yes;
    }

    private void Kill()
    {
        var row = Selected;
        if (row is null || !ConfirmKill(row, "Program sonlandırılacak")) return;
        string? error = ProcessEnumeration.Terminate(row.Pid);
        Message = error ?? $"{row.Name} sonlandırıldı.";
    }

    private void KillTree()
    {
        var row = Selected;
        if (row is null || !ConfirmKill(row, "Program ve başlattığı tüm programlar sonlandırılacak")) return;
        // Children first, so they cannot respawn the parent's work; PID + start time guard against reused PIDs.
        var victims = new List<ProcessRow>();
        void Collect(ProcessRow parent, int depth)
        {
            if (depth > 32) return;
            foreach (var child in _rows.Values.Where(r => r.ParentPid == parent.Pid && r.CreateTime > parent.CreateTime && r != parent))
                Collect(child, depth + 1);
            victims.Add(parent);
        }
        Collect(row, 0);
        int failed = victims.Count(v => ProcessEnumeration.Terminate(v.Pid) is not null);
        Message = failed == 0 ? $"{victims.Count} program sonlandırıldı." : $"{victims.Count - failed} program sonlandırıldı, {failed} tanesi sonlandırılamadı.";
    }

    private void OpenLocation()
    {
        if (Selected?.Path is not { } path) return;
        Message = OpenInExplorer(path) ?? "";
    }

    public static string? OpenInExplorer(string path)
    {
        try
        {
            if (File.Exists(path)) Process.Start("explorer.exe", $"/select,\"{path}\"");
            else if (System.IO.Path.GetDirectoryName(path) is { } dir && Directory.Exists(dir)) Process.Start("explorer.exe", $"\"{dir}\"");
            else return "Dosya bulunamadı.";
            return null;
        }
        catch (Exception ex)
        {
            return $"Klasör açılamadı: {ex.Message}";
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
        Message = "VirusTotal tarayıcıda açılıyor. Yalnızca dosyanın parmak izi kullanılır, dosyanın kendisi gönderilmez.";
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

    private static void TrySetClipboard(string text)
    {
        // The clipboard can be locked by another program for a moment.
        for (int i = 0; i < 3; i++)
        {
            try
            {
                Clipboard.SetText(text);
                return;
            }
            catch (COMException)
            {
                Thread.Sleep(50);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHELLEXECUTEINFOW
    {
        public int cbSize;
        public uint fMask;
        public IntPtr hwnd;
        public string? lpVerb;
        public string lpFile;
        public string? lpParameters;
        public string? lpDirectory;
        public int nShow;
        public IntPtr hInstApp;
        public IntPtr lpIDList;
        public string? lpClass;
        public IntPtr hkeyClass;
        public uint dwHotKey;
        public IntPtr hIconOrMonitor;
        public IntPtr hProcess;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ShellExecuteExW(ref SHELLEXECUTEINFOW info);

    /// <summary>Opens Windows' own file properties dialog (details, digital signatures tab, ...).</summary>
    public static void ShowFileProperties(string path)
    {
        const uint SEE_MASK_INVOKEIDLIST = 0x0000000C;
        var info = new SHELLEXECUTEINFOW
        {
            cbSize = Marshal.SizeOf<SHELLEXECUTEINFOW>(),
            fMask = SEE_MASK_INVOKEIDLIST,
            lpVerb = "properties",
            lpFile = path,
            nShow = 1,
        };
        if (!ShellExecuteExW(ref info)) App.Log(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()), "Özellikler açılamadı");
    }
}
