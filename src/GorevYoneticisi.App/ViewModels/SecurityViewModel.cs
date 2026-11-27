using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GorevYoneticisi.App.Services;
using GorevYoneticisi.Core;
using GorevYoneticisi.Core.Security;

namespace GorevYoneticisi.App.ViewModels;

public sealed class FindingRow
{
    public required string Title { get; init; }
    public required string Subtitle { get; init; }
    public required string Description { get; init; }
    public required RiskLevel Level { get; init; }
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    public string? Path { get; init; }
    public int Pid { get; init; }
    public System.Windows.Media.ImageSource? Icon { get; init; }
}

public sealed class SecurityViewModel : ObservableObject
{
    private readonly MonitorService _monitor;
    private readonly MainViewModel _main;
    private bool _isScanning;
    private string _lastScan = "Henüz tarama yapılmadı.";
    private string _verdict = "Tarama bekleniyor";
    private RiskLevel _verdictLevel = RiskLevel.None;
    private string _methodNote = "";
    private IReadOnlyList<FindingRow> _hidden = Array.Empty<FindingRow>();
    private IReadOnlyList<FindingRow> _risky = Array.Empty<FindingRow>();
    private int _riskySignature;

    public SecurityViewModel(MonitorService monitor, MainViewModel main)
    {
        _monitor = monitor;
        _main = main;
        ScanCommand = new AsyncRelayCommand(ScanAsync, () => !IsScanning);
        ShowInProcessesCommand = new RelayCommand<FindingRow>(row =>
        {
            if (row is null) return;
            _main.Processes.Search = row.Pid.ToString();
            _main.ShowPage(_main.Processes);
        });
        VirusTotalCommand = new AsyncRelayCommand<FindingRow>(async row =>
        {
            if (row?.Path is null) return;
            string? hash = await ProcessesViewModel.HashFileAsync(row.Path);
            if (hash is not null) ProcessesViewModel.OpenUrl($"https://www.virustotal.com/gui/file/{hash}");
        });
    }

    public AsyncRelayCommand ScanCommand { get; }
    public RelayCommand<FindingRow> ShowInProcessesCommand { get; }
    public AsyncRelayCommand<FindingRow> VirusTotalCommand { get; }

    public bool IsElevated => _monitor.DebugPrivilege;

    public bool IsScanning
    {
        get => _isScanning;
        private set { if (SetProperty(ref _isScanning, value)) ScanCommand.NotifyCanExecuteChanged(); }
    }

    public string LastScan { get => _lastScan; private set => SetProperty(ref _lastScan, value); }
    public string Verdict { get => _verdict; private set => SetProperty(ref _verdict, value); }
    public RiskLevel VerdictLevel { get => _verdictLevel; private set => SetProperty(ref _verdictLevel, value); }
    public string MethodNote { get => _methodNote; private set => SetProperty(ref _methodNote, value); }
    public IReadOnlyList<FindingRow> HiddenFindings { get => _hidden; private set { SetProperty(ref _hidden, value); OnPropertyChanged(nameof(HasHidden)); } }
    public IReadOnlyList<FindingRow> RiskyProcesses { get => _risky; private set { SetProperty(ref _risky, value); OnPropertyChanged(nameof(HasRisky)); } }
    public bool HasHidden => _hidden.Count > 0;
    public bool HasRisky => _risky.Count > 0;

    private async Task ScanAsync()
    {
        IsScanning = true;
        try
        {
            // Two scans: a discrepancy only counts when it is seen twice in a row.
            await _monitor.RunSecurityScanAsync();
            await Task.Delay(1500);
            await _monitor.RunSecurityScanAsync();
        }
        finally
        {
            IsScanning = false;
        }
    }

    public void UpdateReport(SecurityReport r)
    {
        LastScan = $"Son tarama: {r.Time:HH:mm:ss} · {r.Duration.TotalMilliseconds:0} ms · " +
                   $"{r.PrimaryCount} işlem listede, {r.BruteForceCount} işlem doğrudan erişimle doğrulandı";

        MethodNote = r.Result.FailedMethods.Count == 0
            ? ""
            : "Bazı listeleme yöntemleri çalışmadı: " + string.Join(", ", r.Result.FailedMethods.Select(MethodName)) +
              ". Bu yöntemlerin sonuçları karşılaştırmaya katılmadı.";

        HiddenFindings = r.Items.Select(i => new FindingRow
        {
            Title = i.Name,
            Subtitle = i.Path is null ? $"PID {i.Finding.Pid}" : $"PID {i.Finding.Pid} · {i.Path}",
            Description = i.Finding.Description,
            Level = i.Finding.Severity,
            Path = i.Path,
            Pid = i.Finding.Pid,
            Icon = Ui.IconCache.Get(i.Path),
        }).OrderByDescending(f => f.Level).ToList();

        int high = r.Items.Count(i => i.Finding.Severity == RiskLevel.High);
        if (!r.Result.PrimaryAvailable)
        {
            Verdict = "Tarama tamamlanamadı: Windows işlem listesi okunamadı.";
            VerdictLevel = RiskLevel.Medium;
        }
        else if (high > 0)
        {
            Verdict = $"{high} işlem Windows'un listelerinden gizleniyor. Aşağıdaki ayrıntılara bakın.";
            VerdictLevel = RiskLevel.High;
        }
        else
        {
            Verdict = "Gizlenen işlem bulunmadı.";
            VerdictLevel = RiskLevel.None;
        }
    }

    public void UpdateProcesses(MonitorSnapshot s)
    {
        var risky = s.Processes.Where(p => p.Risk.Level >= RiskLevel.Medium).ToList();
        int signature = risky.Aggregate(17, (h, p) => HashCode.Combine(h, p.Pid, p.Risk.Score));
        if (signature == _riskySignature) return;
        _riskySignature = signature;

        RiskyProcesses = risky
            .OrderByDescending(p => p.Risk.Score)
            .Select(p => new FindingRow
            {
                Title = p.Name,
                Subtitle = $"PID {p.Pid}" + (p.Path is null ? "" : $" · {p.Path}"),
                Description = $"{RiskName(p.Risk.Level)} · {p.Signature.Display}",
                Level = p.Risk.Level,
                Reasons = p.Risk.Reasons,
                Path = p.Path,
                Pid = p.Pid,
                Icon = Ui.IconCache.Get(p.Path),
            }).ToList();
    }

    private static string RiskName(RiskLevel l) => Ui.RiskColors.Text(l);

    private static string MethodName(EnumerationMethod m) => m switch
    {
        EnumerationMethod.NtQuerySystemInformation => "çekirdek işlem listesi",
        EnumerationMethod.Toolhelp => "Toolhelp anlık görüntüsü",
        EnumerationMethod.EnumProcesses => "EnumProcesses",
        EnumerationMethod.PidBruteForce => "doğrudan PID taraması",
        _ => "ağ tabloları",
    };
}
