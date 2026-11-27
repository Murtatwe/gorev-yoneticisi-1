using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GorevYoneticisi.App.Services;
using GorevYoneticisi.Core.Security;

namespace GorevYoneticisi.App.ViewModels;

public sealed class FindingRow : ObservableObject
{
    private System.Windows.Media.ImageSource? _icon;

    public required string Title { get; init; }
    public required string Subtitle { get; init; }
    public required string Description { get; init; }
    public required RiskLevel Level { get; init; }
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    public string? Path { get; init; }
    public int Pid { get; init; }
    public bool HasPath => Path is not null;
    public System.Windows.Media.ImageSource? Icon { get => _icon; set => SetProperty(ref _icon, value); }

    public static FindingRow WithIcon(FindingRow row)
    {
        row.Icon = Ui.IconCache.GetOrQueue(row.Path, img => row.Icon = img);
        return row;
    }
}

public sealed class SecurityViewModel : ObservableObject
{
    private readonly MonitorService _monitor;
    private readonly MainViewModel _main;
    private bool _isScanning;
    private string _lastScan = "Henüz tarama yapılmadı.";
    private string _verdict = "İlk tarama birkaç saniye içinde yapılacak.";
    private string _verdictDetail = "";
    private RiskLevel _verdictLevel = RiskLevel.None;
    private string _methodNote = "";
    private string _message = "";
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
            _main.Processes.Reveal(row.Pid);
            _main.ShowPage(_main.Processes);
        });
        VirusTotalCommand = new AsyncRelayCommand<FindingRow>(async row =>
        {
            if (row?.Path is null) return;
            Message = $"{row.Title}: parmak izi hesaplanıyor…";
            string? hash = await ProcessesViewModel.HashFileAsync(row.Path);
            if (hash is null)
            {
                Message = $"{row.Title}: dosya okunamadı.";
                return;
            }
            Message = $"{row.Title}: VirusTotal tarayıcıda açıldı (dosyanın kendisi gönderilmez).";
            ProcessesViewModel.OpenUrl($"https://www.virustotal.com/gui/file/{hash}");
        }, row => row?.Path is not null);
        OpenWindowsSecurityCommand = new RelayCommand(() => ProcessesViewModel.OpenUrl("windowsdefender://threat"));
        RestartAsAdminCommand = new RelayCommand(App.RestartAsAdmin);
    }

    public AsyncRelayCommand ScanCommand { get; }
    public RelayCommand<FindingRow> ShowInProcessesCommand { get; }
    public AsyncRelayCommand<FindingRow> VirusTotalCommand { get; }
    public RelayCommand OpenWindowsSecurityCommand { get; }
    public RelayCommand RestartAsAdminCommand { get; }

    public bool IsElevated => _monitor.DebugPrivilege;

    public bool IsScanning
    {
        get => _isScanning;
        private set { if (SetProperty(ref _isScanning, value)) ScanCommand.NotifyCanExecuteChanged(); }
    }

    public string LastScan { get => _lastScan; private set => SetProperty(ref _lastScan, value); }
    public string Verdict { get => _verdict; private set => SetProperty(ref _verdict, value); }
    public string VerdictDetail { get => _verdictDetail; private set => SetProperty(ref _verdictDetail, value); }
    public RiskLevel VerdictLevel { get => _verdictLevel; private set => SetProperty(ref _verdictLevel, value); }
    public string MethodNote { get => _methodNote; private set => SetProperty(ref _methodNote, value); }
    public string Message { get => _message; private set => SetProperty(ref _message, value); }

    public IReadOnlyList<FindingRow> HiddenFindings
    {
        get => _hidden;
        private set { SetProperty(ref _hidden, value); OnPropertyChanged(nameof(HasHidden)); OnPropertyChanged(nameof(ShowAdvice)); }
    }

    public IReadOnlyList<FindingRow> RiskyProcesses
    {
        get => _risky;
        private set { SetProperty(ref _risky, value); OnPropertyChanged(nameof(HasRisky)); OnPropertyChanged(nameof(ShowAdvice)); }
    }

    public bool HasHidden => _hidden.Count > 0;
    public bool HasRisky => _risky.Count > 0;
    public bool ShowAdvice => HasHidden || HasRisky;

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

    public void ReportFailure(string message)
    {
        Verdict = "Tarama sırasında bir hata oluştu.";
        VerdictDetail = $"Ayrıntılar hata kaydına yazıldı ({App.LogPath}). Hata: {message}";
        VerdictLevel = RiskLevel.Medium;
    }

    public void UpdateReport(SecurityReport r)
    {
        LastScan = $"Son tarama: {r.Time:HH:mm:ss} · {r.PrimaryCount} program karşılaştırıldı";

        int failed = r.Result.FailedMethods.Count;
        MethodNote = failed == 0 ? "" : $"Kontrol yöntemlerinden {failed} tanesi çalışmadı; bu taramanın sonucu daha az kesin.";

        HiddenFindings = r.Items.Select(i => FindingRow.WithIcon(new FindingRow
        {
            Title = i.Name,
            Subtitle = i.Path is null ? $"PID {i.Finding.Pid}" : $"PID {i.Finding.Pid} · {i.Path}",
            Description = i.Finding.Description,
            Level = i.Finding.Severity,
            Path = i.Path,
            Pid = i.Finding.Pid,
        })).OrderByDescending(f => f.Level).ToList();

        int high = r.Items.Count(i => i.Finding.Severity == RiskLevel.High);
        if (!r.Result.PrimaryAvailable)
        {
            Verdict = "Tarama tamamlanamadı: Windows'un program listesi okunamadı.";
            VerdictDetail = "Uygulamayı yönetici olarak yeniden açıp tekrar deneyin.";
            VerdictLevel = RiskLevel.Medium;
        }
        else if (high > 0)
        {
            Verdict = $"{high} program Windows'tan gizleniyor.";
            VerdictDetail = "Bu ciddi bir işaret olabilir. Aşağıdaki \"Ne yapmalıyım?\" adımlarını izleyin.";
            VerdictLevel = RiskLevel.High;
        }
        else
        {
            Verdict = "Gizlenen program bulunmadı.";
            VerdictDetail = "Bu, bilgisayarda hiç zararlı olmadığı anlamına gelmez; ara sıra Microsoft Defender ile tam tarama yapın.";
            VerdictLevel = RiskLevel.None;
        }
    }

    public void UpdateProcesses(MonitorSnapshot s)
    {
        var risky = s.Processes.Where(p => p.Risk.Level >= RiskLevel.Medium).ToList();
        int signature = risky.Aggregate(17, (h, p) => HashCode.Combine(h, p.Pid, p.Risk.Score, p.Signature.Display, p.Risk.Reasons.Count));
        if (signature == _riskySignature) return;
        _riskySignature = signature;

        RiskyProcesses = risky
            .OrderByDescending(p => p.Risk.Score)
            .Select(p => FindingRow.WithIcon(new FindingRow
            {
                Title = p.Name,
                Subtitle = $"PID {p.Pid}" + (p.Path is null ? "" : $" · {p.Path}"),
                Description = p.Path is null ? "" : $"Yayımcı: {p.Signature.Display}",
                Level = p.Risk.Level,
                Reasons = p.Risk.Reasons,
                Path = p.Path,
                Pid = p.Pid,
            })).ToList();
    }
}
