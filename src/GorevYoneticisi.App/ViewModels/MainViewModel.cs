using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using GorevYoneticisi.App.Services;
using GorevYoneticisi.Core;
using GorevYoneticisi.Core.Security;
using Wpf.Ui.Controls;

namespace GorevYoneticisi.App.ViewModels;

public sealed record NavEntry(string Title, SymbolRegular Icon, object Page);

public sealed class MainViewModel : ObservableObject
{
    private readonly MonitorService _monitor;
    private readonly Dispatcher _dispatcher;
    private int _snapshotPending;
    private NavEntry _selected;
    private string _status = "Veriler toplanıyor…";
    private string _securityStatus = "Güvenlik taraması bekleniyor";
    private RiskLevel _securityLevel = RiskLevel.None;

    public MainViewModel(MonitorService monitor, AppSettings settings)
    {
        _monitor = monitor;
        _dispatcher = Application.Current.Dispatcher;

        Overview = new OverviewViewModel(monitor.Hardware);
        Processes = new ProcessesViewModel(monitor);
        Security = new SecurityViewModel(monitor, this);
        Network = new NetworkViewModel();
        Startup = new StartupViewModel(monitor, settings);
        Settings = new SettingsViewModel(monitor, settings);

        Pages = new[]
        {
            new NavEntry("Genel Bakış", SymbolRegular.Board24, Overview),
            new NavEntry("İşlemler", SymbolRegular.AppsList24, Processes),
            new NavEntry("Güvenlik", SymbolRegular.Shield24, Security),
            new NavEntry("Ağ", SymbolRegular.Globe24, Network),
            new NavEntry("Başlangıç", SymbolRegular.Rocket24, Startup),
            new NavEntry("Ayarlar", SymbolRegular.Settings24, Settings),
        };
        _selected = Pages[0];

        monitor.SnapshotReady += OnSnapshot;
        monitor.SecurityReportReady += r => _dispatcher.BeginInvoke(() => OnSecurityReport(r));
        monitor.SignaturesUpdated += () => _dispatcher.BeginInvoke(DispatcherPriority.Background, () => Startup.RefreshSignatures());
    }

    public OverviewViewModel Overview { get; }
    public ProcessesViewModel Processes { get; }
    public SecurityViewModel Security { get; }
    public NetworkViewModel Network { get; }
    public StartupViewModel Startup { get; }
    public SettingsViewModel Settings { get; }
    public IReadOnlyList<NavEntry> Pages { get; }

    public bool IsElevated => _monitor.DebugPrivilege;

    public NavEntry SelectedPage
    {
        get => _selected;
        set
        {
            if (value is null || !SetProperty(ref _selected, value)) return;
            OnPropertyChanged(nameof(CurrentPage));
            Network.IsActive = value.Page == Network;
            _monitor.FastSecurityScans = value.Page == Security;
            if (value.Page == Startup) Startup.EnsureLoaded();
        }
    }

    public object CurrentPage => _selected.Page;

    public string Status { get => _status; private set => SetProperty(ref _status, value); }
    public string SecurityStatus { get => _securityStatus; private set => SetProperty(ref _securityStatus, value); }
    public RiskLevel SecurityLevel { get => _securityLevel; private set => SetProperty(ref _securityLevel, value); }

    public void ShowPage(object page)
    {
        var entry = Pages.FirstOrDefault(p => p.Page == page);
        if (entry is not null) SelectedPage = entry;
    }

    private void OnSnapshot(MonitorSnapshot snapshot)
    {
        // Drop frames instead of queueing them when the UI is busy.
        if (Interlocked.Exchange(ref _snapshotPending, 1) == 1) return;
        _dispatcher.BeginInvoke(DispatcherPriority.Background, () =>
        {
            try
            {
                Apply(snapshot);
            }
            catch (Exception ex)
            {
                App.Log(ex, "Görüntü güncellenemedi");
            }
            finally
            {
                Interlocked.Exchange(ref _snapshotPending, 0);
            }
        });
    }

    private void Apply(MonitorSnapshot s)
    {
        Overview.Update(s);
        Processes.Update(s);
        Security.UpdateProcesses(s);
        Network.UpdateProcessNames(s);

        var t = s.Totals;
        double memUsed = t.MemoryTotal == 0 ? 0 : (t.MemoryTotal - t.MemoryAvailable) * 100.0 / t.MemoryTotal;
        Status = $"CPU {Format.Percent(t.CpuPercent)}  ·  Bellek {Format.Percent(memUsed)}  ·  GPU {Format.Percent(t.GpuPercent)}  ·  {s.Processes.Count} işlem";
    }

    private void OnSecurityReport(SecurityReport r)
    {
        Security.UpdateReport(r);
        int high = r.Items.Count(i => i.Finding.Severity == RiskLevel.High);
        if (!r.Result.PrimaryAvailable)
        {
            SecurityLevel = RiskLevel.Medium;
            SecurityStatus = "Güvenlik taraması tamamlanamadı";
        }
        else if (high > 0)
        {
            SecurityLevel = RiskLevel.High;
            SecurityStatus = $"{high} gizli işlem bulundu!";
        }
        else
        {
            SecurityLevel = RiskLevel.None;
            SecurityStatus = $"Gizli işlem yok (son tarama {r.Time:HH:mm:ss})";
        }
    }
}
