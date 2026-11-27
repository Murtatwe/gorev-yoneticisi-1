using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using GorevYoneticisi.App.Services;
using GorevYoneticisi.Core;
using GorevYoneticisi.Core.Metrics;

namespace GorevYoneticisi.App.ViewModels;

public sealed class CoreUsage : ObservableObject
{
    private double _percent;
    public CoreUsage(int index) => Label = $"Çekirdek {index}";
    public string Label { get; }
    public double Percent { get => _percent; set => SetProperty(ref _percent, value); }
}

public sealed class TopProcess
{
    public required string Name { get; init; }
    public required string Value { get; init; }
    public required double Percent { get; init; }
    public System.Windows.Media.ImageSource? Icon { get; init; }
}

public sealed class OverviewViewModel : ObservableObject
{
    private const int HistoryLength = 60;
    private readonly History _cpu = new(HistoryLength), _mem = new(HistoryLength), _gpu = new(HistoryLength),
        _disk = new(HistoryLength), _down = new(HistoryLength), _up = new(HistoryLength);

    private double[] _cpuHistory = Array.Empty<double>(), _memHistory = Array.Empty<double>(), _gpuHistory = Array.Empty<double>(),
        _diskHistory = Array.Empty<double>(), _downHistory = Array.Empty<double>(), _upHistory = Array.Empty<double>();
    private string _cpuText = "%0", _memText = "", _memDetail = "", _gpuText = "%0", _gpuDetail = "", _diskText = "%0", _diskDetail = "",
        _netDown = "0 B/sn", _netUp = "0 B/sn", _uptime = "", _counts = "", _gpuEngines = "";
    private IReadOnlyList<TopProcess> _topCpu = Array.Empty<TopProcess>(), _topMemory = Array.Empty<TopProcess>(), _topGpu = Array.Empty<TopProcess>();

    public OverviewViewModel(HardwareInfo hw)
    {
        Hardware = hw;
        var gpu = hw.Gpus.FirstOrDefault();
        GpuName = gpu?.Name ?? "Ekran kartı bulunamadı";
        GpuMemoryTotal = gpu?.DedicatedMemoryBytes ?? 0;
    }

    public HardwareInfo Hardware { get; }
    public string CpuName => Hardware.CpuName;
    public string CpuSubtitle => $"{Hardware.LogicalProcessors} mantıksal işlemci" + (Hardware.CpuBaseSpeed.Length > 0 ? $" · temel hız {Hardware.CpuBaseSpeed}" : "");
    public string GpuName { get; }
    public long GpuMemoryTotal { get; }
    public string MemoryTotalText => Format.Bytes((long)Hardware.TotalMemoryBytes);
    public string OsName => Hardware.OsName;

    public ObservableCollection<CoreUsage> Cores { get; } = new();

    public double[] CpuHistory { get => _cpuHistory; private set => SetProperty(ref _cpuHistory, value); }
    public double[] MemoryHistory { get => _memHistory; private set => SetProperty(ref _memHistory, value); }
    public double[] GpuHistory { get => _gpuHistory; private set => SetProperty(ref _gpuHistory, value); }
    public double[] DiskHistory { get => _diskHistory; private set => SetProperty(ref _diskHistory, value); }
    public double[] DownHistory { get => _downHistory; private set => SetProperty(ref _downHistory, value); }
    public double[] UpHistory { get => _upHistory; private set => SetProperty(ref _upHistory, value); }

    public string CpuText { get => _cpuText; private set => SetProperty(ref _cpuText, value); }
    public string MemoryText { get => _memText; private set => SetProperty(ref _memText, value); }
    public string MemoryDetail { get => _memDetail; private set => SetProperty(ref _memDetail, value); }
    public string GpuText { get => _gpuText; private set => SetProperty(ref _gpuText, value); }
    public string GpuDetail { get => _gpuDetail; private set => SetProperty(ref _gpuDetail, value); }
    public string GpuEngines { get => _gpuEngines; private set => SetProperty(ref _gpuEngines, value); }
    public string DiskText { get => _diskText; private set => SetProperty(ref _diskText, value); }
    public string DiskDetail { get => _diskDetail; private set => SetProperty(ref _diskDetail, value); }
    public string NetDown { get => _netDown; private set => SetProperty(ref _netDown, value); }
    public string NetUp { get => _netUp; private set => SetProperty(ref _netUp, value); }
    public string Uptime { get => _uptime; private set => SetProperty(ref _uptime, value); }
    public string Counts { get => _counts; private set => SetProperty(ref _counts, value); }

    public IReadOnlyList<TopProcess> TopCpu { get => _topCpu; private set => SetProperty(ref _topCpu, value); }
    public IReadOnlyList<TopProcess> TopMemory { get => _topMemory; private set => SetProperty(ref _topMemory, value); }
    public IReadOnlyList<TopProcess> TopGpu { get => _topGpu; private set => SetProperty(ref _topGpu, value); }

    public void Update(MonitorSnapshot s)
    {
        var t = s.Totals;

        _cpu.Add(t.CpuPercent);
        CpuHistory = _cpu.ToArray();
        CpuText = Format.Percent(t.CpuPercent);

        while (Cores.Count < t.CorePercents.Length) Cores.Add(new CoreUsage(Cores.Count));
        for (int i = 0; i < t.CorePercents.Length && i < Cores.Count; i++) Cores[i].Percent = t.CorePercents[i];

        ulong used = t.MemoryTotal - t.MemoryAvailable;
        double memPct = t.MemoryTotal == 0 ? 0 : used * 100.0 / t.MemoryTotal;
        _mem.Add(memPct);
        MemoryHistory = _mem.ToArray();
        MemoryText = $"{Format.Bytes((long)used)} / {Format.Bytes((long)t.MemoryTotal)}";
        MemoryDetail = $"{Format.Percent(memPct)} kullanımda · Kullanılabilir {Format.Bytes((long)t.MemoryAvailable)} · " +
                       $"Önbellek {Format.Bytes((long)t.CachedBytes)} · Ayrılan (sanal) bellek {Format.Bytes((long)t.CommitUsed)} / {Format.Bytes((long)t.CommitLimit)}";

        _gpu.Add(t.GpuPercent);
        GpuHistory = _gpu.ToArray();
        GpuText = t.GpuAvailable ? Format.Percent(t.GpuPercent) : "—";
        GpuDetail = !t.GpuAvailable
            ? "GPU sayaçları bu sistemde okunamadı."
            : GpuMemoryTotal > 0
                ? $"Ayrılmış bellek {Format.Bytes(t.GpuDedicatedUsed)} / {Format.Bytes(GpuMemoryTotal)} · Paylaşılan {Format.Bytes(t.GpuSharedUsed)}"
                : $"Ayrılmış bellek {Format.Bytes(t.GpuDedicatedUsed)} · Paylaşılan {Format.Bytes(t.GpuSharedUsed)}";
        GpuEngines = string.Join("   ", t.GpuEngines.Where(e => e.Value >= 0.5).OrderByDescending(e => e.Value).Take(4)
            .Select(e => $"{EngineName(e.Key)} {Format.Percent(e.Value)}"));

        _disk.Add(t.DiskActivePercent);
        DiskHistory = _disk.ToArray();
        DiskText = Format.Percent(t.DiskActivePercent);
        DiskDetail = $"Okuma {Format.Rate(t.DiskReadBps)} · Yazma {Format.Rate(t.DiskWriteBps)}";

        _down.Add(t.NetDownBps);
        _up.Add(t.NetUpBps);
        DownHistory = _down.ToArray();
        UpHistory = _up.ToArray();
        NetDown = Format.Rate(t.NetDownBps);
        NetUp = Format.Rate(t.NetUpBps);

        Uptime = Format.Duration(t.Uptime);
        Counts = $"{N(t.ProcessCount)} program çalışıyor";

        var procs = s.Processes.Where(p => p.Pid > 4).ToList();
        TopCpu = procs.OrderByDescending(p => p.CpuPercent).Take(5)
            .Select(p => new TopProcess { Name = p.Name, Value = Format.Percent(p.CpuPercent), Percent = p.CpuPercent, Icon = Ui.IconCache.Get(p.Path) }).ToList();
        long totalMem = Math.Max(1, (long)t.MemoryTotal);
        TopMemory = procs.OrderByDescending(p => p.PrivateWorkingSet).Take(5)
            .Select(p => new TopProcess { Name = p.Name, Value = Format.Bytes(p.PrivateWorkingSet), Percent = p.PrivateWorkingSet * 100.0 / totalMem, Icon = Ui.IconCache.Get(p.Path) }).ToList();
        TopGpu = procs.Where(p => p.GpuPercent > 0).OrderByDescending(p => p.GpuPercent).Take(5)
            .Select(p => new TopProcess { Name = p.Name, Value = Format.Percent(p.GpuPercent), Percent = p.GpuPercent, Icon = Ui.IconCache.Get(p.Path) }).ToList();
    }

    /// <summary>Thousands separator in Turkish style (12.345).</summary>
    private static string N(int value) => value.ToString("N0", System.Globalization.CultureInfo.InvariantCulture).Replace(',', '.');

    private static string EngineName(string type) => type switch
    {
        "3D" => "3B",
        "Copy" => "Kopyalama",
        "VideoDecode" or "Video Decode" => "Video çözme",
        "VideoEncode" or "Video Encode" => "Video kodlama",
        "VideoProcessing" or "Video Processing" => "Video işleme",
        "Compute" => "Hesaplama",
        _ => type,
    };
}
