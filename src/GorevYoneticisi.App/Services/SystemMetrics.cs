using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using GorevYoneticisi.App.Native;
using GorevYoneticisi.Core.Metrics;

namespace GorevYoneticisi.App.Services;

public sealed record SystemTotals(
    double CpuPercent,
    double[] CorePercents,
    ulong MemoryTotal,
    ulong MemoryAvailable,
    ulong CommitUsed,
    ulong CommitLimit,
    ulong CachedBytes,
    double GpuPercent,
    IReadOnlyDictionary<string, double> GpuEngines,
    long GpuDedicatedUsed,
    long GpuSharedUsed,
    bool GpuAvailable,
    double DiskActivePercent,
    double DiskReadBps,
    double DiskWriteBps,
    double NetDownBps,
    double NetUpBps,
    int ProcessCount,
    int ThreadCount,
    int HandleCount,
    TimeSpan Uptime);

/// <summary>Collects system-wide counters and per-process GPU usage. Not thread-safe; call from one thread.</summary>
internal sealed class SystemMetrics : IDisposable
{
    private SystemTimes? _prevSystem;
    private long[]? _prevCoreBusy, _prevCoreTotal;

    private readonly PdhQuery _perf = new();
    private readonly bool _hasUtility;
    private PdhQuery? _gpuQuery;
    private DateTime _gpuQueryCreated;
    // PDH wildcards normally pick up new instances on every collection; the query is still rebuilt
    // now and then as a safety net. The tick right after a rebuild keeps the previous values.
    private static readonly TimeSpan GpuQueryLifetime = TimeSpan.FromMinutes(2);

    private List<NetworkInterface> _nics = new();
    private DateTime _nicsRead = DateTime.MinValue;
    private long _prevNetRx, _prevNetTx;
    private long _prevNetTimestamp;

    private GpuEngineAggregate _lastGpu = new(new Dictionary<int, double>(), new Dictionary<string, double>(), 0);
    private Dictionary<int, long> _lastGpuMemory = new();
    private long _lastGpuDedicated, _lastGpuShared;
    private bool _gpuAvailable;

    public SystemMetrics()
    {
        _perf.TryAdd("diskidle", @"\PhysicalDisk(*)\% Idle Time");
        _perf.TryAdd("read", @"\PhysicalDisk(_Total)\Disk Read Bytes/sec");
        _perf.TryAdd("write", @"\PhysicalDisk(_Total)\Disk Write Bytes/sec");
        // Windows 11 Task Manager shows "Processor Utility" (frequency-aware), not plain busy time.
        _hasUtility = _perf.TryAdd("utility", @"\Processor Information(*)\% Processor Utility");
        _perf.TryAdd("standbyReserve", @"\Memory\Standby Cache Reserve Bytes");
        _perf.TryAdd("standbyNormal", @"\Memory\Standby Cache Normal Priority Bytes");
        _perf.TryAdd("standbyCore", @"\Memory\Standby Cache Core Bytes");
        _perf.TryAdd("modified", @"\Memory\Modified Page List Bytes");
        _perf.Collect();
    }

    public IReadOnlyDictionary<int, double> GpuPerProcess => _lastGpu.PerProcess;
    public IReadOnlyDictionary<int, long> GpuMemoryPerProcess => _lastGpuMemory;

    /// <summary>
    /// Ratio between frequency-aware utility and plain busy time. Per-process CPU is multiplied by it so the
    /// numbers line up with the total, like Task Manager's Processes tab. 1 when not available.
    /// </summary>
    public double CpuScale { get; private set; } = 1;

    public SystemTotals Sample()
    {
        double busy = SampleCpu();
        double[] coresBusy = SampleCores();
        _perf.Collect();

        double cpu = busy;
        double[] cores = coresBusy;
        CpuScale = 1;
        if (_hasUtility && _perf.GetArray("utility") is { Count: > 0 } util)
        {
            var total = util.FirstOrDefault(u => u.Instance == "_Total");
            if (total.Instance is not null)
            {
                cpu = CpuMath.Clamp(total.Value);
                if (busy > 1) CpuScale = Math.Clamp(total.Value / busy, 0.5, 3);
            }
            // Per-core instances are named "group,index"; "_Total" and "0,_Total" are aggregates.
            var perCore = util
                .Where(u => !u.Instance.Contains("_Total", StringComparison.Ordinal))
                .Select(u => (Key: ParseCore(u.Instance), u.Value))
                .Where(u => u.Key.HasValue)
                .OrderBy(u => u.Key!.Value.Group).ThenBy(u => u.Key!.Value.Index)
                .Select(u => CpuMath.Clamp(u.Value))
                .ToArray();
            if (perCore.Length > 0) cores = perCore;
        }

        var mem = new Kernel32.MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<Kernel32.MEMORYSTATUSEX>() };
        Kernel32.GlobalMemoryStatusEx(ref mem);
        Kernel32.K32GetPerformanceInfo(out var perf, Marshal.SizeOf<Kernel32.PERFORMANCE_INFORMATION>());
        ulong page = (ulong)perf.PageSize;

        double? standby = Sum(_perf.GetValue("standbyReserve"), _perf.GetValue("standbyNormal"), _perf.GetValue("standbyCore"), _perf.GetValue("modified"));
        ulong cached = standby is { } sb ? (ulong)sb : (ulong)perf.SystemCache * page;

        // Busiest disk, as Task Manager shows disks separately; an average across disks would hide a saturated one.
        double diskActive = 0;
        if (_perf.GetArray("diskidle") is { } disks)
        {
            foreach (var d in disks.Where(d => d.Instance != "_Total"))
                diskActive = Math.Max(diskActive, CpuMath.Clamp(100 - d.Value));
        }
        double read = _perf.GetValue("read") ?? 0;
        double write = _perf.GetValue("write") ?? 0;

        var (down, up) = SampleNetwork();
        SampleGpu();

        return new SystemTotals(
            cpu, cores,
            mem.ullTotalPhys, mem.ullAvailPhys,
            (ulong)perf.CommitTotal * page, (ulong)perf.CommitLimit * page, cached,
            _lastGpu.Total, _lastGpu.PerEngineType, _lastGpuDedicated, _lastGpuShared, _gpuAvailable,
            diskActive, Math.Max(0, read), Math.Max(0, write),
            down, up,
            (int)perf.ProcessCount, (int)perf.ThreadCount, (int)perf.HandleCount,
            TimeSpan.FromMilliseconds(Environment.TickCount64));
    }

    private static double? Sum(params double?[] values) =>
        values.All(v => v is null) ? null : values.Sum(v => v ?? 0);

    private static (int Group, int Index)? ParseCore(string instance)
    {
        var parts = instance.Split(',');
        return parts.Length == 2 && int.TryParse(parts[0], out int g) && int.TryParse(parts[1], out int i) ? (g, i) : null;
    }

    private double SampleCpu()
    {
        if (!Kernel32.GetSystemTimes(out long idle, out long kernel, out long user)) return 0;
        var cur = new SystemTimes(idle, kernel, user);
        double value = _prevSystem is { } prev ? CpuMath.SystemPercent(prev, cur) : 0;
        _prevSystem = cur;
        return value;
    }

    private unsafe double[] SampleCores()
    {
        int entry = sizeof(Ntdll.SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION);
        int size = entry * 256;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (Ntdll.NtQuerySystemInformation(Ntdll.SystemProcessorPerformanceInformation, buffer, size, out int returned) != Ntdll.STATUS_SUCCESS)
                return Array.Empty<double>();
            int n = returned / entry;
            var busy = new long[n];
            var total = new long[n];
            var result = new double[n];
            var items = (Ntdll.SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION*)buffer;
            for (int i = 0; i < n; i++)
            {
                // KernelTime includes IdleTime here as well.
                total[i] = items[i].KernelTime + items[i].UserTime;
                busy[i] = total[i] - items[i].IdleTime;
                if (_prevCoreTotal is not null && _prevCoreTotal.Length == n)
                {
                    long dt = total[i] - _prevCoreTotal[i];
                    long db = busy[i] - _prevCoreBusy![i];
                    result[i] = dt > 0 ? CpuMath.Clamp(db * 100.0 / dt) : 0;
                }
            }
            _prevCoreBusy = busy;
            _prevCoreTotal = total;
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static readonly string[] VirtualAdapterWords =
    {
        "Hyper-V", "vEthernet", "WSL", "Virtual", "VMware", "VirtualBox", "Loopback", "Wintun", "TAP-", "WireGuard", "Npcap",
    };

    private (double Down, double Up) SampleNetwork()
    {
        if (DateTime.UtcNow - _nicsRead > TimeSpan.FromSeconds(30))
        {
            try
            {
                // Physical adapters only: virtual switches and VPN adapters carry the same traffic again.
                _nics = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .Where(n => n.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel))
                    .Where(n => !VirtualAdapterWords.Any(w => n.Description.Contains(w, StringComparison.OrdinalIgnoreCase) ||
                                                              n.Name.Contains(w, StringComparison.OrdinalIgnoreCase)))
                    .ToList();
            }
            catch (NetworkInformationException)
            {
                _nics = new List<NetworkInterface>();
            }
            _nicsRead = DateTime.UtcNow;
            _prevNetTimestamp = 0; // the adapter set may have changed; restart the rate
        }

        long rx = 0, tx = 0;
        foreach (var nic in _nics)
        {
            try
            {
                var stats = nic.GetIPStatistics();
                rx += stats.BytesReceived;
                tx += stats.BytesSent;
            }
            catch (NetworkInformationException) { }
        }

        long now = System.Diagnostics.Stopwatch.GetTimestamp();
        double down = 0, up = 0;
        if (_prevNetTimestamp != 0)
        {
            double seconds = (now - _prevNetTimestamp) / (double)System.Diagnostics.Stopwatch.Frequency;
            if (seconds > 0)
            {
                down = Math.Max(0, (rx - _prevNetRx) / seconds);
                up = Math.Max(0, (tx - _prevNetTx) / seconds);
            }
        }
        _prevNetRx = rx;
        _prevNetTx = tx;
        _prevNetTimestamp = now;
        return (down, up);
    }

    private void SampleGpu()
    {
        bool fresh = false;
        if (_gpuQuery is null || DateTime.UtcNow - _gpuQueryCreated > GpuQueryLifetime)
        {
            _gpuQuery?.Dispose();
            _gpuQuery = new PdhQuery();
            _gpuAvailable = _gpuQuery.TryAdd("engine", @"\GPU Engine(*)\Utilization Percentage");
            _gpuQuery.TryAdd("procmem", @"\GPU Process Memory(*)\Dedicated Usage");
            _gpuQuery.TryAdd("dedicated", @"\GPU Adapter Memory(*)\Dedicated Usage");
            _gpuQuery.TryAdd("shared", @"\GPU Adapter Memory(*)\Shared Usage");
            _gpuQueryCreated = DateTime.UtcNow;
            fresh = true;
        }

        if (!_gpuQuery.Collect() || fresh) return;

        // Instances come and go constantly; a failed read keeps the previous values instead of flashing 0.
        if (_gpuQuery.GetArray("engine") is { } engines) _lastGpu = GpuAggregator.AggregateEngines(engines);
        if (_gpuQuery.GetArray("procmem") is { } procmem) _lastGpuMemory = GpuAggregator.AggregateMemory(procmem);
        if (_gpuQuery.GetArray("dedicated") is { } dedicated) _lastGpuDedicated = (long)dedicated.Sum(x => x.Value);
        if (_gpuQuery.GetArray("shared") is { } shared) _lastGpuShared = (long)shared.Sum(x => x.Value);
    }

    public void Dispose()
    {
        _perf.Dispose();
        _gpuQuery?.Dispose();
    }
}
