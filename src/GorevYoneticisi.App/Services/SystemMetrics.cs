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

    private readonly PdhQuery _diskQuery = new();
    private PdhQuery? _gpuQuery;
    private DateTime _gpuQueryCreated;
    private static readonly TimeSpan GpuQueryLifetime = TimeSpan.FromSeconds(15);

    private long _prevNetRx, _prevNetTx;
    private long _prevNetTimestamp;

    private GpuEngineAggregate _lastGpu = new(new Dictionary<int, double>(), new Dictionary<string, double>(), 0);
    private Dictionary<int, long> _lastGpuMemory = new();
    private long _lastGpuDedicated, _lastGpuShared;
    private bool _gpuAvailable;

    public SystemMetrics()
    {
        _diskQuery.TryAdd("idle", @"\PhysicalDisk(_Total)\% Idle Time");
        _diskQuery.TryAdd("read", @"\PhysicalDisk(_Total)\Disk Read Bytes/sec");
        _diskQuery.TryAdd("write", @"\PhysicalDisk(_Total)\Disk Write Bytes/sec");
        _diskQuery.Collect();
    }

    public IReadOnlyDictionary<int, double> GpuPerProcess => _lastGpu.PerProcess;
    public IReadOnlyDictionary<int, long> GpuMemoryPerProcess => _lastGpuMemory;

    public SystemTotals Sample()
    {
        double cpu = SampleCpu();
        double[] cores = SampleCores();

        var mem = new Kernel32.MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<Kernel32.MEMORYSTATUSEX>() };
        Kernel32.GlobalMemoryStatusEx(ref mem);
        Kernel32.K32GetPerformanceInfo(out var perf, Marshal.SizeOf<Kernel32.PERFORMANCE_INFORMATION>());
        ulong page = (ulong)perf.PageSize;

        _diskQuery.Collect();
        double idle = _diskQuery.GetValue("idle") ?? 100;
        double read = _diskQuery.GetValue("read") ?? 0;
        double write = _diskQuery.GetValue("write") ?? 0;

        var (down, up) = SampleNetwork();
        SampleGpu();

        return new SystemTotals(
            cpu, cores,
            mem.ullTotalPhys, mem.ullAvailPhys,
            (ulong)perf.CommitTotal * page, (ulong)perf.CommitLimit * page, (ulong)perf.SystemCache * page,
            _lastGpu.Total, _lastGpu.PerEngineType, _lastGpuDedicated, _lastGpuShared, _gpuAvailable,
            CpuMath.Clamp(100 - idle), Math.Max(0, read), Math.Max(0, write),
            down, up,
            (int)perf.ProcessCount, (int)perf.ThreadCount, (int)perf.HandleCount,
            TimeSpan.FromMilliseconds(Environment.TickCount64));
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

    private (double Down, double Up) SampleNetwork()
    {
        long rx = 0, tx = 0;
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                var stats = nic.GetIPStatistics();
                rx += stats.BytesReceived;
                tx += stats.BytesSent;
            }
        }
        catch (NetworkInformationException) { }

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
        // Wildcard instance lists do not pick up processes started later, so the query is rebuilt periodically.
        // The tick right after a rebuild has no rate data yet; the previous values are kept for that tick.
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

        _lastGpu = GpuAggregator.AggregateEngines(_gpuQuery.GetArray("engine"));
        _lastGpuMemory = GpuAggregator.AggregateMemory(_gpuQuery.GetArray("procmem"));
        _lastGpuDedicated = (long)_gpuQuery.GetArray("dedicated").Sum(x => x.Value);
        _lastGpuShared = (long)_gpuQuery.GetArray("shared").Sum(x => x.Value);
    }

    public void Dispose()
    {
        _diskQuery.Dispose();
        _gpuQuery?.Dispose();
    }
}
