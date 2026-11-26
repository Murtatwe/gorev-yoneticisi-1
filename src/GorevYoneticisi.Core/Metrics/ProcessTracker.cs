namespace GorevYoneticisi.Core.Metrics;

/// <summary>One process as read from NtQuerySystemInformation. Times are in 100 ns units.</summary>
public sealed record RawProcessSample(
    int Pid,
    int ParentPid,
    string Name,
    long CreateTime,
    long CpuTime,
    long WorkingSet,
    long PrivateBytes,
    int ThreadCount,
    int HandleCount,
    ulong ReadBytes,
    ulong WriteBytes,
    ulong OtherBytes);

public sealed record ProcessMetrics(RawProcessSample Sample, double CpuPercent, double DiskBytesPerSecond);

/// <summary>
/// Turns successive raw snapshots into rates (CPU %, disk bytes/s).
/// A process is identified by PID + creation time, so a reused PID never inherits old counters.
/// </summary>
public sealed class ProcessTracker
{
    private readonly int _logicalProcessors;
    private Dictionary<int, RawProcessSample> _previous = new();
    private long _previousTimestamp;
    private bool _hasPrevious;

    public ProcessTracker(int logicalProcessors)
    {
        _logicalProcessors = Math.Max(1, logicalProcessors);
    }

    public int TrackedCount => _previous.Count;

    public IReadOnlyList<ProcessMetrics> Update(IEnumerable<RawProcessSample> samples, long timestampTicks)
    {
        long elapsed = _hasPrevious ? timestampTicks - _previousTimestamp : 0;
        var next = new Dictionary<int, RawProcessSample>();
        var result = new List<ProcessMetrics>();

        foreach (var s in samples)
        {
            next[s.Pid] = s;
            double cpu = 0, disk = 0;
            if (elapsed > 0 && _previous.TryGetValue(s.Pid, out var prev) && prev.CreateTime == s.CreateTime)
            {
                cpu = CpuMath.ProcessPercent(prev.CpuTime, s.CpuTime, elapsed, _logicalProcessors);
                ulong prevIo = prev.ReadBytes + prev.WriteBytes;
                ulong curIo = s.ReadBytes + s.WriteBytes;
                if (curIo > prevIo)
                    disk = (curIo - prevIo) / (elapsed / 10_000_000.0);
            }
            result.Add(new ProcessMetrics(s, cpu, disk));
        }

        _previous = next;
        _previousTimestamp = timestampTicks;
        _hasPrevious = true;
        return result;
    }
}
