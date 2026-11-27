using System.Globalization;
using System.Text.RegularExpressions;

namespace GorevYoneticisi.Core.Metrics;

public readonly record struct GpuEngineInstance(int Pid, string Luid, int Phys, int EngineIndex, string EngineType);

/// <summary>Parses instance names of the "GPU Engine" and "GPU Process Memory" performance counters.</summary>
public static partial class GpuInstanceName
{
    [GeneratedRegex(@"^pid_(\d+)_luid_(0x[0-9A-Fa-f]+_0x[0-9A-Fa-f]+)_phys_(\d+)_eng_(\d+)_engtype_(.+)$")]
    private static partial Regex EngineRegex();

    [GeneratedRegex(@"^pid_(\d+)_luid_(0x[0-9A-Fa-f]+_0x[0-9A-Fa-f]+)_phys_(\d+)$")]
    private static partial Regex MemoryRegex();

    [GeneratedRegex(@"#\d+$")]
    private static partial Regex DuplicateSuffix();

    /// <summary>PDH appends "#1", "#2"... to duplicate instance names.</summary>
    private static string Clean(string name) => DuplicateSuffix().Replace(name, "");

    public static bool TryParseEngine(string name, out GpuEngineInstance instance)
    {
        instance = default;
        var m = EngineRegex().Match(Clean(name));
        if (!m.Success) return false;
        if (!int.TryParse(m.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out int pid)) return false;
        instance = new GpuEngineInstance(
            pid,
            m.Groups[2].Value,
            int.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture),
            int.Parse(m.Groups[4].Value, CultureInfo.InvariantCulture),
            m.Groups[5].Value);
        return true;
    }

    public static bool TryParseMemory(string name, out int pid, out string luid)
    {
        pid = 0;
        luid = "";
        var m = MemoryRegex().Match(Clean(name));
        if (!m.Success || !int.TryParse(m.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out pid))
            return false;
        luid = m.Groups[2].Value;
        return true;
    }
}

public sealed record GpuEngineAggregate(
    IReadOnlyDictionary<int, double> PerProcess,
    IReadOnlyDictionary<string, double> PerEngineType,
    double Total);

/// <summary>
/// Combines per-engine utilization the way Windows Task Manager does:
/// a process's GPU usage is its busiest engine, and overall usage is the busiest engine across all processes.
/// </summary>
public static class GpuAggregator
{
    public static GpuEngineAggregate AggregateEngines(IEnumerable<(string Instance, double Value)> samples)
    {
        var perProcessEngine = new Dictionary<(int Pid, string Engine), double>();
        var perEngine = new Dictionary<string, (string Type, double Sum)>();

        foreach (var (instance, value) in samples)
        {
            if (!GpuInstanceName.TryParseEngine(instance, out var e) || double.IsNaN(value) || value <= 0) continue;
            string engineKey = $"{e.Luid}|{e.Phys}|{e.EngineIndex}";

            perProcessEngine.TryGetValue((e.Pid, engineKey), out double p);
            perProcessEngine[(e.Pid, engineKey)] = p + value;

            perEngine.TryGetValue(engineKey, out var t);
            perEngine[engineKey] = (e.EngineType, t.Sum + value);
        }

        var perProcess = new Dictionary<int, double>();
        foreach (var ((pid, _), value) in perProcessEngine)
        {
            perProcess.TryGetValue(pid, out double cur);
            perProcess[pid] = CpuMath.Clamp(Math.Max(cur, value));
        }

        var perType = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        double total = 0;
        foreach (var (_, (type, sum)) in perEngine)
        {
            double clamped = CpuMath.Clamp(sum);
            perType.TryGetValue(type, out double cur);
            perType[type] = Math.Max(cur, clamped);
            total = Math.Max(total, clamped);
        }

        return new GpuEngineAggregate(perProcess, perType, total);
    }

    public static Dictionary<int, long> AggregateMemory(IEnumerable<(string Instance, double Value)> samples)
    {
        var result = new Dictionary<int, long>();
        foreach (var (instance, value) in samples)
        {
            if (!GpuInstanceName.TryParseMemory(instance, out int pid, out _) || double.IsNaN(value) || value <= 0) continue;
            result.TryGetValue(pid, out long cur);
            result[pid] = cur + (long)value;
        }
        return result;
    }
}
