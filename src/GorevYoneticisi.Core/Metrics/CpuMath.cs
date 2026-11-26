namespace GorevYoneticisi.Core.Metrics;

/// <summary>Values from GetSystemTimes, in 100 ns units. Kernel time includes idle time.</summary>
public readonly record struct SystemTimes(long Idle, long Kernel, long User);

public static class CpuMath
{
    public static double SystemPercent(SystemTimes previous, SystemTimes current)
    {
        long idle = current.Idle - previous.Idle;
        long total = (current.Kernel - previous.Kernel) + (current.User - previous.User);
        if (total <= 0) return 0;
        return Clamp((total - idle) * 100.0 / total);
    }

    /// <param name="previousCpuTime">Process kernel+user time (100 ns) at the previous sample.</param>
    /// <param name="currentCpuTime">Process kernel+user time (100 ns) now.</param>
    /// <param name="elapsedTicks">Wall-clock time between samples (100 ns).</param>
    public static double ProcessPercent(long previousCpuTime, long currentCpuTime, long elapsedTicks, int logicalProcessors)
    {
        if (elapsedTicks <= 0 || logicalProcessors <= 0) return 0;
        long used = currentCpuTime - previousCpuTime;
        if (used <= 0) return 0;
        return Clamp(used * 100.0 / ((double)elapsedTicks * logicalProcessors));
    }

    public static double Clamp(double percent) => percent < 0 ? 0 : percent > 100 ? 100 : percent;
}
