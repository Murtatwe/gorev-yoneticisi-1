using GorevYoneticisi.Core.Metrics;

namespace GorevYoneticisi.Core.Tests;

public class CpuMathTests
{
    [Fact]
    public void SystemCpu_ComputesBusyShareOfTotal()
    {
        // GetSystemTimes: kernel time INCLUDES idle time.
        var prev = new SystemTimes(Idle: 1000, Kernel: 2000, User: 1000);
        var cur = new SystemTimes(Idle: 1600, Kernel: 3000, User: 1400);
        // deltas: idle 600, kernel 1000, user 400 -> total 1400, busy 800
        Assert.Equal(800.0 / 1400.0 * 100.0, CpuMath.SystemPercent(prev, cur), 6);
    }

    [Fact]
    public void SystemCpu_ZeroDeltaGivesZero()
    {
        var t = new SystemTimes(1, 2, 3);
        Assert.Equal(0, CpuMath.SystemPercent(t, t));
    }

    [Fact]
    public void ProcessCpu_IsNormalizedByLogicalProcessorCount()
    {
        // 1 second of wall time (10_000_000 ticks), process used 2 seconds of CPU on 8 cores => 25%
        Assert.Equal(25.0, CpuMath.ProcessPercent(0, 20_000_000, 10_000_000, 8), 6);
    }

    [Fact]
    public void ProcessCpu_IsClampedBetween0And100()
    {
        Assert.Equal(100.0, CpuMath.ProcessPercent(0, 999_000_000, 10_000_000, 1));
        Assert.Equal(0.0, CpuMath.ProcessPercent(500, 100, 10_000_000, 4));
        Assert.Equal(0.0, CpuMath.ProcessPercent(0, 100, 0, 4));
    }
}
