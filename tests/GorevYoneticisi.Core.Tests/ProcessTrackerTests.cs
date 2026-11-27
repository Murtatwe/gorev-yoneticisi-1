using GorevYoneticisi.Core.Metrics;

namespace GorevYoneticisi.Core.Tests;

public class ProcessTrackerTests
{
    private static RawProcessSample Sample(int pid, long create, long cpu, ulong read = 0, ulong write = 0, string name = "app.exe") =>
        new(pid, ParentPid: 1, Name: name, CreateTime: create, CpuTime: cpu,
            WorkingSet: 100, PrivateWorkingSet: 50, ThreadCount: 3, HandleCount: 10,
            ReadBytes: read, WriteBytes: write, OtherBytes: 0);

    [Fact]
    public void FirstSample_HasZeroRates()
    {
        var tracker = new ProcessTracker(logicalProcessors: 4);
        var result = tracker.Update(new[] { Sample(10, 1, 5_000_000) }, timestampTicks: 0);
        var p = Assert.Single(result);
        Assert.Equal(0, p.CpuPercent);
        Assert.Equal(0, p.DiskBytesPerSecond);
    }

    [Fact]
    public void SecondSample_ComputesCpuAndDiskRates()
    {
        var tracker = new ProcessTracker(logicalProcessors: 4);
        tracker.Update(new[] { Sample(10, 1, 0, read: 0, write: 0) }, timestampTicks: 0);
        var result = tracker.Update(new[] { Sample(10, 1, 10_000_000, read: 1000, write: 3000) }, timestampTicks: 10_000_000);
        var p = Assert.Single(result);
        Assert.Equal(25.0, p.CpuPercent, 6);          // 1 s CPU / 1 s wall / 4 cores
        Assert.Equal(4000.0, p.DiskBytesPerSecond, 6); // 4000 bytes in 1 s
    }

    [Fact]
    public void ReusedPid_WithDifferentCreateTime_IsTreatedAsNewProcess()
    {
        var tracker = new ProcessTracker(logicalProcessors: 1);
        tracker.Update(new[] { Sample(10, create: 1, cpu: 0) }, timestampTicks: 0);
        var result = tracker.Update(new[] { Sample(10, create: 2, cpu: 9_000_000) }, timestampTicks: 10_000_000);
        Assert.Equal(0, Assert.Single(result).CpuPercent);
    }

    [Fact]
    public void ExitedProcesses_AreForgotten()
    {
        var tracker = new ProcessTracker(logicalProcessors: 1);
        tracker.Update(new[] { Sample(10, 1, 0), Sample(11, 1, 0) }, 0);
        tracker.Update(new[] { Sample(11, 1, 0) }, 10_000_000);
        Assert.Equal(1, tracker.TrackedCount);
    }

    [Fact]
    public void CounterGoingBackwards_DoesNotProduceNegativeRates()
    {
        var tracker = new ProcessTracker(logicalProcessors: 1);
        tracker.Update(new[] { Sample(10, 1, 100, read: 5000) }, 0);
        var p = Assert.Single(tracker.Update(new[] { Sample(10, 1, 50, read: 10) }, 10_000_000));
        Assert.Equal(0, p.CpuPercent);
        Assert.Equal(0, p.DiskBytesPerSecond);
    }
}
