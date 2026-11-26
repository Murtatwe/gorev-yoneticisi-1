using GorevYoneticisi.Core.Metrics;

namespace GorevYoneticisi.Core.Tests;

public class GpuTests
{
    [Fact]
    public void ParsesEngineInstanceName()
    {
        var ok = GpuInstanceName.TryParseEngine("pid_1234_luid_0x00000000_0x0000D1B8_phys_0_eng_3_engtype_VideoDecode", out var e);
        Assert.True(ok);
        Assert.Equal(1234, e.Pid);
        Assert.Equal("0x00000000_0x0000D1B8", e.Luid);
        Assert.Equal(0, e.Phys);
        Assert.Equal(3, e.EngineIndex);
        Assert.Equal("VideoDecode", e.EngineType);
    }

    [Fact]
    public void ParsesEngineTypeWithSpaces()
    {
        Assert.True(GpuInstanceName.TryParseEngine("pid_8_luid_0x0_0x1_phys_0_eng_1_engtype_Video Encode", out var e));
        Assert.Equal("Video Encode", e.EngineType);
    }

    [Theory]
    [InlineData("_Total")]
    [InlineData("garbage")]
    [InlineData("pid_x_luid_0x0_0x1_phys_0_eng_1_engtype_3D")]
    public void RejectsInvalidEngineNames(string name)
    {
        Assert.False(GpuInstanceName.TryParseEngine(name, out _));
    }

    [Fact]
    public void ParsesProcessMemoryInstanceName()
    {
        Assert.True(GpuInstanceName.TryParseMemory("pid_42_luid_0x00000000_0x0000D1B8_phys_0", out var pid, out var luid));
        Assert.Equal(42, pid);
        Assert.Equal("0x00000000_0x0000D1B8", luid);
    }

    [Fact]
    public void Aggregate_ProcessUsageIsBusiestEngine_TotalIsBusiestEngineAcrossProcesses()
    {
        var samples = new[]
        {
            ("pid_1_luid_0x0_0xA_phys_0_eng_0_engtype_3D", 30.0),
            ("pid_1_luid_0x0_0xA_phys_0_eng_3_engtype_VideoDecode", 10.0),
            ("pid_2_luid_0x0_0xA_phys_0_eng_0_engtype_3D", 25.0),
            ("pid_2_luid_0x0_0xA_phys_0_eng_3_engtype_VideoDecode", 50.0),
            ("_Total", 99.0),
        };

        var agg = GpuAggregator.AggregateEngines(samples);

        Assert.Equal(30.0, agg.PerProcess[1], 6);
        Assert.Equal(50.0, agg.PerProcess[2], 6);
        // 3D engine: 30+25=55, VideoDecode: 10+50=60 -> 60
        Assert.Equal(60.0, agg.Total, 6);
        Assert.Equal(55.0, agg.PerEngineType["3D"], 6);
        Assert.Equal(60.0, agg.PerEngineType["VideoDecode"], 6);
    }

    [Fact]
    public void Aggregate_TotalIsClampedTo100()
    {
        var samples = new[]
        {
            ("pid_1_luid_0x0_0xA_phys_0_eng_0_engtype_3D", 80.0),
            ("pid_2_luid_0x0_0xA_phys_0_eng_0_engtype_3D", 70.0),
        };
        Assert.Equal(100.0, GpuAggregator.AggregateEngines(samples).Total);
    }

    [Fact]
    public void AggregateMemory_SumsPerProcess()
    {
        var samples = new[]
        {
            ("pid_1_luid_0x0_0xA_phys_0", 100.0),
            ("pid_1_luid_0x0_0xB_phys_0", 50.0),
            ("pid_2_luid_0x0_0xA_phys_0", 7.0),
        };
        var mem = GpuAggregator.AggregateMemory(samples);
        Assert.Equal(150L, mem[1]);
        Assert.Equal(7L, mem[2]);
    }
}
