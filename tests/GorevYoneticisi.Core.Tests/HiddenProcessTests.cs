using GorevYoneticisi.Core.Security;

namespace GorevYoneticisi.Core.Tests;

public class HiddenProcessTests
{
    private static CrossViewInput Input(
        int[]? nt, int[]? toolhelp = null, int[]? psapi = null,
        (int Pid, long Create)[]? brute = null, int[]? net = null)
    {
        toolhelp ??= nt;
        psapi ??= nt;
        return new CrossViewInput(
            Primary: nt?.ToHashSet(),
            Toolhelp: toolhelp?.ToHashSet(),
            EnumProcesses: psapi?.ToHashSet(),
            BruteForceAlive: (brute ?? (nt ?? Array.Empty<int>()).Select(p => (p, 1L)).ToArray()).ToDictionary(x => x.Item1, x => x.Item2),
            NetworkOwners: (net ?? Array.Empty<int>()).ToHashSet());
    }

    private static readonly int[] Base = Enumerable.Range(1, 50).Select(i => i * 4).ToArray();

    [Fact]
    public void ConsistentViews_ProduceNoFindings()
    {
        var d = new HiddenProcessDetector();
        Assert.Empty(d.Analyze(Input(Base)).Findings);
        Assert.Empty(d.Analyze(Input(Base)).Findings);
    }

    [Fact]
    public void LiveProcessMissingFromAllLists_IsHighAfterTwoScans()
    {
        var d = new HiddenProcessDetector();
        var brute = Base.Select(p => (p, 1L)).Append((666, 77L)).ToArray();
        var input = Input(Base, brute: brute);

        Assert.Empty(d.Analyze(input).Findings);
        var f = Assert.Single(d.Analyze(input).Findings);
        Assert.Equal(666, f.Pid);
        Assert.Equal(77L, f.CreateTime);
        Assert.Equal(HiddenKind.HiddenFromAllLists, f.Kind);
        Assert.Equal(RiskLevel.High, f.Severity);
    }

    [Fact]
    public void TransientDiscrepancy_IsForgotten()
    {
        var d = new HiddenProcessDetector();
        var bad = Input(Base, brute: Base.Select(p => (p, 1L)).Append((666, 1L)).ToArray());
        Assert.Empty(d.Analyze(bad).Findings);
        Assert.Empty(d.Analyze(Input(Base)).Findings);
        Assert.Empty(d.Analyze(bad).Findings);
    }

    [Fact]
    public void ReusedPidWithDifferentCreateTime_ResetsStreak()
    {
        var d = new HiddenProcessDetector();
        Assert.Empty(d.Analyze(Input(Base, brute: Base.Select(p => (p, 1L)).Append((666, 1L)).ToArray())).Findings);
        Assert.Empty(d.Analyze(Input(Base, brute: Base.Select(p => (p, 1L)).Append((666, 2L)).ToArray())).Findings);
    }

    [Fact]
    public void NetworkOnlyOwner_IsLowAndWordedAsStaleRecord()
    {
        var d = new HiddenProcessDetector();
        var input = Input(Base, net: new[] { 4, 777 });
        d.Analyze(input);
        var f = Assert.Single(d.Analyze(input).Findings);
        Assert.Equal(777, f.Pid);
        Assert.Equal(HiddenKind.OnlyInNetworkTable, f.Kind);
        Assert.Equal(RiskLevel.Low, f.Severity);
    }

    [Fact]
    public void MissingOnlyFromSecondaryList_IsLow()
    {
        var d = new HiddenProcessDetector();
        var input = Input(Base, toolhelp: Base.Where(p => p != 40).ToArray());
        d.Analyze(input);
        var f = Assert.Single(d.Analyze(input).Findings);
        Assert.Equal(40, f.Pid);
        Assert.Equal(HiddenKind.MissingFromSomeLists, f.Kind);
        Assert.Equal(RiskLevel.Low, f.Severity);
    }

    [Fact]
    public void BruteForceNotSeeingAProcess_IsNotAFinding()
    {
        var d = new HiddenProcessDetector();
        var input = Input(Base, brute: Base.Skip(5).Select(p => (p, 1L)).ToArray());
        d.Analyze(input);
        Assert.Empty(d.Analyze(input).Findings);
    }

    [Fact]
    public void FailedPrimaryView_IsReportedAsFailure_NotAsMassAlarm()
    {
        var d = new HiddenProcessDetector();
        var input = Input(nt: null, toolhelp: Base, psapi: Base, brute: Base.Select(p => (p, 1L)).ToArray());
        d.Analyze(input);
        var r = d.Analyze(input);
        Assert.False(r.PrimaryAvailable);
        Assert.Empty(r.Findings);
    }

    [Fact]
    public void EmptyOrTruncatedPrimaryView_IsTreatedAsFailure()
    {
        var d = new HiddenProcessDetector();
        var input = Input(nt: Base.Take(3).ToArray(), toolhelp: Base, psapi: Base, brute: Base.Select(p => (p, 1L)).ToArray());
        d.Analyze(input);
        var r = d.Analyze(input);
        Assert.False(r.PrimaryAvailable);
        Assert.Empty(r.Findings);
    }

    [Fact]
    public void BrokenSecondaryView_IsIgnoredAndReported()
    {
        var d = new HiddenProcessDetector();
        var input = Input(Base, toolhelp: Array.Empty<int>());
        d.Analyze(input);
        var r = d.Analyze(input);
        Assert.True(r.PrimaryAvailable);
        Assert.Empty(r.Findings);
        Assert.Contains(EnumerationMethod.Toolhelp, r.FailedMethods);
    }

    [Fact]
    public void IdlePidZero_IsIgnored()
    {
        var d = new HiddenProcessDetector();
        var input = Input(Base, toolhelp: Base.Append(0).ToArray(), net: new[] { 0 });
        d.Analyze(input);
        Assert.Empty(d.Analyze(input).Findings);
    }
}
