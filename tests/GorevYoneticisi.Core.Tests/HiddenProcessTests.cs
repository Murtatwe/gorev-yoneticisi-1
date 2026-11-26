using GorevYoneticisi.Core.Security;

namespace GorevYoneticisi.Core.Tests;

public class HiddenProcessTests
{
    private static Dictionary<EnumerationMethod, IReadOnlySet<int>> Views(
        int[] nt, int[] toolhelp, int[] psapi, int[] brute, int[]? net = null) => new()
    {
        [EnumerationMethod.NtQuerySystemInformation] = nt.ToHashSet(),
        [EnumerationMethod.Toolhelp] = toolhelp.ToHashSet(),
        [EnumerationMethod.EnumProcesses] = psapi.ToHashSet(),
        [EnumerationMethod.PidBruteForce] = brute.ToHashSet(),
        [EnumerationMethod.NetworkTable] = (net ?? Array.Empty<int>()).ToHashSet(),
    };

    [Fact]
    public void ConsistentViews_ProduceNoFindings()
    {
        var detector = new HiddenProcessDetector();
        var v = Views(new[] { 4, 100, 200 }, new[] { 4, 100, 200 }, new[] { 4, 100, 200 }, new[] { 4, 100, 200 });
        Assert.Empty(detector.Analyze(v));
        Assert.Empty(detector.Analyze(v));
    }

    [Fact]
    public void ProcessMissingFromPrimaryList_IsReportedOnlyAfterTwoConsecutiveScans()
    {
        var detector = new HiddenProcessDetector();
        var v = Views(new[] { 4, 100 }, new[] { 4, 100 }, new[] { 4, 100 }, new[] { 4, 100, 666 });

        Assert.Empty(detector.Analyze(v)); // first sighting could be a race (process just started)

        var finding = Assert.Single(detector.Analyze(v));
        Assert.Equal(666, finding.Pid);
        Assert.Contains(EnumerationMethod.PidBruteForce, finding.SeenBy);
        Assert.Contains(EnumerationMethod.NtQuerySystemInformation, finding.MissingFrom);
        Assert.Contains(EnumerationMethod.Toolhelp, finding.MissingFrom);
    }

    [Fact]
    public void TransientDiscrepancy_IsForgottenWhenItDisappears()
    {
        var detector = new HiddenProcessDetector();
        var bad = Views(new[] { 4 }, new[] { 4 }, new[] { 4 }, new[] { 4, 666 });
        var good = Views(new[] { 4 }, new[] { 4 }, new[] { 4 }, new[] { 4 });

        Assert.Empty(detector.Analyze(bad));
        Assert.Empty(detector.Analyze(good));
        Assert.Empty(detector.Analyze(bad)); // counter was reset
    }

    [Fact]
    public void NetworkOwnerNotInProcessList_IsHidden()
    {
        var detector = new HiddenProcessDetector();
        var v = Views(new[] { 4, 100 }, new[] { 4, 100 }, new[] { 4, 100 }, new[] { 4, 100 }, net: new[] { 100, 777 });
        detector.Analyze(v);
        var f = Assert.Single(detector.Analyze(v));
        Assert.Equal(777, f.Pid);
        Assert.Equal(new[] { EnumerationMethod.NetworkTable }, f.SeenBy);
    }

    [Fact]
    public void IdlePidZero_IsIgnored()
    {
        var detector = new HiddenProcessDetector();
        var v = Views(new[] { 4 }, new[] { 0, 4 }, new[] { 0, 4 }, new[] { 4 }, net: new[] { 0 });
        detector.Analyze(v);
        Assert.Empty(detector.Analyze(v));
    }

    [Fact]
    public void ProcessMissingOnlyFromSecondaryList_IsReportedAsMinorInconsistency()
    {
        // Present in NtQuery and brute force, missing from Toolhelp only: a user-mode hook on one API.
        var detector = new HiddenProcessDetector();
        var v = Views(new[] { 4, 300 }, new[] { 4 }, new[] { 4, 300 }, new[] { 4, 300 });
        detector.Analyze(v);
        var f = Assert.Single(detector.Analyze(v));
        Assert.Equal(300, f.Pid);
        Assert.False(f.MissingFromPrimary);
        Assert.Equal(new[] { EnumerationMethod.Toolhelp }, f.MissingFrom);
    }

    [Fact]
    public void BruteForceNotSeeingAProcess_IsNotAFinding()
    {
        // Protected processes can refuse OpenProcess even for admins; absence from brute force means nothing.
        var detector = new HiddenProcessDetector();
        var v = Views(new[] { 4, 500 }, new[] { 4, 500 }, new[] { 4, 500 }, new[] { 4 });
        detector.Analyze(v);
        Assert.Empty(detector.Analyze(v));
    }
}
