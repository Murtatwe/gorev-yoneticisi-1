namespace GorevYoneticisi.Core.Security;

public enum EnumerationMethod
{
    /// <summary>Primary list: NtQuerySystemInformation(SystemProcessInformation).</summary>
    NtQuerySystemInformation,
    /// <summary>CreateToolhelp32Snapshot.</summary>
    Toolhelp,
    /// <summary>EnumProcesses (psapi).</summary>
    EnumProcesses,
    /// <summary>OpenProcess on every possible PID; only processes that are still running are counted.</summary>
    PidBruteForce,
    /// <summary>Owner PIDs of TCP/UDP endpoints.</summary>
    NetworkTable,
}

public sealed record HiddenProcessFinding(
    int Pid,
    IReadOnlyList<EnumerationMethod> SeenBy,
    IReadOnlyList<EnumerationMethod> MissingFrom,
    bool MissingFromPrimary,
    int ConsecutiveScans)
{
    /// <summary>Missing from the primary list = probably hidden on purpose. Otherwise only one API disagrees.</summary>
    public RiskLevel Severity => MissingFromPrimary ? RiskLevel.High : RiskLevel.Medium;
}

/// <summary>
/// Cross-view detection: compares process lists obtained in independent ways.
/// A discrepancy must persist for <see cref="RequiredConsecutiveScans"/> scans in a row,
/// so processes that simply started or exited between two API calls are not reported.
/// </summary>
public sealed class HiddenProcessDetector
{
    public const int RequiredConsecutiveScans = 2;

    // Complete process lists. Brute force and network tables are partial by nature
    // (protected processes may refuse OpenProcess, most processes have no sockets),
    // so absence from them is never evidence of anything.
    private static readonly EnumerationMethod[] ListMethods =
    {
        EnumerationMethod.NtQuerySystemInformation,
        EnumerationMethod.Toolhelp,
        EnumerationMethod.EnumProcesses,
    };

    private readonly Dictionary<int, int> _streaks = new();

    public IReadOnlyList<HiddenProcessFinding> Analyze(IReadOnlyDictionary<EnumerationMethod, IReadOnlySet<int>> views)
    {
        IReadOnlySet<int> Get(EnumerationMethod m) =>
            views.TryGetValue(m, out var s) ? s : new HashSet<int>();

        var primary = Get(EnumerationMethod.NtQuerySystemInformation);
        var all = new HashSet<int>();
        foreach (var set in views.Values) all.UnionWith(set);
        all.Remove(0); // System Idle Process is a pseudo-process; APIs disagree about it by design.

        var findings = new List<HiddenProcessFinding>();
        var seenThisScan = new HashSet<int>();

        foreach (int pid in all.OrderBy(p => p))
        {
            var seenBy = views.Where(kv => kv.Value.Contains(pid)).Select(kv => kv.Key).OrderBy(m => m).ToArray();
            var missingFrom = ListMethods
                .Where(m => views.ContainsKey(m) && !views[m].Contains(pid))
                .ToArray();
            if (missingFrom.Length == 0) continue;

            seenThisScan.Add(pid);
            int streak = _streaks.TryGetValue(pid, out int s) ? s + 1 : 1;
            _streaks[pid] = streak;

            if (streak >= RequiredConsecutiveScans)
            {
                findings.Add(new HiddenProcessFinding(pid, seenBy, missingFrom, !primary.Contains(pid), streak));
            }
        }

        foreach (int pid in _streaks.Keys.Where(p => !seenThisScan.Contains(p)).ToList())
            _streaks.Remove(pid);

        return findings;
    }
}
