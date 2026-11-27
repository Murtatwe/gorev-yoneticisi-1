namespace GorevYoneticisi.Core.Security;

public enum EnumerationMethod
{
    /// <summary>Primary list: NtQuerySystemInformation(SystemProcessInformation).</summary>
    NtQuerySystemInformation,
    /// <summary>CreateToolhelp32Snapshot.</summary>
    Toolhelp,
    /// <summary>EnumProcesses (psapi).</summary>
    EnumProcesses,
    /// <summary>OpenProcess on every possible PID; only processes confirmed still running.</summary>
    PidBruteForce,
    /// <summary>Owner PIDs of TCP/UDP endpoints.</summary>
    NetworkTable,
}

public enum HiddenKind
{
    /// <summary>Running (confirmed by opening it) but absent from Windows' process list: the classic rootkit signal.</summary>
    HiddenFromAllLists,
    /// <summary>Only a network endpoint refers to this PID. Often just a stale socket record.</summary>
    OnlyInNetworkTable,
    /// <summary>In the primary list but missing from Toolhelp or EnumProcesses. Usually timing; occasionally an API hook.</summary>
    MissingFromSomeLists,
}

/// <summary>
/// Inputs for one cross-view scan. A list is null when that method failed.
/// <see cref="BruteForceAlive"/> must contain only processes confirmed to be running
/// (WaitForSingleObject(handle, 0) == WAIT_TIMEOUT), mapped to their creation time.
/// </summary>
public sealed record CrossViewInput(
    IReadOnlySet<int>? Primary,
    IReadOnlySet<int>? Toolhelp,
    IReadOnlySet<int>? EnumProcesses,
    IReadOnlyDictionary<int, long> BruteForceAlive,
    IReadOnlySet<int> NetworkOwners);

public sealed record HiddenProcessFinding(int Pid, long CreateTime, HiddenKind Kind, IReadOnlyList<EnumerationMethod> MissingFrom, int ConsecutiveScans)
{
    public RiskLevel Severity => Kind == HiddenKind.HiddenFromAllLists ? RiskLevel.High : RiskLevel.Low;

    public string Description => Kind switch
    {
        HiddenKind.HiddenFromAllLists =>
            "Çalışıyor ama Windows'un işlem listelerinde görünmüyor. Zararlı yazılımlar kendini böyle gizler.",
        HiddenKind.OnlyInNetworkTable =>
            "Yalnızca bir ağ bağlantısı bu işlemi gösteriyor. Çoğunlukla kapanmış bir programdan kalan eski bir bağlantı kaydıdır.",
        _ =>
            "Bazı Windows listelerinde görünmüyor. Genellikle zamanlama farkıdır; sürekli tekrar ederse dikkat edin.",
    };
}

public sealed record CrossViewResult(
    bool PrimaryAvailable,
    IReadOnlyList<EnumerationMethod> FailedMethods,
    IReadOnlyList<HiddenProcessFinding> Findings);

/// <summary>
/// Cross-view detection. Note: Toolhelp and EnumProcesses are built on the same kernel call as the
/// primary list, so the meaningful signal is the PID brute force (and, weakly, network tables).
/// A discrepancy must persist for <see cref="RequiredConsecutiveScans"/> scans in a row, for the same
/// process (PID + creation time), so processes that simply started or exited mid-scan are ignored.
/// </summary>
public sealed class HiddenProcessDetector
{
    public const int RequiredConsecutiveScans = 2;

    /// <summary>A list view holding fewer than this share of the largest list is considered broken.</summary>
    public const double MinimumListShare = 0.5;

    private readonly Dictionary<(int Pid, long Create, HiddenKind Kind), int> _streaks = new();

    public CrossViewResult Analyze(CrossViewInput input)
    {
        var failed = new List<EnumerationMethod>();
        int largest = new[] { input.Primary, input.Toolhelp, input.EnumProcesses }.Max(s => s?.Count ?? 0);
        largest = Math.Max(largest, input.BruteForceAlive.Count);

        IReadOnlySet<int>? Valid(IReadOnlySet<int>? set, EnumerationMethod method)
        {
            if (set is null || set.Count == 0 || set.Count < largest * MinimumListShare)
            {
                failed.Add(method);
                return null;
            }
            return set;
        }

        var primary = Valid(input.Primary, EnumerationMethod.NtQuerySystemInformation);
        var toolhelp = Valid(input.Toolhelp, EnumerationMethod.Toolhelp);
        var psapi = Valid(input.EnumProcesses, EnumerationMethod.EnumProcesses);

        if (primary is null)
        {
            _streaks.Clear();
            return new CrossViewResult(false, failed, Array.Empty<HiddenProcessFinding>());
        }

        var candidates = new List<(int Pid, long Create, HiddenKind Kind, EnumerationMethod[] Missing)>();

        foreach (var (pid, create) in input.BruteForceAlive)
        {
            if (pid != 0 && !primary.Contains(pid))
                candidates.Add((pid, create, HiddenKind.HiddenFromAllLists, MissingLists(pid, primary, toolhelp, psapi)));
        }

        foreach (int pid in input.NetworkOwners)
        {
            if (pid != 0 && !primary.Contains(pid) && !input.BruteForceAlive.ContainsKey(pid))
                candidates.Add((pid, 0, HiddenKind.OnlyInNetworkTable, MissingLists(pid, primary, toolhelp, psapi)));
        }

        foreach (int pid in primary)
        {
            if (pid == 0) continue;
            var missing = new List<EnumerationMethod>();
            if (toolhelp is not null && !toolhelp.Contains(pid)) missing.Add(EnumerationMethod.Toolhelp);
            if (psapi is not null && !psapi.Contains(pid)) missing.Add(EnumerationMethod.EnumProcesses);
            if (missing.Count > 0)
            {
                long create = input.BruteForceAlive.TryGetValue(pid, out long c) ? c : 0;
                candidates.Add((pid, create, HiddenKind.MissingFromSomeLists, missing.ToArray()));
            }
        }

        var findings = new List<HiddenProcessFinding>();
        var seen = new HashSet<(int, long, HiddenKind)>();
        foreach (var c in candidates.OrderBy(c => c.Pid))
        {
            var key = (c.Pid, c.Create, c.Kind);
            if (!seen.Add(key)) continue;
            int streak = _streaks.TryGetValue(key, out int s) ? s + 1 : 1;
            _streaks[key] = streak;
            if (streak >= RequiredConsecutiveScans)
                findings.Add(new HiddenProcessFinding(c.Pid, c.Create, c.Kind, c.Missing, streak));
        }

        foreach (var key in _streaks.Keys.Where(k => !seen.Contains(k)).ToList())
            _streaks.Remove(key);

        return new CrossViewResult(true, failed, findings);
    }

    private static EnumerationMethod[] MissingLists(int pid, IReadOnlySet<int> primary, IReadOnlySet<int>? toolhelp, IReadOnlySet<int>? psapi)
    {
        var list = new List<EnumerationMethod>();
        if (!primary.Contains(pid)) list.Add(EnumerationMethod.NtQuerySystemInformation);
        if (toolhelp is not null && !toolhelp.Contains(pid)) list.Add(EnumerationMethod.Toolhelp);
        if (psapi is not null && !psapi.Contains(pid)) list.Add(EnumerationMethod.EnumProcesses);
        return list.ToArray();
    }
}
