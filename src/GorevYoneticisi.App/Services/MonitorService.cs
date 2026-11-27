using System.Diagnostics;
using GorevYoneticisi.App.Native;
using GorevYoneticisi.Core.Metrics;
using GorevYoneticisi.Core.Security;

namespace GorevYoneticisi.App.Services;

public sealed record ProcessInfo(
    int Pid,
    int ParentPid,
    string Name,
    string? Path,
    long CreateTime,
    double CpuPercent,
    long PrivateWorkingSet,
    long WorkingSet,
    double GpuPercent,
    long GpuMemory,
    double IoBytesPerSecond,
    int Threads,
    int Handles,
    SignatureInfo Signature,
    RiskAssessment Risk,
    HiddenProcessFinding? Hidden);

public sealed record MonitorSnapshot(DateTime Time, SystemTotals Totals, IReadOnlyList<ProcessInfo> Processes);

public sealed record HiddenProcessView(HiddenProcessFinding Finding, string Name, string? Path);

public sealed record SecurityReport(
    DateTime Time,
    TimeSpan Duration,
    CrossViewResult Result,
    IReadOnlyList<HiddenProcessView> Items,
    int BruteForceCount,
    int PrimaryCount);

/// <summary>
/// Runs collection on a background thread and publishes snapshots. Subscribers are called on that
/// background thread and must marshal to the UI thread themselves.
/// </summary>
public sealed class MonitorService : IDisposable
{
    private readonly SystemMetrics _metrics = new();
    private readonly ProcessTracker _tracker;
    private readonly ProcessDetails _details = new();
    private readonly SignatureCache _signatures = new();
    private readonly FileStates _files = new();
    private readonly RiskScorer _scorer = new(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
    private readonly HiddenProcessDetector _detector = new();
    private readonly SemaphoreSlim _scanLock = new(1, 1);
    private readonly CancellationTokenSource _cts = new();
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private Thread? _thread;
    private int _tick;
    private DateTime _lastScanStarted = DateTime.MinValue;

    public MonitorService()
    {
        DebugPrivilege = Advapi32.TryEnableDebugPrivilege();
        Hardware = HardwareInfo.Read();
        _tracker = new ProcessTracker(Hardware.LogicalProcessors);
        _signatures.Updated += () => SignaturesUpdated?.Invoke();
    }

    public HardwareInfo Hardware { get; }
    public bool DebugPrivilege { get; }
    public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(1);
    public TimeSpan SecurityInterval { get; set; } = TimeSpan.FromSeconds(10);
    public SecurityReport? LastSecurity { get; private set; }
    public string? LastError { get; private set; }

    public event Action<MonitorSnapshot>? SnapshotReady;
    public event Action<SecurityReport>? SecurityReportReady;
    public event Action? SignaturesUpdated;

    public void Start()
    {
        if (_thread is not null) return;
        _thread = new Thread(Loop) { IsBackground = true, Name = "İzleme", Priority = ThreadPriority.AboveNormal };
        _thread.Start();
    }

    private void Loop()
    {
        var token = _cts.Token;
        while (!token.IsCancellationRequested)
        {
            var started = _clock.Elapsed;
            try
            {
                var snapshot = Collect();
                LastError = null;
                SnapshotReady?.Invoke(snapshot);
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
            }

            if (DateTime.UtcNow - _lastScanStarted > SecurityInterval && _scanLock.CurrentCount > 0)
            {
                _lastScanStarted = DateTime.UtcNow;
                _ = Task.Run(() => RunSecurityScanAsync(token));
            }

            var wait = Interval - (_clock.Elapsed - started);
            if (wait < TimeSpan.FromMilliseconds(100)) wait = TimeSpan.FromMilliseconds(100);
            token.WaitHandle.WaitOne(wait);
        }
    }

    private MonitorSnapshot Collect()
    {
        var totals = _metrics.Sample();
        var raw = ProcessEnumeration.QueryPrimary();
        var rates = _tracker.Update(raw, _clock.Elapsed.Ticks);
        var gpu = _metrics.GpuPerProcess;
        var gpuMem = _metrics.GpuMemoryPerProcess;

        var hidden = new Dictionary<int, HiddenProcessView>();
        if (LastSecurity is { } sec)
            foreach (var item in sec.Items) hidden[item.Finding.Pid] = item;

        var list = new List<ProcessInfo>(rates.Count + hidden.Count);
        foreach (var m in rates)
        {
            var s = m.Sample;
            string? path = _details.GetPath(s.Pid, s.CreateTime);
            hidden.TryGetValue(s.Pid, out var h);
            var finding = h?.Finding;
            list.Add(Build(s.Pid, s.ParentPid, s.Name, path, s.CreateTime, m.CpuPercent, s.PrivateWorkingSet, s.WorkingSet,
                gpu.GetValueOrDefault(s.Pid), gpuMem.GetValueOrDefault(s.Pid), m.DiskBytesPerSecond, s.ThreadCount, s.HandleCount, finding));
            hidden.Remove(s.Pid);
        }

        // Processes found only by the security scan (hidden from the normal list) are added so they are visible.
        foreach (var h in hidden.Values.Where(v => v.Finding.Kind == HiddenKind.HiddenFromAllLists))
        {
            list.Add(Build(h.Finding.Pid, 0, h.Name, h.Path, h.Finding.CreateTime, 0, 0, 0, 0, 0, 0, 0, 0, h.Finding));
        }

        if (++_tick % 30 == 0) _details.Prune(raw.Select(r => (r.Pid, r.CreateTime)));
        return new MonitorSnapshot(DateTime.Now, totals, list);
    }

    private ProcessInfo Build(int pid, int ppid, string name, string? path, long create, double cpu, long privateWs, long ws,
        double gpu, long gpuMem, double io, int threads, int handles, HiddenProcessFinding? hidden)
    {
        var sig = _signatures.Get(path);
        var risk = _scorer.Assess(new ProcessSecurityInput(
            name, path, sig.Status, sig.Signer,
            hidden?.Severity ?? RiskLevel.None,
            _files.Get(path), pid, ppid));
        return new ProcessInfo(pid, ppid, name, path, create, cpu, privateWs, ws, gpu, gpuMem, io, threads, handles, sig, risk, hidden);
    }

    public async Task<SecurityReport?> RunSecurityScanAsync(CancellationToken cancel = default)
    {
        if (!await _scanLock.WaitAsync(0, cancel).ConfigureAwait(false))
        {
            // A scan is already running; wait for it and return its result.
            await _scanLock.WaitAsync(cancel).ConfigureAwait(false);
            _scanLock.Release();
            return LastSecurity;
        }
        try
        {
            var sw = Stopwatch.StartNew();
            // Order matters: brute force first, primary list last, so processes that start mid-scan
            // land in the primary list (no finding) rather than only in the brute-force view.
            var primaryGuess = SafeList(() => ProcessEnumeration.QueryPrimary().Select(p => p.Pid).ToHashSet());
            int maxPid = Math.Clamp((primaryGuess?.DefaultIfEmpty(0).Max() ?? 0) + 16384, 65536, 1 << 22);
            var brute = ProcessEnumeration.BruteForcePids(maxPid, cancel);
            var net = SafeList(() => NetworkConnections.Read().Select(c => c.Pid).ToHashSet()) ?? new HashSet<int>();
            var primary = SafeList(() => ProcessEnumeration.QueryPrimary().Select(p => p.Pid).ToHashSet());
            var toolhelp = SafeList(ProcessEnumeration.ToolhelpPids);
            var psapi = SafeList(ProcessEnumeration.EnumProcessesPids);

            var result = _detector.Analyze(new CrossViewInput(primary, toolhelp, psapi, brute, net));

            var items = result.Findings.Select(f =>
            {
                string? path = _details.QueryPath(f.Pid);
                string name = path is null ? $"(bilinmiyor, PID {f.Pid})" : System.IO.Path.GetFileName(path);
                return new HiddenProcessView(f, name, path);
            }).ToList();

            var report = new SecurityReport(DateTime.Now, sw.Elapsed, result, items, brute.Count, primary?.Count ?? 0);
            LastSecurity = report;
            SecurityReportReady?.Invoke(report);
            return report;
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        finally
        {
            _scanLock.Release();
        }
    }

    private static HashSet<int>? SafeList(Func<HashSet<int>> f)
    {
        try { return f(); } catch { return null; }
    }

    public static List<ConnectionInfo> ReadConnections() => NetworkConnections.Read();

    public static string? GetCommandLine(int pid) => ProcessDetails.QueryCommandLine(pid);

    public SignatureInfo GetSignature(string? path) => _signatures.Get(path);

    public RiskAssessment AssessFile(string name, string? path, int extraScore, IEnumerable<string> extraReasons)
    {
        var sig = _signatures.Get(path);
        var r = _scorer.Assess(new ProcessSecurityInput(name, path, sig.Status, sig.Signer, RiskLevel.None, _files.Get(path)));
        if (extraScore == 0) return r;
        int score = r.Score + extraScore;
        return new RiskAssessment(RiskScorer.LevelFor(score), score, extraReasons.Concat(r.Reasons).ToList());
    }

    public void Dispose()
    {
        _cts.Cancel();
        _thread?.Join(TimeSpan.FromSeconds(2));
        _signatures.Dispose();
        _metrics.Dispose();
    }
}

/// <summary>Whether a process's file still exists. Cached for 30 seconds per path; access problems are "Unknown".</summary>
internal sealed class FileStates
{
    private readonly Dictionary<string, (FileState State, long At)> _cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly long Ttl = TimeSpan.FromSeconds(30).Ticks;

    public FileState Get(string? path)
    {
        if (string.IsNullOrEmpty(path) || !System.IO.Path.IsPathFullyQualified(path)) return FileState.Unknown;
        long now = DateTime.UtcNow.Ticks;
        lock (_cache)
        {
            if (_cache.TryGetValue(path, out var e) && now - e.At < Ttl) return e.State;
        }
        FileState state;
        try
        {
            if (File.Exists(path)) state = FileState.Exists;
            else
            {
                string? dir = System.IO.Path.GetDirectoryName(path);
                state = dir is not null && Directory.Exists(dir) ? FileState.Missing : FileState.Unknown;
            }
        }
        catch
        {
            state = FileState.Unknown;
        }
        lock (_cache)
        {
            _cache[path] = (state, now);
        }
        return state;
    }
}
