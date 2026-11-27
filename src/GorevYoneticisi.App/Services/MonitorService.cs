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
    private readonly Dictionary<(int Pid, long Create), (SignatureStatus Sig, FileState File, RiskLevel Hidden, RiskAssessment Risk)> _riskCache = new();
    private Thread? _thread;
    private Task? _scanTask;
    private int _tick;
    private DateTime _lastScanStarted = DateTime.MinValue;
    private HashSet<int>? _lastPrimaryPids;

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
    public TimeSpan SecurityInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>While the Security page is open, background scans run at least every 10 seconds.</summary>
    public bool FastSecurityScans { get; set; }
    public SecurityReport? LastSecurity { get; private set; }
    public string? LastError { get; private set; }

    public event Action<MonitorSnapshot>? SnapshotReady;
    public event Action<SecurityReport>? SecurityReportReady;
    public event Action? SignaturesUpdated;
    /// <summary>Collection or scan errors (null = recovered). Called on a background thread.</summary>
    public event Action<string?>? ErrorChanged;
    public event Action<string>? SecurityScanFailed;

    private readonly HashSet<string> _loggedErrors = new();

    public void Start()
    {
        if (_thread is not null) return;
        _thread = new Thread(Loop) { IsBackground = true, Name = "İzleme", Priority = ThreadPriority.Normal };
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
                if (LastError is not null)
                {
                    LastError = null;
                    ErrorChanged?.Invoke(null);
                }
                SnapshotReady?.Invoke(snapshot);
            }
            catch (Exception ex)
            {
                if (LastError != ex.Message)
                {
                    LastError = ex.Message;
                    ErrorChanged?.Invoke(ex.Message);
                }
                if (_loggedErrors.Add(ex.Message)) App.Log(ex, "Veri toplama hatası");
            }

            var scanEvery = FastSecurityScans && SecurityInterval > TimeSpan.FromSeconds(10) ? TimeSpan.FromSeconds(10) : SecurityInterval;
            if (DateTime.UtcNow - _lastScanStarted > scanEvery && _scanLock.CurrentCount > 0)
            {
                _lastScanStarted = DateTime.UtcNow;
                _scanTask = RunSecurityScanAsync(token);
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

        _lastPrimaryPids = raw.Select(r => r.Pid).ToHashSet();

        var hidden = new Dictionary<int, HiddenProcessView>();
        if (LastSecurity is { } sec)
            foreach (var item in sec.Items) hidden[item.Finding.Pid] = item;

        double scale = _metrics.CpuScale;
        var list = new List<ProcessInfo>(rates.Count + hidden.Count);
        foreach (var m in rates)
        {
            var s = m.Sample;
            string? path = _details.GetPath(s.Pid, s.CreateTime);
            HiddenProcessFinding? finding = null;
            if (hidden.Remove(s.Pid, out var h))
            {
                // A finding belongs to one specific process (PID + start time). A process that is in the normal
                // list is, by definition, not hidden from it any more; only the weaker findings still apply.
                bool sameProcess = h.Finding.CreateTime == 0 || h.Finding.CreateTime == s.CreateTime;
                if (sameProcess && h.Finding.Kind != HiddenKind.HiddenFromAllLists) finding = h.Finding;
            }
            list.Add(Build(s.Pid, s.ParentPid, s.Name, path, s.CreateTime, CpuMath.Clamp(m.CpuPercent * scale), s.PrivateWorkingSet, s.WorkingSet,
                gpu.GetValueOrDefault(s.Pid), gpuMem.GetValueOrDefault(s.Pid), m.DiskBytesPerSecond, s.ThreadCount, s.HandleCount, finding));
        }

        // Processes found only by the security scan (hidden from the normal list) are added so they are visible.
        foreach (var h in hidden.Values.Where(v => v.Finding.Kind == HiddenKind.HiddenFromAllLists))
        {
            list.Add(Build(h.Finding.Pid, 0, h.Name, h.Path, h.Finding.CreateTime, 0, 0, 0, 0, 0, 0, 0, 0, h.Finding));
        }

        if (++_tick % 30 == 0)
        {
            var alive = raw.Select(r => (r.Pid, r.CreateTime)).ToHashSet();
            _details.Prune(alive);
            foreach (var key in _riskCache.Keys.Where(k => !alive.Contains(k)).ToList()) _riskCache.Remove(key);
        }
        return new MonitorSnapshot(DateTime.Now, totals, list);
    }

    private ProcessInfo Build(int pid, int ppid, string name, string? path, long create, double cpu, long privateWs, long ws,
        double gpu, long gpuMem, double io, int threads, int handles, HiddenProcessFinding? hidden)
    {
        var sig = _signatures.Get(path);
        var file = _files.Get(path);
        var hiddenLevel = hidden?.Severity ?? RiskLevel.None;
        // Scoring is pure but not free; only recompute when one of its inputs changed.
        if (!_riskCache.TryGetValue((pid, create), out var cached) ||
            cached.Sig != sig.Status || cached.File != file || cached.Hidden != hiddenLevel)
        {
            var assessed = _scorer.Assess(new ProcessSecurityInput(name, path, sig.Status, sig.Signer, hiddenLevel, file, pid, ppid));
            cached = (sig.Status, file, hiddenLevel, assessed);
            _riskCache[(pid, create)] = cached;
        }
        var risk = cached.Risk;
        return new ProcessInfo(pid, ppid, name, path, create, cpu, privateWs, ws, gpu, gpuMem, io, threads, handles, sig, risk, hidden);
    }

    /// <summary>Runs a cross-view scan on a background thread. Safe to call from the UI thread.</summary>
    public Task<SecurityReport?> RunSecurityScanAsync(CancellationToken cancel = default) =>
        Task.Run(() => ScanCoreAsync(cancel), cancel);

    private async Task<SecurityReport?> ScanCoreAsync(CancellationToken cancel)
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
            var primaryGuess = _lastPrimaryPids ?? SafeList(() => ProcessEnumeration.QueryPrimary().Select(p => p.Pid).ToHashSet());
            int maxPid = Math.Clamp((primaryGuess?.DefaultIfEmpty(0).Max() ?? 0) + 16384, 65536, 1 << 22);
            // Processes already in the normal list are not opened at all: the detector only cares about
            // live processes missing from it. This also keeps audit tools (Sysmon, EDR) from logging every process.
            var brute = ProcessEnumeration.BruteForcePids(maxPid, primaryGuess, cancel);
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
        catch (Exception ex)
        {
            App.Log(ex, "Güvenlik taraması hatası");
            SecurityScanFailed?.Invoke(ex.Message);
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

    public SignatureInfo GetSignature(string? path, bool highPriority = true) => _signatures.Get(path, highPriority);

    public FileState GetFileState(string? path) => _files.Get(path);

    /// <summary>Risk of a startup entry (nothing is running, so a missing file means a leftover entry, not a deleted program).</summary>
    public RiskAssessment AssessStartupFile(string name, string? path, int extraScore, IEnumerable<string> extraReasons)
    {
        var reasons = extraReasons.ToList();
        int score = extraScore;
        if (path is not null && Path.IsPathFullyQualified(path))
        {
            var sig = _signatures.Get(path, highPriority: false);
            var r = _scorer.Assess(new ProcessSecurityInput(name, path, sig.Status, sig.Signer, RiskLevel.None, FileState.Unknown));
            score += r.Score;
            reasons.AddRange(r.Reasons);
            if (_files.Get(path) == FileState.Missing)
            {
                score += 5;
                reasons.Add("Kayıt duruyor ama dosyası yok. Genellikle kaldırılmış bir programdan kalır.");
            }
        }
        return new RiskAssessment(RiskScorer.LevelFor(score), score, reasons);
    }

    public void Dispose()
    {
        _cts.Cancel();
        bool stopped = _thread?.Join(TimeSpan.FromSeconds(3)) ?? true;
        try { _scanTask?.Wait(TimeSpan.FromSeconds(2)); } catch { /* cancelled or failed; already logged */ }
        _signatures.Dispose();
        // Closing PDH queries while the collector thread is still inside PDH could crash natively.
        if (stopped) _metrics.Dispose();
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
