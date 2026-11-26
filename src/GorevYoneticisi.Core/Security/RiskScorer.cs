using System.Text.RegularExpressions;

namespace GorevYoneticisi.Core.Security;

public enum SignatureStatus
{
    /// <summary>Not checked yet, or could not be checked (e.g. no access to the file).</summary>
    Unknown,
    Signed,
    Unsigned,
    /// <summary>Signature present but the file was modified after signing.</summary>
    Invalid,
    /// <summary>Signature present but the certificate chain is not trusted (self-signed, revoked, ...).</summary>
    Untrusted,
}

public enum RiskLevel { None = 0, Low = 1, Medium = 2, High = 3 }

public sealed record ProcessSecurityInput(
    string Name,
    string? Path,
    SignatureStatus Signature,
    string? Signer,
    bool IsHidden,
    bool FileExists);

public sealed record RiskAssessment(RiskLevel Level, int Score, IReadOnlyList<string> Reasons)
{
    public static readonly RiskAssessment Clean = new(RiskLevel.None, 0, Array.Empty<string>());
}

/// <summary>Heuristic, explainable risk score. Every point added comes with a Turkish reason.</summary>
public sealed partial class RiskScorer
{
    public const int LowThreshold = 1;
    public const int MediumThreshold = 30;
    public const int HighThreshold = 60;

    // Windows binaries that must only run from System32 / SysWOW64.
    private static readonly HashSet<string> System32Only = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe",
        "wininit.exe", "spoolsv.exe", "taskhostw.exe", "dwm.exe", "conhost.exe", "rundll32.exe",
        "lsaiso.exe", "fontdrvhost.exe", "sihost.exe", "ctfmon.exe", "dllhost.exe", "taskmgr.exe",
        "regsvr32.exe", "searchindexer.exe", "wudfhost.exe", "audiodg.exe", "runtimebroker.exe",
    };

    // Windows binaries that live directly in the Windows directory.
    private static readonly HashSet<string> WindowsDirOnly = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe",
    };

    // Kernel-managed pseudo processes: no file path can be read for them, which is normal.
    private static readonly HashSet<string> PathlessSystemProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Registry", "Secure System", "Memory Compression", "System Idle Process", "Idle",
        "vmmem", "vmmemWSL", "Interrupts",
    };

    // Real names that happen to be one edit away from a system name.
    private static readonly HashSet<string> LookalikeAllowList = new(StringComparer.OrdinalIgnoreCase)
    {
        "taskhost.exe", "taskhostex.exe", "dashost.exe",
    };

    [GeneratedRegex(@"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|bmp|mp3|mp4|avi|mkv|zip|rar|7z)\.(exe|scr|com|bat|cmd|pif|vbs|js)$", RegexOptions.IgnoreCase)]
    private static partial Regex DoubleExtension();

    private static readonly string[] RiskyLocations =
    {
        @"\AppData\Local\Temp\", @"\Windows\Temp\", @"\Downloads\", @"\Users\Public\", @"\$Recycle.Bin\",
    };

    private readonly string _windowsDir;
    private readonly string _system32;
    private readonly string _sysWow64;

    public RiskScorer(string windowsDirectory)
    {
        _windowsDir = Normalize(windowsDirectory);
        _system32 = _windowsDir + @"system32\";
        _sysWow64 = _windowsDir + @"syswow64\";
    }

    public RiskAssessment Assess(ProcessSecurityInput input)
    {
        int score = 0;
        var reasons = new List<string>();
        void Add(int points, string reason) { score += points; reasons.Add(reason); }

        string name = input.Name ?? "";
        string? dir = input.Path is null ? null : DirectoryOf(input.Path);

        if (input.IsHidden)
            Add(100, "İşlem bazı Windows listelerinden gizleniyor. Bu, rootkit davranışıdır.");

        switch (input.Signature)
        {
            case SignatureStatus.Invalid:
                Add(70, "Dijital imza geçersiz: dosya imzalandıktan sonra değiştirilmiş.");
                break;
            case SignatureStatus.Untrusted:
                Add(40, "Dijital imza güvenilir bir sertifikaya dayanmıyor.");
                break;
            case SignatureStatus.Unsigned:
                Add(20, "Dosyanın dijital imzası yok.");
                break;
        }

        bool signedOk = input.Signature == SignatureStatus.Signed;

        if (dir is not null)
        {
            if (System32Only.Contains(name) && dir != _system32 && dir != _sysWow64)
                Add(70, $"{name} bir Windows sistem dosyasının adı ama System32 dışından çalışıyor.");
            else if (WindowsDirOnly.Contains(name) && dir != _windowsDir && dir != _sysWow64)
                Add(70, $"{name} bir Windows sistem dosyasının adı ama Windows klasörü dışından çalışıyor.");

            string padded = input.Path!;
            if (RiskyLocations.Any(l => padded.Contains(l, StringComparison.OrdinalIgnoreCase)))
            {
                Add(signedOk ? 10 : 25, "Geçici dosyalar, İndirilenler ya da ortak klasör gibi riskli bir yerden çalışıyor.");
                if (input.Signature == SignatureStatus.Unsigned) Add(10, "İmzasız olması ve riskli yerde bulunması birlikte daha şüpheli.");
            }
            else if (padded.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase) && !signedOk)
            {
                Add(15, "ProgramData klasöründen imzasız olarak çalışıyor.");
            }
        }

        string? lookalike = FindLookalike(name);
        if (lookalike is not null)
            Add(60, $"Adı Windows sistem dosyası {lookalike} adına çok benziyor (taklit olabilir).");

        if (DoubleExtension().IsMatch(name))
            Add(40, "Çift uzantılı dosya adı (ör. belge.pdf.exe): belge gibi görünen bir program.");

        if (input.Path is not null && !input.FileExists)
            Add(40, "Program çalışıyor ama dosyası diskte yok (çalıştıktan sonra silinmiş olabilir).");

        if (input.Path is null && !input.IsHidden && !PathlessSystemProcesses.Contains(name))
            Add(5, "Dosya yolu okunamadı.");

        return new RiskAssessment(LevelFor(score), score, reasons);
    }

    public static RiskLevel LevelFor(int score) =>
        score >= HighThreshold ? RiskLevel.High :
        score >= MediumThreshold ? RiskLevel.Medium :
        score >= LowThreshold ? RiskLevel.Low : RiskLevel.None;

    private static string? FindLookalike(string name)
    {
        if (System32Only.Contains(name) || WindowsDirOnly.Contains(name) || LookalikeAllowList.Contains(name))
            return null;
        string baseName = StripExe(name);
        if (baseName.Length < 4) return null;
        foreach (var system in System32Only.Concat(WindowsDirOnly))
        {
            string sys = StripExe(system);
            if (sys.Length < 5) continue;
            if (OsaDistance(baseName.ToLowerInvariant(), sys.ToLowerInvariant()) == 1) return system;
        }
        return null;
    }

    private static string StripExe(string n) =>
        n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? n[..^4] : n;

    /// <summary>Optimal string alignment distance (Levenshtein + adjacent transposition).</summary>
    internal static int OsaDistance(string a, string b)
    {
        var d = new int[a.Length + 1, b.Length + 1];
        for (int i = 0; i <= a.Length; i++) d[i, 0] = i;
        for (int j = 0; j <= b.Length; j++) d[0, j] = j;
        for (int i = 1; i <= a.Length; i++)
        {
            for (int j = 1; j <= b.Length; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1])
                    d[i, j] = Math.Min(d[i, j], d[i - 2, j - 2] + 1);
            }
        }
        return d[a.Length, b.Length];
    }

    private static string DirectoryOf(string path)
    {
        string p = path.Replace('/', '\\');
        int idx = p.LastIndexOf('\\');
        return idx < 0 ? "" : Normalize(p[..idx]);
    }

    private static string Normalize(string dir) => dir.Replace('/', '\\').TrimEnd('\\').ToLowerInvariant() + @"\";
}
