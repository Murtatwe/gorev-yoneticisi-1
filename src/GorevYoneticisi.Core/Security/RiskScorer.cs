using System.Text.RegularExpressions;

namespace GorevYoneticisi.Core.Security;

public enum SignatureStatus
{
    /// <summary>Not checked yet, or could not be checked (e.g. no access to the file). Never scored as unsigned.</summary>
    Unknown,
    Signed,
    Unsigned,
    /// <summary>Signature present but the file content no longer matches it (TRUST_E_BAD_DIGEST).</summary>
    Invalid,
    /// <summary>Signature present but the certificate chain is not trusted (self-signed, revoked, ...).</summary>
    Untrusted,
    /// <summary>Signed with a certificate that has expired and no timestamp. Common for old legitimate software.</summary>
    Expired,
}

public enum RiskLevel { None = 0, Low = 1, Medium = 2, High = 3 }

public enum FileState { Unknown, Exists, Missing }

public sealed record ProcessSecurityInput(
    string Name,
    string? Path,
    SignatureStatus Signature,
    string? Signer,
    RiskLevel HiddenSeverity,
    FileState File,
    int? Pid = null,
    int? ParentPid = null);

public sealed record RiskAssessment(RiskLevel Level, int Score, IReadOnlyList<string> Reasons)
{
    public static readonly RiskAssessment Clean = new(RiskLevel.None, 0, Array.Empty<string>());
}

/// <summary>Heuristic, explainable risk score. Every point added comes with a plain-Turkish reason.</summary>
public sealed partial class RiskScorer
{
    public const int MediumThreshold = 30;
    public const int HighThreshold = 60;

    private static readonly string[] S32 = { @"system32\" };
    private static readonly string[] S32AndWow = { @"system32\", @"syswow64\" };

    /// <summary>Windows program names and the only folders (relative to the Windows folder) they legitimately run from.</summary>
    private static readonly Dictionary<string, string[]> KnownLocations = new(StringComparer.OrdinalIgnoreCase)
    {
        // 64-bit-only core processes
        ["lsass.exe"] = S32, ["csrss.exe"] = S32, ["smss.exe"] = S32, ["wininit.exe"] = S32,
        ["winlogon.exe"] = S32, ["services.exe"] = S32, ["lsaiso.exe"] = S32, ["dwm.exe"] = S32,
        ["sihost.exe"] = S32, ["fontdrvhost.exe"] = S32, ["spoolsv.exe"] = S32, ["audiodg.exe"] = S32,
        ["searchindexer.exe"] = S32, ["wudfhost.exe"] = S32, ["userinit.exe"] = S32, ["logonui.exe"] = S32,
        ["consent.exe"] = S32, ["taskhostw.exe"] = S32, ["smartscreen.exe"] = S32,
        ["runtimebroker.exe"] = S32, ["backgroundtaskhost.exe"] = S32,
        // Exist in both 64- and 32-bit flavours
        ["svchost.exe"] = S32AndWow, ["dllhost.exe"] = S32AndWow, ["rundll32.exe"] = S32AndWow,
        ["regsvr32.exe"] = S32AndWow, ["conhost.exe"] = S32AndWow, ["taskmgr.exe"] = S32AndWow,
        ["ctfmon.exe"] = S32AndWow, ["cmd.exe"] = S32AndWow, ["mshta.exe"] = S32AndWow,
        ["wscript.exe"] = S32AndWow, ["cscript.exe"] = S32AndWow, ["msiexec.exe"] = S32AndWow,
        ["werfault.exe"] = S32AndWow,
        // Special folders
        ["explorer.exe"] = new[] { "", @"syswow64\" },
        ["powershell.exe"] = new[] { @"system32\windowspowershell\v1.0\", @"syswow64\windowspowershell\v1.0\" },
        ["wmiprvse.exe"] = new[] { @"system32\wbem\", @"syswow64\wbem\" },
    };

    /// <summary>Microsoft Defender lives outside the Windows folder; these are path prefixes relative to the system drive.</summary>
    private static readonly Dictionary<string, string[]> KnownPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["msmpeng.exe"] = new[] { @"programdata\microsoft\windows defender\platform\", @"program files\windows defender\" },
        ["nissrv.exe"] = new[] { @"programdata\microsoft\windows defender\platform\", @"program files\windows defender\" },
        ["mpdefendercoreservice.exe"] = new[] { @"programdata\microsoft\windows defender\platform\", @"program files\windows defender\" },
    };

    private static readonly HashSet<string> LookalikeAllowList = new(StringComparer.OrdinalIgnoreCase)
    {
        "taskhost.exe", "taskhostex.exe", "dashost.exe", "iexplore.exe", "mscorsvw.exe",
    };

    /// <summary>Kernel pseudo-processes that legitimately have no file. Only valid as PID 4 or a direct child of PID 4.</summary>
    private static readonly HashSet<string> KernelPseudoProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Registry", "Secure System", "Memory Compression",
    };

    private static readonly HashSet<string> OtherPathless = new(StringComparer.OrdinalIgnoreCase)
    {
        "System Idle Process", "Idle", "vmmem", "vmmemWSL",
    };

    [GeneratedRegex(@"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|bmp|mp3|mp4|avi|mkv|zip|rar|7z)\s*\.(exe|scr|com|bat|cmd|pif|vbs|js)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DoubleExtension();

    [GeneratedRegex(@"^[A-Za-z]:\\")]
    private static partial Regex DosPath();

    private static readonly (string Fragment, string Label)[] RiskyLocations =
    {
        (@"\appdata\local\temp\", "geçici dosyalar (Temp) klasöründen"),
        (@"\windows\temp\", "Windows geçici dosyalar klasöründen"),
        (@"\downloads\", "İndirilenler klasöründen"),
        (@"\users\public\", "herkese açık kullanıcı klasöründen"),
        (@"\$recycle.bin\", "Geri Dönüşüm Kutusu'ndan"),
        (@"\windows\tasks\", "Windows'un program barındırmaması gereken Tasks klasöründen"),
        (@"\windows\fonts\", "yazı tipleri (Fonts) klasöründen"),
        (@"\windows\debug\", "Windows'un Debug klasöründen"),
        (@":\perflogs\", "PerfLogs klasöründen"),
    };

    private static readonly (string Fragment, string Label)[] UserLocations =
    {
        (@"\appdata\roaming\", "kullanıcı AppData\\Roaming klasöründen"),
        (@"\appdata\local\", "kullanıcı AppData\\Local klasöründen"),
        (@"\desktop\", "Masaüstünden"),
        (@":\programdata\", "ProgramData klasöründen"),
    };

    private static readonly string[] PackageLocations = { @"\program files\windowsapps\", @"\windows\systemapps\" };

    private readonly string _windowsDir;   // "c:\windows\"
    private readonly string _systemDrive;  // "c:\"

    public RiskScorer(string windowsDirectory)
    {
        _windowsDir = NormalizeDir(windowsDirectory);
        _systemDrive = _windowsDir.Length >= 3 ? _windowsDir[..3] : @"c:\";
    }

    public RiskAssessment Assess(ProcessSecurityInput input)
    {
        int score = 0;
        var reasons = new List<string>();
        void Add(int points, string reason) { score += points; reasons.Add(reason); }

        string rawName = input.Name ?? "";
        string? path = input.Path;
        bool dos = path is not null && DosPath().IsMatch(path);
        string rawFileName = dos ? path![(path!.LastIndexOf('\\') + 1)..] : rawName;
        string name = NameNormalizer.Skeleton(rawFileName);
        string lowerPath = dos ? path!.ToLowerInvariant() : "";
        string dir = dos ? lowerPath[..(lowerPath.LastIndexOf('\\') + 1)] : "";
        var sig = input.Signature;
        bool badSig = sig is SignatureStatus.Unsigned or SignatureStatus.Untrusted or SignatureStatus.Invalid;
        bool packaged = dos && PackageLocations.Any(l => lowerPath.Contains(l, StringComparison.Ordinal));

        // --- hidden from Windows' process lists ---
        switch (input.HiddenSeverity)
        {
            case RiskLevel.High:
                Add(100, "Bu işlem Windows'un işlem listelerinde görünmüyor ama çalışıyor. Zararlı yazılımlar kendini böyle gizler; nadiren bir güvenlik programı da buna yol açabilir.");
                break;
            case RiskLevel.Medium:
                Add(40, "Bu işlem Windows'un bazı listelerinde görünmüyor.");
                break;
            case RiskLevel.Low:
                Add(10, "Windows listelerinde küçük bir tutarsızlık var (genelde zararsızdır).");
                break;
        }

        // --- fake kernel processes ---
        if (KernelPseudoProcesses.Contains(rawName) && input.Pid is int pid && pid != 4 && input.ParentPid != 4)
            Add(80, $"\"{rawName}\" adı Windows çekirdeğine ait, ama bu işlem gerçek sistem işlemi değil (sahte olabilir).");

        // --- digital signature ---
        switch (sig)
        {
            case SignatureStatus.Invalid:
                Add(70, "Dijital imza geçersiz: dosya imzalandıktan sonra değiştirilmiş olabilir.");
                break;
            case SignatureStatus.Untrusted:
                Add(40, "İmza var ama Windows bu imzaya güvenmiyor (sertifika iptal edilmiş ya da kendinden imzalı olabilir).");
                break;
            case SignatureStatus.Expired:
                Add(5, "Dijital imzanın süresi dolmuş. Eski programlarda olağandır.");
                break;
            case SignatureStatus.Unsigned when !packaged:
                Add(20, "Dosyanın dijital imzası yok. Tek başına tehlikeli değildir; birçok küçük program imzasızdır.");
                break;
        }

        // --- misleading characters in the file name ---
        if (NameNormalizer.HasMisleadingCharacters(rawFileName) || NameNormalizer.HasMisleadingCharacters(rawName))
            Add(60, "Dosya adında görünmeyen ya da yanıltıcı karakterler var (ör. başka alfabeden harfler, sonda boşluk). Bu, gerçek adı gizleme hilesidir.");

        // --- Windows program names in the wrong folder ---
        if (dos)
        {
            if (KnownLocations.TryGetValue(name, out var allowedDirs))
            {
                if (!allowedDirs.Any(d => dir == _windowsDir + d))
                {
                    string where = allowedDirs[0].Length == 0 ? _windowsDir : _windowsDir + allowedDirs[0];
                    Add(70, $"\"{name}\" gerçek bir Windows dosyasının adı; gerçeği yalnızca {where.TrimEnd('\\')} içinde bulunur. Bu kopya başka bir yerden çalışıyor: {path![..path!.LastIndexOf('\\')]}.");
                }
            }
            else if (KnownPrefixes.TryGetValue(name, out var prefixes) &&
                     !prefixes.Any(p => lowerPath.StartsWith(_systemDrive + p, StringComparison.Ordinal)))
            {
                Add(70, $"\"{name}\" Microsoft Defender'a ait bir ad ama Defender'ın klasöründen çalışmıyor.");
            }

            // --- unusual folders ---
            var risky = RiskyLocations.FirstOrDefault(l => lowerPath.Contains(l.Fragment, StringComparison.Ordinal));
            if (risky.Fragment is not null)
            {
                if (badSig) Add(25, $"İmzasız bir program {risky.Label} çalışıyor; zararlılar sık sık buralara yerleşir.");
                else if (sig == SignatureStatus.Unknown) Add(10, $"Program {risky.Label} çalışıyor.");
            }
            else if (badSig && !packaged)
            {
                var user = UserLocations.FirstOrDefault(l => lowerPath.Contains(l.Fragment, StringComparison.Ordinal));
                bool profileRoot = IsUserProfileRoot(dir);
                if (user.Fragment is not null || profileRoot)
                    Add(15, $"İmzasız bir program {(profileRoot ? "kullanıcı klasörünün kökünden" : user.Label)} çalışıyor.");
            }
        }

        // --- look-alike names ---
        string? lookalike = FindLookalike(name);
        if (lookalike is not null)
        {
            bool microsoftInSystem = dos && dir.StartsWith(_windowsDir, StringComparison.Ordinal) && sig == SignatureStatus.Signed;
            if (!microsoftInSystem)
            {
                Add(sig == SignatureStatus.Signed ? 25 : 60,
                    $"Adı, Windows'un \"{lookalike}\" dosyasına çok benziyor ama aynısı değil; zararlılar sık sık böyle taklit adlar kullanır.");
            }
        }

        // --- belge.pdf.exe ---
        if (DoubleExtension().IsMatch(name))
            Add(40, "Çift uzantılı dosya adı (ör. belge.pdf.exe): belge gibi görünen bir program.");

        // --- file deleted after start ---
        if (input.File == FileState.Missing && path is not null)
            Add(40, "Program çalışıyor ama dosyası diskte bulunamadı (çalıştıktan sonra silinmiş olabilir).");

        // --- no path at all ---
        if (path is null && input.HiddenSeverity == RiskLevel.None &&
            !KernelPseudoProcesses.Contains(rawName) && !OtherPathless.Contains(rawName))
            Add(5, "Dosya yolu okunamadı (korumalı sistem işlemlerinde bu normaldir).");

        return new RiskAssessment(LevelFor(score), score, reasons);
    }

    public static RiskLevel LevelFor(int score) =>
        score >= HighThreshold ? RiskLevel.High :
        score >= MediumThreshold ? RiskLevel.Medium :
        score > 0 ? RiskLevel.Low : RiskLevel.None;

    private bool IsUserProfileRoot(string dir)
    {
        // c:\users\<name>\
        string users = _systemDrive + @"users\";
        if (!dir.StartsWith(users, StringComparison.Ordinal)) return false;
        string rest = dir[users.Length..];
        return rest.Length > 1 && rest.IndexOf('\\') == rest.Length - 1;
    }

    private static string? FindLookalike(string skeletonName)
    {
        if (KnownLocations.ContainsKey(skeletonName) || KnownPrefixes.ContainsKey(skeletonName) ||
            LookalikeAllowList.Contains(skeletonName))
            return null;

        string candidate = NameNormalizer.LookalikeKey(StripExe(skeletonName));
        if (candidate.Length < 4) return null;

        foreach (var system in KnownLocations.Keys.Concat(KnownPrefixes.Keys))
        {
            string sys = NameNormalizer.LookalikeKey(StripExe(system));
            if (sys.Length < 4) continue;

            if (candidate == sys) return system; // e.g. svch0st -> svchost
            int distance = OsaDistance(candidate, sys);
            if (distance == 1) return system;
            if (distance == 2 && candidate.Length >= 7 && sys.Length >= 7) return system;
            if (HasArchitectureAffix(candidate, sys)) return system;
        }
        return null;
    }

    /// <summary>svchost32, explorer64, lsass_x64, x64svchost ...</summary>
    private static bool HasArchitectureAffix(string candidate, string sys)
    {
        static bool IsAffix(string s) => s.Length is > 0 and <= 4 && s.All(c => char.IsDigit(c) || c is 'x' or '_' or '-');
        if (candidate.StartsWith(sys, StringComparison.Ordinal) && IsAffix(candidate[sys.Length..])) return true;
        if (candidate.EndsWith(sys, StringComparison.Ordinal) && IsAffix(candidate[..^sys.Length])) return true;
        return false;
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

    private static string NormalizeDir(string dir) => dir.Replace('/', '\\').TrimEnd('\\').ToLowerInvariant() + @"\";
}
