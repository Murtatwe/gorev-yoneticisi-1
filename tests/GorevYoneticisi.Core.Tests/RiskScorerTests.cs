using System.Globalization;
using GorevYoneticisi.Core.Security;

namespace GorevYoneticisi.Core.Tests;

public class RiskScorerTests
{
    private readonly RiskScorer _scorer = new(windowsDirectory: @"C:\Windows");

    private static ProcessSecurityInput Input(
        string name, string? path, SignatureStatus sig = SignatureStatus.Signed,
        RiskLevel hidden = RiskLevel.None, FileState file = FileState.Exists,
        int? pid = 1000, int? parent = 500, string? signer = null) =>
        new(name, path, sig, signer ?? (sig == SignatureStatus.Signed ? "Microsoft Windows" : null),
            hidden, file, pid, parent);

    private RiskLevel Level(ProcessSecurityInput i) => _scorer.Assess(i).Level;

    // ---- clean, legitimate cases (false positive guards) ----

    [Theory]
    [InlineData("svchost.exe", @"C:\Windows\System32\svchost.exe")]
    [InlineData("explorer.exe", @"C:\Windows\explorer.exe")]
    [InlineData("rundll32.exe", @"C:\Windows\SysWOW64\rundll32.exe")]
    [InlineData("powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")]
    [InlineData("WmiPrvSE.exe", @"C:\Windows\System32\wbem\WmiPrvSE.exe")]
    [InlineData("chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe")]
    [InlineData("notepad.exe", @"C:\Windows\System32\notepad.exe")]
    [InlineData("MsMpEng.exe", @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe")]
    public void SignedLegitimateProcesses_AreClean(string name, string path)
    {
        Assert.Equal(RiskLevel.None, Level(Input(name, path)));
    }

    [Fact]
    public void PathComparisonIsCaseInsensitive()
    {
        Assert.Equal(RiskLevel.None, Level(Input("SVCHOST.EXE", @"c:\windows\system32\SVCHOST.EXE")));
    }

    [Fact]
    public void DefenderInProgramData_WithUnknownSignature_IsClean()
    {
        Assert.Equal(RiskLevel.None, Level(Input("MsMpEng.exe",
            @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1-0\MsMpEng.exe", SignatureStatus.Unknown)));
    }

    [Fact]
    public void UnknownSignature_IsNeverCalledUnsigned()
    {
        var r = _scorer.Assess(Input("x.exe", @"C:\ProgramData\Vendor\x.exe", SignatureStatus.Unknown));
        Assert.DoesNotContain(r.Reasons, x => x.Contains("imza", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void SignedAppInLocalAppData_IsClean()
    {
        Assert.Equal(RiskLevel.None, Level(Input("Discord.exe", @"C:\Users\ali\AppData\Local\Discord\app-1.0.9\Discord.exe", signer: "Discord Inc.")));
    }

    [Fact]
    public void StoreAppWithoutFileSignature_IsClean()
    {
        Assert.Equal(RiskLevel.None, Level(Input("ms-teams.exe",
            @"C:\Program Files\WindowsApps\MSTeams_24.1.0_x64__8wekyb3d8bbwe\ms-teams.exe", SignatureStatus.Unsigned)));
    }

    [Fact]
    public void KernelPseudoProcesses_WithoutPath_AreClean()
    {
        Assert.Equal(RiskLevel.None, Level(Input("System", null, SignatureStatus.Unknown, pid: 4, parent: 0)));
        Assert.Equal(RiskLevel.None, Level(Input("Registry", null, SignatureStatus.Unknown, pid: 120, parent: 4)));
        Assert.Equal(RiskLevel.None, Level(Input("Memory Compression", null, SignatureStatus.Unknown, pid: 3000, parent: 4)));
    }

    [Fact]
    public void NotYetCheckedSignature_DoesNotAddRisk()
    {
        Assert.Equal(RiskLevel.None, Level(Input("app.exe", @"C:\Program Files\App\app.exe", SignatureStatus.Unknown)));
    }

    [Fact]
    public void UnknownFileState_DoesNotAddRisk()
    {
        Assert.Equal(RiskLevel.None, Level(Input("app.exe", @"C:\Program Files\App\app.exe", file: FileState.Unknown)));
    }

    [Fact]
    public void NonDosPath_DoesNotTriggerLocationRules()
    {
        Assert.Equal(RiskLevel.None, Level(Input("svchost.exe", @"\Device\HarddiskVolume3\Windows\System32\svchost.exe")));
    }

    [Fact]
    public void RealNamesNearSystemNames_AreNotFlagged()
    {
        Assert.Equal(RiskLevel.None, Level(Input("taskhost.exe", @"C:\Windows\System32\taskhost.exe")));
        Assert.Equal(RiskLevel.None, Level(Input("dashost.exe", @"C:\Windows\System32\dashost.exe")));
    }

    // ---- risky cases ----

    [Fact]
    public void UnsignedAppInProgramFiles_IsLowWithReassurance()
    {
        var r = _scorer.Assess(Input("tool.exe", @"C:\Program Files\Tool\tool.exe", SignatureStatus.Unsigned));
        Assert.Equal(RiskLevel.Low, r.Level);
        Assert.Contains(r.Reasons, x => x.Contains("imza", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void UnsignedAppInTemp_IsMedium()
    {
        Assert.Equal(RiskLevel.Medium, Level(Input("x.exe", @"C:\Users\ali\AppData\Local\Temp\x.exe", SignatureStatus.Unsigned)));
    }

    [Fact]
    public void UnsignedAppInRoaming_IsMedium()
    {
        Assert.Equal(RiskLevel.Medium, Level(Input("updater.exe", @"C:\Users\ali\AppData\Roaming\abcd\updater.exe", SignatureStatus.Unsigned)));
    }

    [Fact]
    public void SystemNameOutsideSystem32_IsHigh()
    {
        var r = _scorer.Assess(Input("svchost.exe", @"C:\Users\ali\AppData\Roaming\svchost.exe", SignatureStatus.Unsigned));
        Assert.Equal(RiskLevel.High, r.Level);
        Assert.Contains(r.Reasons, x => x.Contains("svchost.exe"));
    }

    [Fact]
    public void LsassInSysWow64_IsHigh()
    {
        Assert.Equal(RiskLevel.High, Level(Input("lsass.exe", @"C:\Windows\SysWOW64\lsass.exe")));
    }

    [Fact]
    public void SystemNameInWindowsRoot_IsHigh()
    {
        Assert.Equal(RiskLevel.High, Level(Input("svchost.exe", @"C:\Windows\svchost.exe", SignatureStatus.Unsigned)));
    }

    [Theory]
    [InlineData("scvhost.exe")]
    [InlineData("svch0st.exe")]
    [InlineData("lsas.exe")]
    [InlineData("csrsss.exe")]
    [InlineData("svchost32.exe")]
    [InlineData("explorer64.exe")]
    [InlineData("ѕvсhost.exe")] // Cyrillic ѕ and с
    public void LookalikeOfSystemName_IsFlagged(string name)
    {
        var r = _scorer.Assess(Input(name, $@"C:\ProgramData\{name}", SignatureStatus.Unsigned));
        Assert.Equal(RiskLevel.High, r.Level);
    }

    [Theory]
    [InlineData("svchost.exe ")]
    [InlineData("svchost.exe.")]
    [InlineData("fatura\u202Efdp.exe")]
    [InlineData("sv\u200Bchost.exe")]
    public void MisleadingCharactersInName_AreHigh(string name)
    {
        var r = _scorer.Assess(Input(name, $@"C:\Users\ali\Downloads\{name}", SignatureStatus.Unsigned));
        Assert.Equal(RiskLevel.High, r.Level);
    }

    [Theory]
    [InlineData("fatura.pdf.exe")]
    [InlineData("belge.pdf      .exe")]
    [InlineData("RESIM.JPG.SCR")]
    public void DoubleExtension_IsFlagged(string name)
    {
        var r = _scorer.Assess(Input(name, $@"C:\Users\ali\Downloads\{name}", SignatureStatus.Unsigned));
        Assert.Equal(RiskLevel.High, r.Level);
        Assert.Contains(r.Reasons, x => x.Contains("uzantı"));
    }

    [Fact]
    public void DoubleExtension_WorksUnderTurkishCulture()
    {
        var old = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");
            var r = _scorer.Assess(Input("FATURA.PDF.PIF", @"C:\Users\ali\Downloads\FATURA.PDF.PIF", SignatureStatus.Unsigned));
            Assert.Contains(r.Reasons, x => x.Contains("uzantı"));
        }
        finally
        {
            CultureInfo.CurrentCulture = old;
        }
    }

    [Fact]
    public void HiddenHigh_IsAlwaysHigh()
    {
        Assert.Equal(RiskLevel.High, Level(Input("chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe", hidden: RiskLevel.High)));
    }

    [Fact]
    public void HiddenLow_IsOnlyLow()
    {
        Assert.Equal(RiskLevel.Low, Level(Input("chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe", hidden: RiskLevel.Low)));
    }

    [Fact]
    public void ExpiredSignature_IsOnlyLow()
    {
        var r = _scorer.Assess(Input("oldtool.exe", @"C:\Program Files\Old\oldtool.exe", SignatureStatus.Expired));
        Assert.Equal(RiskLevel.Low, r.Level);
        Assert.DoesNotContain(r.Reasons, x => x.Contains("güvenmiyor"));
    }

    [Fact]
    public void InvalidSignature_IsHigh()
    {
        Assert.Equal(RiskLevel.High, Level(Input("app.exe", @"C:\Program Files\App\app.exe", SignatureStatus.Invalid)));
    }

    [Fact]
    public void ConfirmedMissingExecutable_IsMedium()
    {
        Assert.Equal(RiskLevel.Medium, Level(Input("app.exe", @"C:\Program Files\App\app.exe", SignatureStatus.Unknown, file: FileState.Missing)));
    }

    [Fact]
    public void FakeSystemProcess_NotPid4_IsHigh()
    {
        Assert.Equal(RiskLevel.High, Level(Input("System", null, SignatureStatus.Unknown, pid: 9000, parent: 1234)));
    }

    [Fact]
    public void UnreadablePath_ForOrdinaryProcess_IsLowWithCalmWording()
    {
        var r = _scorer.Assess(Input("something.exe", null, SignatureStatus.Unknown));
        Assert.Equal(RiskLevel.Low, r.Level);
        Assert.Contains(r.Reasons, x => x.Contains("normal"));
    }
}

public class NameNormalizationTests
{
    [Theory]
    [InlineData("svchost.exe", "svchost.exe")]
    [InlineData("SVCHOST.EXE", "svchost.exe")]
    [InlineData("svchost.exe  ", "svchost.exe")]
    [InlineData("ѕvсhоѕt.exe", "svchost.exe")]
    [InlineData("sv\u200Bchost.exe", "svchost.exe")]
    public void SkeletonRemovesTricks(string raw, string expected)
    {
        Assert.Equal(expected, NameNormalizer.Skeleton(raw));
    }

    [Theory]
    [InlineData("svchost.exe", false)]
    [InlineData("svchost.exe ", true)]
    [InlineData("a\u202Eb.exe", true)]
    [InlineData("ѕvchost.exe", true)]
    [InlineData("Müzik Çalar.exe", false)] // Turkish letters are legitimate
    public void DetectsMisleadingCharacters(string raw, bool expected)
    {
        Assert.Equal(expected, NameNormalizer.HasMisleadingCharacters(raw));
    }
}
