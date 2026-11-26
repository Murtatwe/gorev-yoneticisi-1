using GorevYoneticisi.Core.Security;

namespace GorevYoneticisi.Core.Tests;

public class RiskScorerTests
{
    private readonly RiskScorer _scorer = new(windowsDirectory: @"C:\Windows");

    private static ProcessSecurityInput Input(
        string name, string? path, SignatureStatus sig = SignatureStatus.Signed,
        bool hidden = false, bool fileExists = true) =>
        new(name, path, sig, Signer: sig == SignatureStatus.Signed ? "Microsoft Windows" : null,
            IsHidden: hidden, FileExists: fileExists);

    [Fact]
    public void SignedSystemProcessInSystem32_IsClean()
    {
        var r = _scorer.Assess(Input("svchost.exe", @"C:\Windows\System32\svchost.exe"));
        Assert.Equal(RiskLevel.None, r.Level);
        Assert.Empty(r.Reasons);
    }

    [Fact]
    public void SignedAppInProgramFiles_IsClean()
    {
        Assert.Equal(RiskLevel.None, _scorer.Assess(Input("chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe")).Level);
    }

    [Fact]
    public void UnsignedAppInProgramFiles_IsLow()
    {
        var r = _scorer.Assess(Input("tool.exe", @"C:\Program Files\Tool\tool.exe", SignatureStatus.Unsigned));
        Assert.Equal(RiskLevel.Low, r.Level);
        Assert.Contains(r.Reasons, x => x.Contains("imza", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void UnsignedAppInTemp_IsMedium()
    {
        var r = _scorer.Assess(Input("x.exe", @"C:\Users\ali\AppData\Local\Temp\x.exe", SignatureStatus.Unsigned));
        Assert.True(r.Level >= RiskLevel.Medium);
    }

    [Fact]
    public void SystemNameOutsideSystem32_IsHigh()
    {
        var r = _scorer.Assess(Input("svchost.exe", @"C:\Users\ali\AppData\Roaming\svchost.exe", SignatureStatus.Unsigned));
        Assert.Equal(RiskLevel.High, r.Level);
        Assert.Contains(r.Reasons, x => x.Contains("svchost.exe"));
    }

    [Fact]
    public void ExplorerInWindowsDirectory_IsClean()
    {
        Assert.Equal(RiskLevel.None, _scorer.Assess(Input("explorer.exe", @"C:\Windows\explorer.exe")).Level);
    }

    [Fact]
    public void SysWow64SystemBinary_IsClean()
    {
        Assert.Equal(RiskLevel.None, _scorer.Assess(Input("rundll32.exe", @"C:\Windows\SysWOW64\rundll32.exe")).Level);
    }

    [Theory]
    [InlineData("scvhost.exe")]
    [InlineData("svch0st.exe")]
    [InlineData("lsas.exe")]
    [InlineData("csrsss.exe")]
    public void LookalikeOfSystemName_IsFlagged(string name)
    {
        var r = _scorer.Assess(Input(name, $@"C:\ProgramData\{name}", SignatureStatus.Unsigned));
        Assert.Equal(RiskLevel.High, r.Level);
        Assert.Contains(r.Reasons, x => x.Contains("benziyor"));
    }

    [Fact]
    public void LookalikeRule_DoesNotFlagUnrelatedShortNames()
    {
        // "lsm.exe" vs "lsass.exe" is distance 2; "dwm.exe" exact; ordinary names must not be flagged.
        var r = _scorer.Assess(Input("notepad.exe", @"C:\Windows\System32\notepad.exe"));
        Assert.Equal(RiskLevel.None, r.Level);
    }

    [Fact]
    public void HiddenProcess_IsAlwaysHigh()
    {
        var r = _scorer.Assess(Input("chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe", hidden: true));
        Assert.Equal(RiskLevel.High, r.Level);
    }

    [Fact]
    public void InvalidSignature_IsHigh()
    {
        Assert.Equal(RiskLevel.High, _scorer.Assess(Input("app.exe", @"C:\Program Files\App\app.exe", SignatureStatus.Invalid)).Level);
    }

    [Fact]
    public void DoubleExtension_IsFlagged()
    {
        var r = _scorer.Assess(Input("fatura.pdf.exe", @"C:\Users\ali\Downloads\fatura.pdf.exe", SignatureStatus.Unsigned));
        Assert.Equal(RiskLevel.High, r.Level);
        Assert.Contains(r.Reasons, x => x.Contains("uzantı"));
    }

    [Fact]
    public void DeletedExecutable_IsFlagged()
    {
        var r = _scorer.Assess(Input("app.exe", @"C:\Program Files\App\app.exe", SignatureStatus.Unknown, fileExists: false));
        Assert.True(r.Level >= RiskLevel.Medium);
    }

    [Fact]
    public void UnknownPath_ForKnownProtectedProcess_IsClean()
    {
        Assert.Equal(RiskLevel.None, _scorer.Assess(Input("Registry", null, SignatureStatus.Unknown)).Level);
        Assert.Equal(RiskLevel.None, _scorer.Assess(Input("System", null, SignatureStatus.Unknown)).Level);
    }

    [Fact]
    public void NotYetCheckedSignature_DoesNotAddRisk()
    {
        Assert.Equal(RiskLevel.None, _scorer.Assess(Input("app.exe", @"C:\Program Files\App\app.exe", SignatureStatus.Unknown)).Level);
    }

    [Fact]
    public void PathComparisonIsCaseInsensitive()
    {
        Assert.Equal(RiskLevel.None, _scorer.Assess(Input("SVCHOST.EXE", @"c:\windows\system32\SVCHOST.EXE")).Level);
    }
}
