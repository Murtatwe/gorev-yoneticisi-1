using GorevYoneticisi.Core;
using GorevYoneticisi.Core.Metrics;
using GorevYoneticisi.Core.Security;

namespace GorevYoneticisi.Core.Tests;

public class CommandLineTests
{
    [Theory]
    [InlineData("\"C:\\Program Files\\App\\app.exe\" --tray", @"C:\Program Files\App\app.exe")]
    [InlineData(@"C:\Tools\tool.exe /silent", @"C:\Tools\tool.exe")]
    [InlineData(@"C:\Program Files\My App\app.exe /s", @"C:\Program Files\My App\app.exe")]
    [InlineData(@"C:\x\y.exe", @"C:\x\y.exe")]
    [InlineData(@"rundll32.exe C:\Users\a\evil.dll,Start", @"C:\Users\a\evil.dll")]
    [InlineData(@"C:\Windows\System32\rundll32.exe ""C:\p q\lib.dll"",Entry", @"C:\p q\lib.dll")]
    [InlineData(@"""C:\x\a.bat""", @"C:\x\a.bat")]
    [InlineData(@"C:\scripts\run.cmd arg", @"C:\scripts\run.cmd")]
    public void ExtractsExecutablePath(string command, string expected)
    {
        Assert.Equal(expected, CommandLine.ExtractTarget(command));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void EmptyCommandReturnsNull(string command)
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
    public void NormalizesCommonPrefixes(string input, string expected)
    {
        Assert.Equal(expected, DevicePaths.ToDosPath(input, new Dictionary<string, string>(), windowsDirectory: @"C:\Windows"));
    }
}
