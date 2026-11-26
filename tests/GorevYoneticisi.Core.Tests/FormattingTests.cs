using GorevYoneticisi.Core;

namespace GorevYoneticisi.Core.Tests;

public class FormattingTests
{
    [Theory]
    [InlineData(0, "0 B")]
    [InlineData(512, "512 B")]
    [InlineData(1024, "1,0 KB")]
    [InlineData(1536, "1,5 KB")]
    [InlineData(1048576, "1,0 MB")]
    [InlineData(5368709120, "5,0 GB")]
    [InlineData(1099511627776, "1,0 TB")]
    public void Bytes_UsesBinaryUnitsAndTurkishDecimalComma(long bytes, string expected)
    {
        Assert.Equal(expected, Format.Bytes(bytes));
    }

    [Fact]
    public void Bytes_NegativeIsTreatedAsZero()
    {
        Assert.Equal("0 B", Format.Bytes(-5));
    }

    [Theory]
    [InlineData(0, "0 B/sn")]
    [InlineData(2048, "2,0 KB/sn")]
    public void Rate_AppendsPerSecond(double bytesPerSecond, string expected)
    {
        Assert.Equal(expected, Format.Rate(bytesPerSecond));
    }

    [Theory]
    [InlineData(0, "%0")]
    [InlineData(12.345, "%12,3")]
    [InlineData(100, "%100")]
    [InlineData(0.04, "%0")]
    public void Percent_UsesTurkishPrefixStyle(double value, string expected)
    {
        Assert.Equal(expected, Format.Percent(value));
    }

    [Theory]
    [InlineData(59, "59 sn")]
    [InlineData(61, "1 dk 1 sn")]
    [InlineData(3600, "1 sa 0 dk")]
    [InlineData(90061, "1 gün 1 sa 1 dk")]
    public void Duration_IsHumanReadableTurkish(int seconds, string expected)
    {
        Assert.Equal(expected, Format.Duration(TimeSpan.FromSeconds(seconds)));
    }
}
