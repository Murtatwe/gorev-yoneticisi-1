using System.Globalization;

namespace GorevYoneticisi.Core;

/// <summary>Turkish, culture-independent display formatting (does not depend on installed ICU data).</summary>
public static class Format
{
    private static readonly string[] Units = { "B", "KB", "MB", "GB", "TB", "PB" };

    public static string Bytes(long bytes) => Bytes((double)bytes);

    public static string Bytes(double bytes)
    {
        if (double.IsNaN(bytes) || bytes <= 0) return "0 B";
        if (bytes < 1024) return $"{Math.Round(bytes):0} B";
        int unit = 0;
        while (bytes >= 1024 && unit < Units.Length - 1)
        {
            bytes /= 1024;
            unit++;
        }
        return $"{Number(bytes, 1, keepDecimals: true)} {Units[unit]}";
    }

    public static string Rate(double bytesPerSecond) => Bytes(bytesPerSecond) + "/sn";

    public static string Percent(double value)
    {
        if (double.IsNaN(value) || value < 0) value = 0;
        return "%" + Number(value, 1, keepDecimals: false);
    }

    public static string Duration(TimeSpan t)
    {
        if (t < TimeSpan.Zero) t = TimeSpan.Zero;
        if (t.TotalSeconds < 60) return $"{(int)t.TotalSeconds} sn";
        if (t.TotalHours < 1) return $"{t.Minutes} dk {t.Seconds} sn";
        if (t.TotalDays < 1) return $"{(int)t.TotalHours} sa {t.Minutes} dk";
        return $"{(int)t.TotalDays} gün {t.Hours} sa {t.Minutes} dk";
    }

    /// <summary>Formats with a decimal comma. When <paramref name="keepDecimals"/> is false, ".0" is dropped.</summary>
    public static string Number(double value, int decimals, bool keepDecimals)
    {
        double rounded = Math.Round(value, decimals, MidpointRounding.AwayFromZero);
        string pattern = keepDecimals || rounded != Math.Floor(rounded)
            ? "0." + new string('0', decimals)
            : "0";
        return rounded.ToString(pattern, CultureInfo.InvariantCulture).Replace('.', ',');
    }
}
