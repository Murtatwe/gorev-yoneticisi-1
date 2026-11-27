using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using GorevYoneticisi.Core.Security;

namespace GorevYoneticisi.App.Ui;

public static class RiskColors
{
    public static readonly SolidColorBrush High = Freeze(Color.FromRgb(0xE5, 0x48, 0x4D));
    public static readonly SolidColorBrush Medium = Freeze(Color.FromRgb(0xF5, 0xA5, 0x24));
    public static readonly SolidColorBrush Low = Freeze(Color.FromRgb(0xC9, 0xB8, 0x4A));
    public static readonly SolidColorBrush None = Freeze(Color.FromRgb(0x46, 0xA7, 0x58));

    public static SolidColorBrush For(RiskLevel level) => level switch
    {
        RiskLevel.High => High,
        RiskLevel.Medium => Medium,
        RiskLevel.Low => Low,
        _ => None,
    };

    public static string Text(RiskLevel level) => level switch
    {
        RiskLevel.High => "Yüksek risk",
        RiskLevel.Medium => "Orta risk",
        RiskLevel.Low => "Düşük risk",
        _ => "Temiz",
    };

    private static SolidColorBrush Freeze(Color c)
    {
        var b = new SolidColorBrush(c);
        b.Freeze();
        return b;
    }
}

public sealed class RiskBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is RiskLevel l ? RiskColors.For(l) : Brushes.Transparent;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class RiskTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is RiskLevel l ? RiskColors.Text(l) : "";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool b = value is true;
        if (Invert) b = !b;
        return b ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class NullToVisibilityConverter : IValueConverter
{
    /// <summary>When true: visible only when the value IS null/empty.</summary>
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool empty = value is null || value is string { Length: 0 };
        return empty ^ Invert ? Visibility.Collapsed : Visibility.Visible;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Maps a 0-100 percentage to a width, using the converter parameter as the full width.</summary>
public sealed class PercentToWidthConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        double full = parameter is string s && double.TryParse(s, NumberStyles.Any, CultureInfo.InvariantCulture, out double f) ? f : 100;
        double pct = value is double d ? d : 0;
        return Math.Max(0, Math.Min(100, pct)) / 100.0 * full;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class ZeroToVisibleConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is int i && i == 0 ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}
