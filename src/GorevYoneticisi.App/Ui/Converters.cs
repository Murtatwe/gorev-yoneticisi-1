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

    // "Temiz" would promise more than a heuristic can know; "no problem seen" is honest.
    public static string Text(RiskLevel level) => level switch
    {
        RiskLevel.High => "Yüksek risk",
        RiskLevel.Medium => "Dikkat",
        RiskLevel.Low => "Düşük risk",
        _ => "Sorun görülmedi",
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
    /// <summary>When true, "no risk" is transparent so only flagged rows carry colour.</summary>
    public bool HideNone { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is RiskLevel l ? (HideNone && l == RiskLevel.None ? Brushes.Transparent : RiskColors.For(l)) : Brushes.Transparent;

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

/// <summary>True when the risk level is at least Medium (for warning icons; colour alone is not enough).</summary>
public sealed class RiskAtLeastMediumToVisibility : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is RiskLevel l && l >= RiskLevel.Medium ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>
/// Cell heat colour like Task Manager: the accent colour with opacity proportional to the value.
/// ConverterParameter = value treated as 100% (default 100).
/// </summary>
public sealed class HeatBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush[] Steps = Enumerable.Range(0, 11).Select(i =>
    {
        var b = new SolidColorBrush(Color.FromArgb((byte)(i * 0.045 * 255), 0x4C, 0x9A, 0xFF));
        b.Freeze();
        return b;
    }).ToArray();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        double full = parameter is string s && double.TryParse(s, NumberStyles.Any, CultureInfo.InvariantCulture, out double f) ? f : 100;
        double v = value switch { double d => d, long l => l, int i => i, _ => 0 };
        if (v <= 0 || full <= 0) return Brushes.Transparent;
        int step = (int)Math.Ceiling(Math.Min(1, v / full) * 10);
        return Steps[Math.Clamp(step, 0, 10)];
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Gives elements outside the visual tree (DataGrid column headers, context menus) access to a DataContext.</summary>
public sealed class BindingProxy : Freezable
{
    public static readonly DependencyProperty DataProperty =
        DependencyProperty.Register(nameof(Data), typeof(object), typeof(BindingProxy));

    public object? Data { get => GetValue(DataProperty); set => SetValue(DataProperty, value); }

    protected override Freezable CreateInstanceCore() => new BindingProxy();
}

public sealed class InverseBool : IValueConverter
{
    public static readonly InverseBool Instance = new();
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is not true;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => value is not true;
}

public sealed class NotNull : IValueConverter
{
    public static readonly NotNull Instance = new();
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is not null && value is not string { Length: 0 };
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}
