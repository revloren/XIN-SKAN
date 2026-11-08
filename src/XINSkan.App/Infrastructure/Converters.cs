using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace XINSkan.App.Infrastructure;

/// <summary>true → visible; with ConverterParameter "invert" → collapsed.</summary>
public sealed class BoolToVisibility : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var b = value is true;
        if (parameter is "invert")
        {
            b = !b;
        }

        return b ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Empty string → visible (placeholders over empty fields).</summary>
public sealed class EmptyToVisibility : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is null || (value is string s && s.Length == 0) ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>null or empty → collapsed.</summary>
public sealed class NullToVisibility : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is null || (value is string s && s.Length == 0) ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Available capability → ok colour; missing → warning colour (missing rights limit, not break, a check).</summary>
public sealed class AvailabilityBrush : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        Application.Current.FindResource(value is true ? "OkBrush" : "WarnBrush");

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Ready module → text colour; planned → muted.</summary>
public sealed class ReadyBrush : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        Application.Current.FindResource(value is true ? "OkBrush" : "MutedBrush");

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Integrity state → colour.</summary>
public sealed class IntegrityBrush : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => Application.Current.FindResource(value switch
    {
        Services.IntegrityState.Verified => "OkBrush",
        Services.IntegrityState.NotClosed => "WarnBrush",
        _ => "FailBrush",
    });

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Formats a large count with thin-space grouping.</summary>
public sealed class CountFormat : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is long l ? l.ToString("N0", CultureInfo.GetCultureInfo("ru-RU")) : value?.ToString() ?? string.Empty;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
