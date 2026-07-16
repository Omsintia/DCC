using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// Shows an element exactly while its bound VM message is present (F1): the
/// Configuration editor's banners (Conflict, HelperIncompatible, RestartFailed,
/// ProxyRejected, SaveError, SaveNotice, blocked-save, LoadError) are all "null =
/// hidden" string properties per E3, so one converter covers them all. Null and
/// blank/whitespace strings collapse; anything else — including non-string values —
/// is visible.
/// </summary>
public sealed class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        null => Visibility.Collapsed,
        string s when string.IsNullOrWhiteSpace(s) => Visibility.Collapsed,
        _ => Visibility.Visible,
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException($"{nameof(NullToVisibilityConverter)} is one-way only.");
}
