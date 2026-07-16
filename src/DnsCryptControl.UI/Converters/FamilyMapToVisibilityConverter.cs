using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// The visibility companion to <see cref="FamilyMapLookupConverter"/> (Phase 5d, D1): looks a keyed
/// entry out of a per-family / per-key map by the fixed <c>ConverterParameter</c> and returns
/// <see cref="Visibility.Visible"/> exactly when that entry is present and non-blank, else
/// <see cref="Visibility.Collapsed"/>. A per-family honesty banner binds its <c>Message</c> through
/// <see cref="FamilyMapLookupConverter"/> and its <c>Visibility</c> through this — so a family with no
/// entry for that surface (the common case) hides its banner, and only the one family the message
/// belongs to shows it. Keys match by <see cref="object.ToString"/> so an enum key
/// (<c>RuleFamily.BlockedNames</c>) and a string parameter resolve. One-way only (IC-5).
/// </summary>
public sealed class FamilyMapToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not IDictionary map || parameter is not string wantKey)
        {
            return Visibility.Collapsed;
        }

        foreach (DictionaryEntry entry in map)
        {
            if (string.Equals(entry.Key?.ToString(), wantKey, StringComparison.Ordinal))
            {
                return entry.Value is string s && !string.IsNullOrWhiteSpace(s)
                    ? Visibility.Visible
                    : Visibility.Collapsed;
            }
        }

        return Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException($"{nameof(FamilyMapToVisibilityConverter)} is one-way only.");
}
