using System.Collections;
using System.Globalization;
using System.Windows.Data;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// Looks one entry out of a keyed map by a fixed key supplied as the <c>ConverterParameter</c>
/// (Phase 5d, D1). The Filtering tab's honesty/notice surfaces (external-path, empty-but-wired,
/// staleness, per-family notice/error) live on <c>FilteringViewModel</c> as
/// <c>IReadOnlyDictionary&lt;RuleFamily,string&gt;</c>, and the toggle projection as
/// <c>IReadOnlyDictionary&lt;string,object?&gt;</c>. Each per-family section (or per-key toggle)
/// binds the whole map as the value and names its own key as the parameter (a string). The lookup
/// matches by comparing each key's <see cref="object.ToString"/> to the parameter, so an enum key
/// (<c>RuleFamily.BlockedNames</c> ⇄ <c>"BlockedNames"</c>) and a string key both resolve without
/// the view needing to construct the enum value. A present entry returns its value; an absent key —
/// the common "no banner" case — returns <see langword="null"/>, so the same <c>NullToVisibility</c>
/// pattern hides the section's banner. One-way only; the map is never mutated through the view (IC-5).
/// </summary>
public sealed class FamilyMapLookupConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not IDictionary map || parameter is not string wantKey)
        {
            return null;
        }

        foreach (DictionaryEntry entry in map)
        {
            if (string.Equals(entry.Key?.ToString(), wantKey, StringComparison.Ordinal))
            {
                return entry.Value;
            }
        }

        return null;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException($"{nameof(FamilyMapLookupConverter)} is one-way only.");
}
