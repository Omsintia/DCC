using System.Globalization;
using System.Windows.Data;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// Text for the structured pane's deprecation chip (F1): binds the entry's
/// <c>ReplacedBy</c> (nullable in the catalog) and renders
/// "deprecated — use {ReplacedBy}", or plain "deprecated" when the catalog names no
/// replacement. The chip's VISIBILITY is driven separately by the entry's
/// <c>Deprecated</c> flag.
/// </summary>
public sealed class DeprecatedChipTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is string replacedBy && replacedBy.Length > 0
            ? "deprecated — use " + replacedBy
            : "deprecated";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException($"{nameof(DeprecatedChipTextConverter)} is one-way only.");
}
