using System.Globalization;
using System.Windows.Data;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// Renders a boolean as a short, human word for the Logs &amp; Diagnostics health snapshot: <c>true</c> →
/// "yes", anything else → "no". A <c>ConverterParameter</c> of "run" swaps the vocabulary to
/// "running"/"stopped" (used for the proxy state).
/// </summary>
public sealed class BooleanToYesNoConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var on = value is true;
        return (parameter as string) == "run"
            ? (on ? "running" : "stopped")
            : (on ? "yes" : "no");
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        (value as string) is "yes" or "running";
}
