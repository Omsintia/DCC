using System.Globalization;
using System.Windows.Data;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// The Configuration editor's StringArray projection (F1): a TOML string array is
/// edited as a one-per-line multiline <c>TextBox</c>. <see cref="Convert"/> renders the
/// current <c>IReadOnlyList&lt;string&gt;</c> value one item per line;
/// <see cref="ConvertBack"/>/<see cref="ParseLines"/> turn the edited text back into an
/// array — each line trimmed, blank lines dropped (so a trailing newline never commits
/// an empty element), and empty text committing an EMPTY array (A2's pinned
/// <c>SetStringArray([]) → []</c>), never <c>[""]</c>. The commit path is Explicit
/// (the view's code-behind calls <see cref="ParseLines"/> on focus loss), so both
/// directions live here as tested logic per the plan's TDD-honesty rule.
/// </summary>
public sealed class StringArrayToLinesConverter : IValueConverter
{
    /// <summary>One item per line; empty array → empty text.</summary>
    public static string ToLines(IReadOnlyList<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        return string.Join(Environment.NewLine, values);
    }

    /// <summary>Splits on line breaks (CRLF or LF), trims every line, drops blanks.</summary>
    public static IReadOnlyList<string> ParseLines(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return text
            .Split('\n')
            .Select(static line => line.Trim())
            .Where(static line => line.Length > 0)
            .ToArray();
    }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is IReadOnlyList<string> values ? ToLines(values) : string.Empty;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is string text ? ParseLines(text) : Array.Empty<string>();
}
