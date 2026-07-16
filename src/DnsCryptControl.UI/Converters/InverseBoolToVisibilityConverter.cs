using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// Maps a boolean to <see cref="Visibility"/> INVERTED: <c>true → Collapsed</c>, <c>false → Visible</c>.
/// The Filtering list⇄raw editor binds the structured list's <c>Border.Visibility</c> to the "Raw text"
/// toggle's <c>IsChecked</c> so the list HIDES when raw is selected; the built-in
/// <c>BooleanToVisibilityConverter</c> (used for the raw editor's own Visibility) is the non-inverted
/// counterpart. Note: <see cref="InverseBooleanConverter"/> returns a <see cref="bool"/> (for
/// <c>IsEnabled</c> bindings) and must NOT be bound to a <see cref="Visibility"/> target — that mismatch
/// leaves the target at its default <c>Visible</c>. Non-bool / null is treated as <c>false</c> (Visible) —
/// a fail-safe that shows the list.
/// </summary>
public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is Visibility.Collapsed;
}
