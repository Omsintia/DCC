using System.Globalization;
using System.Windows.Data;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// Negates a boolean (Phase 5c views): <c>IsEnabled = !IsRoutesReadOnly</c> etc. Non-bool /
/// null inputs are treated as <c>false</c> (so the negation is <c>true</c>) — a fail-open
/// default is correct for the enable-editing bindings that use this.
/// </summary>
public sealed class InverseBooleanConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is not true;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is not true;
}
