using System.Globalization;
using System.Windows.Data;
using DnsCryptControl.UI.Models;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// Maps the Dashboard's truthful <see cref="ProtectionStatusView"/> to the human-readable
/// label shown on the status <c>ui:Badge</c> (C2). Kept in the view layer, alongside
/// <see cref="ProtectionStatusToAppearanceConverter"/>, so the view-model stays a pure
/// POCO with no display-string concerns.
/// </summary>
public sealed class ProtectionStatusToTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        ProtectionStatusView.ProtectedVerified => "Protected",
        ProtectionStatusView.Applying => "Applying…",
        ProtectionStatusView.Verifying => "Verifying…",
        ProtectionStatusView.PartiallyProtected => "Partially protected — leak detected",
        ProtectionStatusView.ProxyStopped => "Proxy stopped",
        ProtectionStatusView.DiagnosticsUnavailable => "Protected — verifying DNS…",
        ProtectionStatusView.HelperUnavailable => "Helper unavailable",
        ProtectionStatusView.HelperIncompatible => "Helper version incompatible",
        ProtectionStatusView.Unprotected => "Not protected",
        _ => "Unknown",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException($"{nameof(ProtectionStatusToTextConverter)} is one-way only.");
}
