using System.Globalization;
using System.Windows.Data;
using DnsCryptControl.UI.Models;
using Wpf.Ui.Controls;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// Maps the Dashboard's truthful <see cref="ProtectionStatusView"/> to the WPF-UI
/// <see cref="ControlAppearance"/> used by the status <c>ui:Badge</c> (C2). This mapping
/// is intentionally a view-layer concern: <see cref="ProtectionStatusView"/> itself is a
/// pure POCO enum with no WPF dependency, so the presentation choice — which color reads
/// as "safe" — lives here, not on the view-model.
/// </summary>
public sealed class ProtectionStatusToAppearanceConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        ProtectionStatusView.ProtectedVerified => ControlAppearance.Success,
        ProtectionStatusView.Applying => ControlAppearance.Caution,
        ProtectionStatusView.Verifying => ControlAppearance.Caution,
        ProtectionStatusView.PartiallyProtected => ControlAppearance.Caution,
        ProtectionStatusView.ProxyStopped => ControlAppearance.Caution,
        ProtectionStatusView.DiagnosticsUnavailable => ControlAppearance.Caution,
        ProtectionStatusView.HelperUnavailable => ControlAppearance.Danger,
        ProtectionStatusView.HelperIncompatible => ControlAppearance.Danger,
        ProtectionStatusView.Unprotected => ControlAppearance.Secondary,
        _ => ControlAppearance.Secondary,
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException($"{nameof(ProtectionStatusToAppearanceConverter)} is one-way only.");
}
