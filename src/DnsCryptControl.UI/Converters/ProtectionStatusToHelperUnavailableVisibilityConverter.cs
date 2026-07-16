using System.Globalization;
using System.Windows;
using System.Windows.Data;
using DnsCryptControl.UI.Models;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// Drives the visibility of the Dashboard's "helper unavailable" banner (D1). The
/// unprivileged UI can never install/start the SYSTEM helper itself, so when
/// <see cref="ProtectionStatusView.HelperUnavailable"/> is observed the view shows a
/// prominent banner explaining that the helper service must be started out-of-band
/// (installer / dev-install script) plus a "Re-check" action. The banner ALSO shows for
/// <see cref="ProtectionStatusView.HelperIncompatible"/> (F20) — a version-mismatched
/// helper is just as blocking as no helper at all, it just needs different guidance (see
/// <see cref="ProtectionStatusToHelperBannerMessageConverter"/>). Every other status —
/// including the transient <see cref="ProtectionStatusView.Applying"/> state — collapses
/// it. Kept in the view layer so <see cref="ProtectionStatusView"/> and the VM stay pure
/// POCOs with no <see cref="Visibility"/> dependency.
/// </summary>
public sealed class ProtectionStatusToHelperUnavailableVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        ProtectionStatusView.HelperUnavailable => Visibility.Visible,
        ProtectionStatusView.HelperIncompatible => Visibility.Visible,
        _ => Visibility.Collapsed,
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException($"{nameof(ProtectionStatusToHelperUnavailableVisibilityConverter)} is one-way only.");
}
