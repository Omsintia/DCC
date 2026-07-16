using System.Globalization;
using System.Windows.Data;
using DnsCryptControl.UI.Models;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// Supplies the Dashboard's helper banner (D1/F20) title/message pair for whichever of the
/// two blocking helper states is active — <see cref="ProtectionStatusView.HelperUnavailable"/>
/// (no helper reachable) or <see cref="ProtectionStatusView.HelperIncompatible"/> (a helper
/// answered, but on a different <c>IpcProtocol.Version</c> — its other fields are never
/// trusted, so this is guidance, not a status readout). <paramref name="parameter"/>
/// selects which half of the pair to return: <c>"Title"</c> or <c>"Message"</c> (anything
/// else returns the message). Kept in the view layer so <see cref="ProtectionStatusView"/>
/// and the VM stay pure POCOs with no display-string concerns.
/// </summary>
public sealed class ProtectionStatusToHelperBannerMessageConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var wantsTitle = string.Equals(parameter as string, "Title", StringComparison.Ordinal);

        return value switch
        {
            ProtectionStatusView.HelperIncompatible => wantsTitle
                ? "Helper version incompatible"
                : "The helper is a different version — update the app/helper.",
            _ => wantsTitle
                ? "Helper service unavailable"
                : "The DnsCryptControl helper service isn't running. Start it (installer / dev-install script), then re-check.",
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException($"{nameof(ProtectionStatusToHelperBannerMessageConverter)} is one-way only.");
}
