using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using DnsCryptControl.UI.Models;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// 5h (Dashboard visual polish): maps the protection status to an accent brush for the
/// title-bar status dot and the hero banner tint. Mid-tone colours read on BOTH themes
/// (they sit over theme surfaces via alpha), so no per-theme resource pair is needed.
/// Honesty discipline unchanged: green is reserved for the diagnostics-verified status —
/// every other state gets amber (transitional), red (helper trouble) or neutral gray.
/// ConverterParameter selects the role: "Dot" (solid), "HeroBackground" (low-alpha tint),
/// "HeroBorder" (mid-alpha tint).
/// </summary>
public sealed class ProtectionStatusToBrushConverter : IValueConverter
{
    private static SolidColorBrush Frozen(byte a, byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(Color.FromArgb(a, r, g, b));
        brush.Freeze();
        return brush;
    }

    // Solid dot colours.
    private static readonly SolidColorBrush GreenDot = Frozen(0xFF, 0x16, 0xA3, 0x4A);
    private static readonly SolidColorBrush AmberDot = Frozen(0xFF, 0xD9, 0x77, 0x06);
    private static readonly SolidColorBrush RedDot = Frozen(0xFF, 0xDC, 0x26, 0x26);
    private static readonly SolidColorBrush GrayDot = Frozen(0xFF, 0x9C, 0xA3, 0xAF);

    // Hero tints (alpha over the theme surface).
    private static readonly SolidColorBrush GreenBg = Frozen(0x22, 0x16, 0xA3, 0x4A);
    private static readonly SolidColorBrush AmberBg = Frozen(0x22, 0xD9, 0x77, 0x06);
    private static readonly SolidColorBrush RedBg = Frozen(0x22, 0xDC, 0x26, 0x26);
    private static readonly SolidColorBrush GrayBg = Frozen(0x14, 0x9C, 0xA3, 0xAF);
    private static readonly SolidColorBrush GreenBorder = Frozen(0x55, 0x16, 0xA3, 0x4A);
    private static readonly SolidColorBrush AmberBorder = Frozen(0x55, 0xD9, 0x77, 0x06);
    private static readonly SolidColorBrush RedBorder = Frozen(0x55, 0xDC, 0x26, 0x26);
    private static readonly SolidColorBrush GrayBorder = Frozen(0x38, 0x9C, 0xA3, 0xAF);

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var role = parameter as string ?? "Dot";
        var status = value as ProtectionStatusView? ?? ProtectionStatusView.Unprotected;
        var tone = status switch
        {
            ProtectionStatusView.ProtectedVerified => 0, // green
            ProtectionStatusView.Applying => 1,          // amber
            ProtectionStatusView.Verifying => 1,         // amber (transitional cold-start)
            ProtectionStatusView.PartiallyProtected => 1,
            ProtectionStatusView.ProxyStopped => 1,      // amber — proxy not running (fail-closed, not leaking)
            ProtectionStatusView.DiagnosticsUnavailable => 1, // amber — reachable + running, DNS check unverifiable this cycle
            ProtectionStatusView.HelperUnavailable => 2, // red
            ProtectionStatusView.HelperIncompatible => 2,
            _ => 3,                                      // neutral gray
        };

        return role switch
        {
            "HeroBackground" => tone switch { 0 => GreenBg, 1 => AmberBg, 2 => RedBg, _ => GrayBg },
            "HeroBorder" => tone switch { 0 => GreenBorder, 1 => AmberBorder, 2 => RedBorder, _ => GrayBorder },
            _ => tone switch { 0 => GreenDot, 1 => AmberDot, 2 => RedDot, _ => GrayDot },
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException($"{nameof(ProtectionStatusToBrushConverter)} is one-way only.");
}
