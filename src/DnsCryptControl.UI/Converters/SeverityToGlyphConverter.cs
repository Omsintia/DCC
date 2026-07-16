using System.Globalization;
using System.Windows.Data;
using DnsCryptControl.Core.Validation;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// The validation panel's severity glyphs (F1), covering BOTH issue kinds the panel
/// lists: schema <see cref="ValidationSeverity"/> from <c>ConfigValidator</c> and
/// <see cref="OpsecConcernSeverity"/> from <c>OpsecConfigRules</c>. The two critical
/// OPSEC severities share one glyph deliberately — they block a protected save
/// identically (P5b-U1); Advisory never blocks and reads as informational.
/// </summary>
public sealed class SeverityToGlyphConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        ValidationSeverity.Error => "✖",
        ValidationSeverity.Warning => "⚠",
        OpsecConcernSeverity.KillSwitchCritical => "⛔",
        OpsecConcernSeverity.ProtectionCritical => "⛔",
        OpsecConcernSeverity.Advisory => "ℹ",
        _ => "•",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException($"{nameof(SeverityToGlyphConverter)} is one-way only.");
}
