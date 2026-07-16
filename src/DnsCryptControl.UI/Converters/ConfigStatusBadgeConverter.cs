using System.Globalization;
using System.Windows.Data;
using DnsCryptControl.Core.Validation;
using Wpf.Ui.Controls;

namespace DnsCryptControl.UI.Converters;

/// <summary>
/// The Configuration subbar's status badge (F1): a <see cref="IMultiValueConverter"/>
/// over <c>[IsValid, ValidationIssues, SaveBlockedReason]</c> rendering
/// "Valid / N errors / Blocked". <paramref name="parameter"/> selects <c>"Appearance"</c>
/// (a <see cref="ControlAppearance"/>) or the text (default), mirroring the
/// parameterized <see cref="ProtectionStatusToHelperBannerMessageConverter"/> pattern.
///
/// <para>Precedence: published Error-severity issues (the most actionable readout) →
/// the OPSEC block mirror → Valid. <c>IsValid == false</c> with no published issues —
/// the parse-failed load seed, before any edit publishes findings (E2) — reads
/// "Invalid", never a false "Valid". Unset MultiBinding slots degrade to the same
/// fail-safe "Invalid".</para>
/// </summary>
public sealed class ConfigStatusBadgeConverter : IMultiValueConverter
{
    public object Convert(object?[]? values, Type targetType, object? parameter, CultureInfo culture)
    {
        var wantsAppearance = string.Equals(parameter as string, "Appearance", StringComparison.Ordinal);

        var isValid = values is { Length: >= 1 } && values[0] is bool v && v;
        var errorCount = values is { Length: >= 2 } && values[1] is IReadOnlyList<ValidationIssue> issues
            ? issues.Count(static i => i.Severity == ValidationSeverity.Error)
            : 0;
        var blockedReason = values is { Length: >= 3 } ? values[2] as string : null;

        if (errorCount > 0)
        {
            return wantsAppearance
                ? ControlAppearance.Danger
                : string.Create(CultureInfo.InvariantCulture, $"{errorCount} {(errorCount == 1 ? "error" : "errors")}");
        }

        if (!string.IsNullOrEmpty(blockedReason))
        {
            return wantsAppearance ? ControlAppearance.Caution : "Blocked";
        }

        if (isValid)
        {
            return wantsAppearance ? ControlAppearance.Success : "Valid";
        }

        return wantsAppearance ? ControlAppearance.Danger : "Invalid";
    }

    public object[] ConvertBack(object? value, Type[] targetTypes, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException($"{nameof(ConfigStatusBadgeConverter)} is one-way only.");
}
