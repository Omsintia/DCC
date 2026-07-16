using System.Globalization;
using System.Windows;
using DnsCryptControl.Core.Validation;
using DnsCryptControl.UI.Converters;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// F1: the Configuration view's converters. Per the plan's TDD-honesty rule, ONLY
/// converters with real logic get tests here — the XAML itself is compile-verified and
/// controller-reviewed against the approved configuration-v2 mockup, exactly like 5a's
/// views. Converters are plain classes (no dispatcher affinity), so constructing them
/// here matches the established <see cref="ProtectionStatusConvertersTests"/> pattern.
/// </summary>
public class ConfigurationConvertersTests
{
    // ---------------------------------------------------------------------------
    // InverseBoolToVisibilityConverter (5d-VM-1) — the Filtering list Border hides in
    // raw mode. This MUST return a Visibility (not a bool): the bug it fixes was binding
    // InverseBooleanConverter (which returns a bool) to Border.Visibility, so the coercion
    // failed and the list stayed at its default Visible (list + raw editor rendered stacked).
    // ---------------------------------------------------------------------------

    [Fact]
    public void inverse_bool_to_visibility_collapses_the_list_when_raw_selected()
    {
        var converter = new InverseBoolToVisibilityConverter();
        Assert.Equal(Visibility.Collapsed,
            converter.Convert(true, typeof(Visibility), null, CultureInfo.InvariantCulture));
    }

    [Fact]
    public void inverse_bool_to_visibility_shows_the_list_when_list_selected_or_null()
    {
        var converter = new InverseBoolToVisibilityConverter();
        Assert.Equal(Visibility.Visible,
            converter.Convert(false, typeof(Visibility), null, CultureInfo.InvariantCulture));
        Assert.Equal(Visibility.Visible,
            converter.Convert(null, typeof(Visibility), null, CultureInfo.InvariantCulture));
    }

    // ---------------------------------------------------------------------------
    // StringArrayToLinesConverter — the StringArray editor's one-per-line multiline
    // TextBox projection (F1): array -> lines for display, lines -> array for the
    // structured-edit commit path.
    // ---------------------------------------------------------------------------

    [Fact]
    public void lines_converter_joins_array_items_one_per_line()
    {
        var converter = new StringArrayToLinesConverter();

        var result = converter.Convert(
            new[] { "127.0.0.1:53", "[::1]:53" }, typeof(string), null, CultureInfo.InvariantCulture);

        Assert.Equal("127.0.0.1:53" + Environment.NewLine + "[::1]:53", result);
    }

    [Fact]
    public void lines_converter_projects_null_and_non_array_values_as_empty_text()
    {
        var converter = new StringArrayToLinesConverter();

        Assert.Equal(string.Empty, converter.Convert(null, typeof(string), null, CultureInfo.InvariantCulture));
        Assert.Equal(string.Empty, converter.Convert(42, typeof(string), null, CultureInfo.InvariantCulture));
    }

    [Fact]
    public void lines_converter_projects_an_empty_array_as_empty_text()
    {
        var converter = new StringArrayToLinesConverter();

        var result = converter.Convert(
            Array.Empty<string>(), typeof(string), null, CultureInfo.InvariantCulture);

        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void lines_convert_back_splits_on_both_crlf_and_lf()
    {
        var converter = new StringArrayToLinesConverter();

        var result = converter.ConvertBack(
            "a\r\nb\nc", typeof(IReadOnlyList<string>), null, CultureInfo.InvariantCulture);

        var list = Assert.IsAssignableFrom<IReadOnlyList<string>>(result);
        Assert.Equal(new[] { "a", "b", "c" }, list);
    }

    [Fact]
    public void lines_convert_back_trims_each_line_and_drops_blank_lines()
    {
        var converter = new StringArrayToLinesConverter();

        var result = converter.ConvertBack(
            "  127.0.0.1:53  \r\n\r\n   \n9.9.9.9:53\n", typeof(IReadOnlyList<string>), null, CultureInfo.InvariantCulture);

        var list = Assert.IsAssignableFrom<IReadOnlyList<string>>(result);
        Assert.Equal(new[] { "127.0.0.1:53", "9.9.9.9:53" }, list);
    }

    [Fact]
    public void lines_convert_back_of_empty_text_is_an_empty_array()
    {
        // An emptied editor commits an EMPTY array (A2 pinned SetStringArray([]) -> `[]`),
        // never a single empty element.
        var converter = new StringArrayToLinesConverter();

        var result = converter.ConvertBack(
            string.Empty, typeof(IReadOnlyList<string>), null, CultureInfo.InvariantCulture);

        var list = Assert.IsAssignableFrom<IReadOnlyList<string>>(result);
        Assert.Empty(list);
    }

    [Fact]
    public void lines_convert_back_of_a_non_string_is_an_empty_array()
    {
        var converter = new StringArrayToLinesConverter();

        var result = converter.ConvertBack(
            null, typeof(IReadOnlyList<string>), null, CultureInfo.InvariantCulture);

        var list = Assert.IsAssignableFrom<IReadOnlyList<string>>(result);
        Assert.Empty(list);
    }

    [Fact]
    public void lines_projection_round_trips_a_typical_address_list()
    {
        var converter = new StringArrayToLinesConverter();
        var original = new[] { "127.0.0.1:53", "[::1]:53", "9.9.9.9:53" };

        var text = converter.Convert(original, typeof(string), null, CultureInfo.InvariantCulture);
        var back = converter.ConvertBack(text, typeof(IReadOnlyList<string>), null, CultureInfo.InvariantCulture);

        Assert.Equal(original, Assert.IsAssignableFrom<IReadOnlyList<string>>(back));
    }

    // ---------------------------------------------------------------------------
    // NullToVisibilityConverter — every message-carrying banner (Conflict, SaveError,
    // SaveNotice, RestartFailed, ProxyRejected, HelperIncompatible, blocked-save,
    // LoadError) is visible exactly while its VM string is non-empty.
    // ---------------------------------------------------------------------------

    [Fact]
    public void null_to_visibility_collapses_null_and_blank_strings()
    {
        var converter = new NullToVisibilityConverter();

        Assert.Equal(Visibility.Collapsed, converter.Convert(null, typeof(Visibility), null, CultureInfo.InvariantCulture));
        Assert.Equal(Visibility.Collapsed, converter.Convert(string.Empty, typeof(Visibility), null, CultureInfo.InvariantCulture));
        Assert.Equal(Visibility.Collapsed, converter.Convert("   ", typeof(Visibility), null, CultureInfo.InvariantCulture));
    }

    [Fact]
    public void null_to_visibility_shows_a_real_message_and_any_non_string_value()
    {
        var converter = new NullToVisibilityConverter();

        Assert.Equal(Visibility.Visible, converter.Convert("OPSEC guard: ...", typeof(Visibility), null, CultureInfo.InvariantCulture));
        Assert.Equal(Visibility.Visible, converter.Convert(42, typeof(Visibility), null, CultureInfo.InvariantCulture));
    }

    [Fact]
    public void null_to_visibility_convert_back_is_not_supported()
    {
        var converter = new NullToVisibilityConverter();

        Assert.Throws<NotSupportedException>(() =>
            converter.ConvertBack(Visibility.Visible, typeof(string), null, CultureInfo.InvariantCulture));
    }

    // ---------------------------------------------------------------------------
    // DeprecatedChipTextConverter — the "deprecated — use {ReplacedBy}" chip on
    // structured entries; the catalog's ReplacedBy is nullable.
    // ---------------------------------------------------------------------------

    [Fact]
    public void deprecated_chip_names_the_replacement_when_the_catalog_has_one()
    {
        var converter = new DeprecatedChipTextConverter();

        var result = converter.Convert("listen_addresses", typeof(string), null, CultureInfo.InvariantCulture);

        Assert.Equal("deprecated — use listen_addresses", result);
    }

    [Fact]
    public void deprecated_chip_falls_back_to_plain_deprecated_without_a_replacement()
    {
        var converter = new DeprecatedChipTextConverter();

        Assert.Equal("deprecated", converter.Convert(null, typeof(string), null, CultureInfo.InvariantCulture));
        Assert.Equal("deprecated", converter.Convert(string.Empty, typeof(string), null, CultureInfo.InvariantCulture));
    }

    [Fact]
    public void deprecated_chip_convert_back_is_not_supported()
    {
        var converter = new DeprecatedChipTextConverter();

        Assert.Throws<NotSupportedException>(() =>
            converter.ConvertBack("deprecated", typeof(string), null, CultureInfo.InvariantCulture));
    }

    // ---------------------------------------------------------------------------
    // SeverityToGlyphConverter — the validation panel's severity glyphs for BOTH
    // issue kinds: schema ValidationSeverity and OpsecConcernSeverity (F1).
    // ---------------------------------------------------------------------------

    [Theory]
    [InlineData(ValidationSeverity.Error, "✖")] // ✖
    [InlineData(ValidationSeverity.Warning, "⚠")] // ⚠
    public void severity_glyph_maps_every_schema_severity(ValidationSeverity severity, string expected)
    {
        var converter = new SeverityToGlyphConverter();

        Assert.Equal(expected, converter.Convert(severity, typeof(string), null, CultureInfo.InvariantCulture));
    }

    [Theory]
    [InlineData(OpsecConcernSeverity.KillSwitchCritical, "⛔")] // ⛔
    [InlineData(OpsecConcernSeverity.ProtectionCritical, "⛔")] // ⛔ — both criticals block a protected save
    [InlineData(OpsecConcernSeverity.Advisory, "ℹ")] // ℹ
    public void severity_glyph_maps_every_opsec_severity(OpsecConcernSeverity severity, string expected)
    {
        var converter = new SeverityToGlyphConverter();

        Assert.Equal(expected, converter.Convert(severity, typeof(string), null, CultureInfo.InvariantCulture));
    }

    [Fact]
    public void severity_glyph_falls_back_to_a_bullet_for_a_non_severity_value()
    {
        var converter = new SeverityToGlyphConverter();

        Assert.Equal("•", converter.Convert(null, typeof(string), null, CultureInfo.InvariantCulture));
        Assert.Equal("•", converter.Convert("nope", typeof(string), null, CultureInfo.InvariantCulture));
    }

    [Fact]
    public void severity_glyph_convert_back_is_not_supported()
    {
        var converter = new SeverityToGlyphConverter();

        Assert.Throws<NotSupportedException>(() =>
            converter.ConvertBack("⚠", typeof(ValidationSeverity), null, CultureInfo.InvariantCulture));
    }

    // ---------------------------------------------------------------------------
    // ConfigStatusBadgeConverter — the subbar status badge (Valid / N errors /
    // Blocked). MultiBinding over [IsValid, ValidationIssues, SaveBlockedReason];
    // ConverterParameter picks "Text" (default) or "Appearance", mirroring the
    // parameterized ProtectionStatusToHelperBannerMessageConverter pattern.
    // Precedence: published Error issues > OPSEC block > valid — errors are the most
    // actionable readout, and the blocked-save banner explains the block regardless.
    // ---------------------------------------------------------------------------

    private static object[] BadgeValues(bool isValid, IReadOnlyList<ValidationIssue> issues, string? blockedReason) =>
        new object[] { isValid, issues, blockedReason! };

    private static ValidationIssue Issue(ValidationSeverity severity) =>
        new("some_key", "message", severity);

    [Fact]
    public void badge_shows_valid_on_success_state()
    {
        var converter = new ConfigStatusBadgeConverter();
        var values = BadgeValues(true, Array.Empty<ValidationIssue>(), null);

        Assert.Equal("Valid", converter.Convert(values, typeof(string), "Text", CultureInfo.InvariantCulture));
        Assert.Equal(
            Wpf.Ui.Controls.ControlAppearance.Success,
            converter.Convert(values, typeof(object), "Appearance", CultureInfo.InvariantCulture));
    }

    [Fact]
    public void badge_counts_only_error_severity_issues()
    {
        var converter = new ConfigStatusBadgeConverter();
        var issues = new[] { Issue(ValidationSeverity.Error), Issue(ValidationSeverity.Warning), Issue(ValidationSeverity.Error) };
        var values = BadgeValues(false, issues, null);

        Assert.Equal("2 errors", converter.Convert(values, typeof(string), "Text", CultureInfo.InvariantCulture));
        Assert.Equal(
            Wpf.Ui.Controls.ControlAppearance.Danger,
            converter.Convert(values, typeof(object), "Appearance", CultureInfo.InvariantCulture));
    }

    [Fact]
    public void badge_uses_singular_for_one_error()
    {
        var converter = new ConfigStatusBadgeConverter();
        var values = BadgeValues(false, new[] { Issue(ValidationSeverity.Error) }, null);

        Assert.Equal("1 error", converter.Convert(values, typeof(string), "Text", CultureInfo.InvariantCulture));
    }

    [Fact]
    public void badge_shows_blocked_when_the_opsec_mirror_blocks_a_schema_valid_config()
    {
        var converter = new ConfigStatusBadgeConverter();
        var values = BadgeValues(true, Array.Empty<ValidationIssue>(), "OPSEC guard: netprobe_timeout must be 0");

        Assert.Equal("Blocked", converter.Convert(values, typeof(string), "Text", CultureInfo.InvariantCulture));
        Assert.Equal(
            Wpf.Ui.Controls.ControlAppearance.Caution,
            converter.Convert(values, typeof(object), "Appearance", CultureInfo.InvariantCulture));
    }

    [Fact]
    public void badge_prefers_the_error_count_over_blocked_when_both_apply()
    {
        var converter = new ConfigStatusBadgeConverter();
        var values = BadgeValues(false, new[] { Issue(ValidationSeverity.Error) }, "OPSEC guard: ...");

        Assert.Equal("1 error", converter.Convert(values, typeof(string), "Text", CultureInfo.InvariantCulture));
    }

    [Fact]
    public void badge_shows_invalid_for_the_unpublished_invalid_seed_state()
    {
        // A load whose TOML failed to parse seeds IsValid=false with NO published issues
        // (findings publish per edit, E2) — the badge must not claim "Valid".
        var converter = new ConfigStatusBadgeConverter();
        var values = BadgeValues(false, Array.Empty<ValidationIssue>(), null);

        Assert.Equal("Invalid", converter.Convert(values, typeof(string), "Text", CultureInfo.InvariantCulture));
        Assert.Equal(
            Wpf.Ui.Controls.ControlAppearance.Danger,
            converter.Convert(values, typeof(object), "Appearance", CultureInfo.InvariantCulture));
    }

    [Fact]
    public void badge_treats_unset_binding_values_as_the_invalid_state()
    {
        // Before the first VM publication a MultiBinding can hand the converter
        // DependencyProperty.UnsetValue slots — never crash, never claim Valid.
        var converter = new ConfigStatusBadgeConverter();
        var values = new[] { DependencyProperty.UnsetValue, DependencyProperty.UnsetValue, DependencyProperty.UnsetValue };

        Assert.Equal("Invalid", converter.Convert(values, typeof(string), "Text", CultureInfo.InvariantCulture));
        Assert.Equal(
            Wpf.Ui.Controls.ControlAppearance.Danger,
            converter.Convert(values, typeof(object), "Appearance", CultureInfo.InvariantCulture));
    }

    [Fact]
    public void badge_convert_back_is_not_supported()
    {
        var converter = new ConfigStatusBadgeConverter();

        Assert.Throws<NotSupportedException>(() =>
            converter.ConvertBack("Valid", new[] { typeof(bool) }, null, CultureInfo.InvariantCulture));
    }
}
