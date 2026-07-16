using System.Globalization;
using System.Windows;
using DnsCryptControl.UI.Converters;
using DnsCryptControl.UI.Models;
using Wpf.Ui.Controls;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// C2: the view-layer mapping from the VM's pure-POCO <see cref="ProtectionStatusView"/>
/// enum to WPF-UI presentation (a <see cref="ControlAppearance"/> for the status
/// <c>ui:Badge</c> and the human-readable label). Converters live in the UI/view layer —
/// the VM stays a pure POCO with zero WPF type references, so this mapping is the one
/// place status semantics become an <see cref="System.Windows.Data.IValueConverter"/>.
/// </summary>
public class ProtectionStatusConvertersTests
{
    [Theory]
    [InlineData(ProtectionStatusView.ProtectedVerified, ControlAppearance.Success)]
    [InlineData(ProtectionStatusView.Applying, ControlAppearance.Caution)]
    [InlineData(ProtectionStatusView.PartiallyProtected, ControlAppearance.Caution)]
    [InlineData(ProtectionStatusView.Unprotected, ControlAppearance.Secondary)]
    [InlineData(ProtectionStatusView.HelperUnavailable, ControlAppearance.Danger)]
    public void Appearance_converter_maps_every_status_value(ProtectionStatusView status, ControlAppearance expected)
    {
        var converter = new ProtectionStatusToAppearanceConverter();

        var result = converter.Convert(status, typeof(ControlAppearance), null, CultureInfo.InvariantCulture);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void Appearance_converter_falls_back_to_secondary_for_a_non_enum_value()
    {
        var converter = new ProtectionStatusToAppearanceConverter();

        var result = converter.Convert("not-a-status", typeof(ControlAppearance), null, CultureInfo.InvariantCulture);

        Assert.Equal(ControlAppearance.Secondary, result);
    }

    [Theory]
    [InlineData(ProtectionStatusView.ProtectedVerified, "Protected")]
    [InlineData(ProtectionStatusView.Applying, "Applying…")]
    [InlineData(ProtectionStatusView.PartiallyProtected, "Partially protected — leak detected")]
    [InlineData(ProtectionStatusView.Unprotected, "Not protected")]
    [InlineData(ProtectionStatusView.HelperUnavailable, "Helper unavailable")]
    public void Text_converter_maps_every_status_value(ProtectionStatusView status, string expected)
    {
        var converter = new ProtectionStatusToTextConverter();

        var result = converter.Convert(status, typeof(string), null, CultureInfo.InvariantCulture);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void Text_converter_falls_back_to_unknown_for_a_non_enum_value()
    {
        var converter = new ProtectionStatusToTextConverter();

        var result = converter.Convert(null, typeof(string), null, CultureInfo.InvariantCulture);

        Assert.Equal("Unknown", result);
    }

    [Fact]
    public void ConvertBack_is_not_supported()
    {
        var appearance = new ProtectionStatusToAppearanceConverter();
        var text = new ProtectionStatusToTextConverter();

        Assert.Throws<NotSupportedException>(() =>
            appearance.ConvertBack(ControlAppearance.Success, typeof(ProtectionStatusView), null, CultureInfo.InvariantCulture));
        Assert.Throws<NotSupportedException>(() =>
            text.ConvertBack("Protected", typeof(ProtectionStatusView), null, CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// D1: the "helper unavailable" banner must be visible ONLY for
    /// <see cref="ProtectionStatusView.HelperUnavailable"/> — every other status
    /// (including the transient <c>Applying</c> state) collapses it. Kept in the view
    /// layer so the VM stays a pure POCO with no <see cref="Visibility"/> dependency.
    /// </summary>
    [Theory]
    [InlineData(ProtectionStatusView.HelperUnavailable, Visibility.Visible)]
    [InlineData(ProtectionStatusView.ProtectedVerified, Visibility.Collapsed)]
    [InlineData(ProtectionStatusView.PartiallyProtected, Visibility.Collapsed)]
    [InlineData(ProtectionStatusView.Unprotected, Visibility.Collapsed)]
    [InlineData(ProtectionStatusView.Applying, Visibility.Collapsed)]
    public void helper_unavailable_banner_is_visible_only_for_HelperUnavailable(ProtectionStatusView status, Visibility expected)
    {
        var converter = new ProtectionStatusToHelperUnavailableVisibilityConverter();

        var result = converter.Convert(status, typeof(Visibility), null, CultureInfo.InvariantCulture);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void helper_unavailable_visibility_converter_falls_back_to_collapsed_for_a_non_enum_value()
    {
        var converter = new ProtectionStatusToHelperUnavailableVisibilityConverter();

        var result = converter.Convert(null, typeof(Visibility), null, CultureInfo.InvariantCulture);

        Assert.Equal(Visibility.Collapsed, result);
    }

    [Fact]
    public void helper_unavailable_visibility_ConvertBack_is_not_supported()
    {
        var converter = new ProtectionStatusToHelperUnavailableVisibilityConverter();

        Assert.Throws<NotSupportedException>(() =>
            converter.ConvertBack(Visibility.Visible, typeof(ProtectionStatusView), null, CultureInfo.InvariantCulture));
    }
}
