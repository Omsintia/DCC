using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>B: <see cref="ThemePreferenceParser"/> — the pure string→theme mapping behind IThemeApplier (headless).</summary>
public sealed class ThemeApplierTests
{
    [Theory]
    [InlineData("Light", ThemePreference.Light)]
    [InlineData("light", ThemePreference.Light)]
    [InlineData("Dark", ThemePreference.Dark)]
    [InlineData("dark", ThemePreference.Dark)]
    [InlineData(" Dark ", ThemePreference.Dark)]
    [InlineData("System", ThemePreference.System)]
    [InlineData(null, ThemePreference.System)]
    public void Parse_mapsPersistedStringToPreference(string? theme, ThemePreference expected)
    {
        Assert.Equal(expected, ThemePreferenceParser.Parse(theme));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("chartreuse")]
    [InlineData("LIGHTish")]
    public void Parse_unknownOrGarbage_fallsBackToSystem(string theme)
    {
        Assert.Equal(ThemePreference.System, ThemePreferenceParser.Parse(theme));
    }
}
