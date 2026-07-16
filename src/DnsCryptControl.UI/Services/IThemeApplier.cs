namespace DnsCryptControl.UI.Services;

/// <summary>The three theme choices offered in Settings (Phase 5f).</summary>
public enum ThemePreference
{
    /// <summary>Follow the OS theme (the default when nothing is persisted).</summary>
    System,

    /// <summary>Force the light theme.</summary>
    Light,

    /// <summary>Force the dark theme.</summary>
    Dark,
}

/// <summary>Applies the user's persisted theme preference to the running app (Phase 5f).</summary>
public interface IThemeApplier
{
    /// <summary>
    /// Apply the persisted theme string ("Light"/"Dark", or null/"System"/anything else = follow the OS).
    /// Fail-closed: never throws — an apply fault leaves the current theme untouched. When a window is
    /// attached, an explicit Light/Dark un-watches WPF-UI's SystemThemeWatcher and System re-watches it,
    /// so an explicit theme and the OS-follow watcher never fight (a fight leaves text invisible).
    /// </summary>
    void Apply(string? theme);

    /// <summary>Attach the shell window (typed <c>object</c> to keep this POCO-friendly; the WPF applier
    /// casts it) so <see cref="Apply"/> and <see cref="Prime"/> can watch/un-watch SystemThemeWatcher against
    /// it. Call once, before <see cref="Prime"/>.</summary>
    void AttachWindow(object window);

    /// <summary>
    /// Prime WPF-UI's theme resources against the attached window BEFORE the window's XAML is parsed
    /// (<c>InitializeComponent</c>). <c>SystemThemeWatcher.Watch</c> injects the accent resources
    /// (<c>SystemAccentColorPrimary</c>, …) that WPF-UI control templates resolve via <c>{StaticResource}</c>
    /// at PARSE time; <see cref="Apply"/>'s <c>ApplicationThemeManager.Apply(Light/Dark)</c> path does NOT
    /// inject them, so without this the first window's parse throws a XamlParseException and the app never
    /// starts. This is the pre-5f (Watch-before-InitializeComponent) behaviour that shipped 5a–5e. Fail-closed:
    /// call after <see cref="AttachWindow"/> and before <c>InitializeComponent</c>; <see cref="Apply"/> then
    /// layers the persisted preference on top (an explicit Light/Dark un-watches so it never fights the OS
    /// follower — the invisible-text fix).
    /// </summary>
    void Prime();
}

/// <summary>
/// Pure parsing of the persisted theme string into a <see cref="ThemePreference"/> — unit-tested
/// headlessly so the string→theme mapping is verified without touching WPF statics.
/// </summary>
public static class ThemePreferenceParser
{
    /// <summary>Map a persisted theme string to a preference; unrecognised/empty/null → System.</summary>
    public static ThemePreference Parse(string? theme) => theme?.Trim().ToUpperInvariant() switch
    {
        "LIGHT" => ThemePreference.Light,
        "DARK" => ThemePreference.Dark,
        _ => ThemePreference.System,
    };
}
