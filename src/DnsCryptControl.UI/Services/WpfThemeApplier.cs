using System;
using System.Windows;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Applies the persisted theme via WPF-UI's <see cref="ApplicationThemeManager"/> AND owns WPF-UI's
/// <see cref="SystemThemeWatcher"/>, so an explicit Light/Dark and the OS-follow watcher never fight —
/// that fight left the app half-themed (light backgrounds + the dark theme's white text = invisible
/// default-foreground headings/values/buttons across every tab). The string→enum mapping is the pure
/// <see cref="ThemePreferenceParser"/> (unit-tested); this concrete applier touches WPF statics and is
/// exercised only live. Fail-closed: an apply fault must never crash the app.
/// </summary>
public sealed class WpfThemeApplier : IThemeApplier
{
    private Window? _window;

    public void AttachWindow(object window) => _window = window as Window;

    public void Prime()
    {
        try
        {
            // SystemThemeWatcher.Watch injects WPF-UI's accent resources (SystemAccentColorPrimary, ...) into
            // the application resources — the accent that the ControlsDictionary templates resolve via
            // {StaticResource} at the window's parse time. ApplicationThemeManager.Apply(Light/Dark) does NOT
            // inject them, so this MUST run before InitializeComponent or the parse throws and the app dies on
            // launch. Restores the pre-5f Watch-before-InitializeComponent that shipped 5a–5e.
            // WindowBackdropType.None explicitly: Watch's default is Mica — see Apply's System case for why
            // Mica must never reach this window.
            if (_window is not null)
            {
                SystemThemeWatcher.Watch(_window, WindowBackdropType.None, updateAccents: true);
            }
        }
        catch (Exception)
        {
            // Fail-closed: priming is best-effort; a fault here must never crash startup.
        }
    }

    public void Apply(string? theme)
    {
        try
        {
            switch (ThemePreferenceParser.Parse(theme))
            {
                // A FORCED theme must pass WindowBackdropType.None. ApplicationThemeManager.Apply's default Mica
                // path calls WindowBackdrop.RemoveBackground(window), which sets the window + DWM composition to
                // TRANSPARENT so the Mica material shows through — and on an OS whose theme differs from the
                // forced one (e.g. forcing Dark on a Light Windows) that material stays the OS colour. The result
                // is the dictionary brushes go dark (foreground text → white) while the window's backdrop layer
                // stays light → white-on-light invisible content. WindowBackdropType.None instead paints an
                // opaque ApplicationBackgroundBrush that follows the theme dictionary, so content is theme-correct
                // regardless of the OS theme (WPF-UI issue #625). System mode keeps Mica: the backdrop then equals
                // the OS theme, so it resolves the right colour and the translucent effect is preserved.
                case ThemePreference.Light:
                    if (_window is not null) { SystemThemeWatcher.UnWatch(_window); }
                    ApplicationThemeManager.Apply(ApplicationTheme.Light, WindowBackdropType.None);
                    break;
                case ThemePreference.Dark:
                    if (_window is not null) { SystemThemeWatcher.UnWatch(_window); }
                    ApplicationThemeManager.Apply(ApplicationTheme.Dark, WindowBackdropType.None);
                    break;
                default:
                    // System mode must ALSO pin WindowBackdropType.None (the XAML window declares None, and
                    // the forced paths above pass it explicitly): ApplySystemTheme and Watch default to Mica,
                    // whose RemoveBackground turns the window into a DWM-composited transparent surface. On a
                    // COLD first launch after a Windows restart that composition can fail to attach, leaving a
                    // WHITE backdrop under the dark theme's white foreground — an all-white window until a
                    // window state change re-applies the backdrop (the tray double-click "cure"). The opaque
                    // None backdrop paints ApplicationBackgroundBrush and never depends on DWM (the same
                    // failure class as WPF-UI issue #625). ApplySystemTheme resolves the OS theme mapping;
                    // the second Apply re-asserts it with the opaque backdrop.
                    ApplicationThemeManager.ApplySystemTheme();
                    ApplicationThemeManager.Apply(ApplicationThemeManager.GetAppTheme(), WindowBackdropType.None, updateAccent: true);
                    if (_window is not null) { SystemThemeWatcher.Watch(_window, WindowBackdropType.None, updateAccents: true); }
                    break;
            }
        }
        catch (Exception)
        {
            // Fail-closed: a theme-apply fault must NEVER crash the app. WPF-UI's apply path reaches WPF
            // resource-dictionary mutation + DWM/WinRT P/Invoke, which raise COMException/ExternalException/
            // EntryPointNotFoundException (not InvalidOperationException) — so catch broadly here. Both the
            // startup call (App.OnStartup, before the window shows → its catch does Shutdown()+rethrow) and
            // the live theme-dropdown call (SettingsViewModel, no try/catch, no dispatcher handler) rely on
            // this boundary. CA1031 is intentional for this fail-closed applier.
        }
    }
}
