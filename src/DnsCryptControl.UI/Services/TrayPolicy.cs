namespace DnsCryptControl.UI.Services;

/// <summary>What a user-initiated window close should do (Phase 5f tray).</summary>
public enum WindowCloseAction
{
    /// <summary>Let the window close and the app exit.</summary>
    Exit,

    /// <summary>Cancel the close and hide the window to the notification-area tray.</summary>
    HideToTray,
}

/// <summary>
/// The pure, WPF-free tray/window-lifecycle DECISIONS (Phase 5f), extracted so they are unit-testable
/// non-STA. The actual <c>NotifyIcon</c> + Show/Hide plumbing lives in the window code-behind and is
/// exercised only live (the VM run), mirroring how <c>MainWindow</c> is excluded from the headless
/// HostWiring tests.
/// </summary>
public static class TrayPolicy
{
    /// <summary>
    /// Decide what a user-initiated window close should do: hide to the tray ONLY when the
    /// "keep running in the tray on close" preference is on AND this is not a real Quit
    /// (<paramref name="reallyExit"/>, which the tray Quit sets before closing). Otherwise exit.
    /// </summary>
    public static WindowCloseAction OnUserClose(bool minimizeToTrayOnClose, bool reallyExit) =>
        !reallyExit && minimizeToTrayOnClose ? WindowCloseAction.HideToTray : WindowCloseAction.Exit;

    /// <summary>Whether the window should start hidden in the tray instead of shown.</summary>
    public static bool StartHidden(bool startMinimized) => startMinimized;
}
