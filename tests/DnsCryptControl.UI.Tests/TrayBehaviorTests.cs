using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>C: <see cref="TrayPolicy"/> — the pure close/start-minimised decisions behind the Phase 5f tray.</summary>
public sealed class TrayBehaviorTests
{
    [Fact]
    public void Close_withMinimizeToTrayOn_hidesInsteadOfExiting()
    {
        Assert.Equal(
            WindowCloseAction.HideToTray,
            TrayPolicy.OnUserClose(minimizeToTrayOnClose: true, reallyExit: false));
    }

    [Fact]
    public void Close_withMinimizeToTrayOff_exits()
    {
        Assert.Equal(
            WindowCloseAction.Exit,
            TrayPolicy.OnUserClose(minimizeToTrayOnClose: false, reallyExit: false));
    }

    [Fact]
    public void QuitFromTray_alwaysExits_evenWithMinimizeToTrayOn()
    {
        // The tray "Quit" sets reallyExit before closing, so the close-to-tray intercept is bypassed.
        Assert.Equal(
            WindowCloseAction.Exit,
            TrayPolicy.OnUserClose(minimizeToTrayOnClose: true, reallyExit: true));
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void StartHidden_followsStartMinimizedPref(bool startMinimized, bool expectedHidden)
    {
        Assert.Equal(expectedHidden, TrayPolicy.StartHidden(startMinimized));
    }
}
