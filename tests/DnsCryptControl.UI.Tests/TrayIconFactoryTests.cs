using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>Feature (status-tinted tray): <see cref="TrayIconFactory.ForStatus"/> must yield a real,
/// non-empty icon for each protection status (it recolours the host exe's associated icon). GDI is
/// Windows-only, so the assertions run only on Windows (the whole UI project targets net8.0-windows,
/// but keep the guard so the suite is portable).</summary>
public sealed class TrayIconFactoryTests
{
    [Theory]
    [InlineData(TrayIconFactory.TrayStatus.Protected)]
    [InlineData(TrayIconFactory.TrayStatus.Warning)]
    [InlineData(TrayIconFactory.TrayStatus.Neutral)]
    public void ForStatus_producesANonEmptyIcon(TrayIconFactory.TrayStatus status)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var icon = TrayIconFactory.ForStatus(status);

        Assert.NotNull(icon);
        Assert.True(icon!.Width > 0);
        Assert.True(icon.Height > 0);
    }
}
