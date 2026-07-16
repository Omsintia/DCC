using System.Windows;
using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Views;

/// <summary>
/// The Logs &amp; Diagnostics tab (Phase 5e, design 3.1/3.2). Bound via <c>DataContext</c> to the injected
/// <see cref="LogsDiagnosticsViewModel"/>. Code-behind is view PLUMBING only: it forwards Refresh / the
/// opt-in proxy-log capture toggle to the unit-tested VM methods and puts the health-only diagnostics
/// bundle (<see cref="LogsDiagnosticsViewModel.BuildDiagnosticsText"/>, which excludes all query data,
/// IC-QM6) on the clipboard. The health snapshot reuses the existing helper status/diagnostics — no new
/// privileged wire (IC-2).
/// </summary>
public partial class LogsDiagnosticsView
{
    public LogsDiagnosticsView()
    {
        InitializeComponent();
    }

    private LogsDiagnosticsViewModel? ViewModel => DataContext as LogsDiagnosticsViewModel;

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm)
        {
            await vm.RefreshAsync(CancellationToken.None).ConfigureAwait(true);
        }
    }

    private void CopyDiagnostics_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm)
        {
            return;
        }

        try
        {
            // Health-only text (versions, service/protection/kill-switch/leak flags) — NEVER query data.
            Clipboard.SetText(vm.BuildDiagnosticsText());
        }
        catch (Exception)
        {
            // The clipboard can transiently be locked by another process; a failed copy is a benign no-op.
        }
    }

    private async void EnableCapture_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm)
        {
            await vm.EnableProxyLogCaptureAsync(CancellationToken.None).ConfigureAwait(true);
        }
    }

    private async void DisableCapture_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm)
        {
            await vm.DisableProxyLogCaptureAsync(CancellationToken.None).ConfigureAwait(true);
        }
    }
}
