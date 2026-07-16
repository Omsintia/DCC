using System.ComponentModel;
using System.Windows;
using DnsCryptControl.UI.ViewModels;
using ContentDialog = Wpf.Ui.Controls.ContentDialog;
using ContentDialogHost = Wpf.Ui.Controls.ContentDialogHost;
using ContentDialogResult = Wpf.Ui.Controls.ContentDialogResult;

namespace DnsCryptControl.UI.Views;

/// <summary>
/// The Query Monitor tab (Phase 5e, design 2.6). Bound via <c>DataContext</c> to the injected
/// <see cref="QueryMonitorViewModel"/>. Code-behind is view PLUMBING only: it forwards the toolbar
/// clicks to the unit-tested VM methods and shows/routes the "turn on logging" consent
/// <see cref="ContentDialog"/> when the VM raises <see cref="QueryMonitorViewModel.PendingLoggingConsent"/>
/// (the consent gate, IC-QM2) — the config write, the read-and-shred loop, and the ring buffer all live
/// in the VM. Mirrors <see cref="ResolversView"/>'s consent pattern exactly.
/// </summary>
public partial class QueryMonitorView
{
    private QueryMonitorViewModel? _boundViewModel;
    private ContentDialog? _consentDialog;
    private bool _consentDialogOpen;

    public QueryMonitorView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private QueryMonitorViewModel? ViewModel => DataContext as QueryMonitorViewModel;

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (_boundViewModel is not null)
        {
            _boundViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        }

        _boundViewModel = e.NewValue as QueryMonitorViewModel;
        if (_boundViewModel is not null)
        {
            _boundViewModel.PropertyChanged += OnViewModelPropertyChanged;
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(QueryMonitorViewModel.PendingLoggingConsent))
        {
            // Fire-and-forget: ShowConsentAsync is fail-closed and routes to the VM's non-throwing
            // Confirm/Cancel. A pending request appearing shows the dialog; it clearing hides it.
            _ = ShowConsentAsync();
        }
    }

    /// <summary>The "Turn on logging" button — only ARMS the consent request; writes nothing (IC-QM2).</summary>
    private void Enable_Click(object sender, RoutedEventArgs e) => ViewModel?.RequestEnable();

    /// <summary>"Stop &amp; clear" (IC-QM5): unset the config key, stop the poller, purge the file, clear view.</summary>
    private async void StopClear_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm)
        {
            await vm.DisableAsync(CancellationToken.None).ConfigureAwait(true);
        }
    }

    private void Pause_Click(object sender, RoutedEventArgs e) => ViewModel?.Pause();

    private void Resume_Click(object sender, RoutedEventArgs e) => ViewModel?.Resume();

    private void Clear_Click(object sender, RoutedEventArgs e) => ViewModel?.ClearView();

    /// <summary>
    /// Shows the "turn on query logging" consent dialog while the VM has a
    /// <see cref="QueryMonitorViewModel.PendingLoggingConsent"/>, then routes the result: Primary ⇒
    /// <see cref="QueryMonitorViewModel.ConfirmEnableAsync"/> (the consented act — writes the config key
    /// and starts the read-and-shred loop), anything else ⇒ <see cref="QueryMonitorViewModel.CancelEnable"/>
    /// (writes nothing). Re-entrancy is guarded. If no host presenter is reachable the consent is
    /// cancelled so logging never turns on unconsented.
    /// </summary>
    private async Task ShowConsentAsync()
    {
        if (ViewModel is not { } vm)
        {
            return;
        }

        if (vm.PendingLoggingConsent is null)
        {
            return; // the request cleared — nothing to show.
        }

        if (_consentDialogOpen)
        {
            return; // already showing for this request.
        }

        var dialog = ResolveConsentDialog();
        var host = FindDialogHost();
        if (dialog is null || host is null)
        {
            vm.CancelEnable();
            return;
        }

        dialog.DataContext = vm; // resources don't inherit DataContext — bind the path explicitly.
        if (dialog.DialogHostEx is null)
        {
            dialog.DialogHostEx = host;
        }

        _consentDialogOpen = true;
        try
        {
            var result = await dialog.ShowAsync(CancellationToken.None).ConfigureAwait(true);
            if (result == ContentDialogResult.Primary)
            {
                await vm.ConfirmEnableAsync(CancellationToken.None).ConfigureAwait(true);
            }
            else
            {
                vm.CancelEnable();
            }
        }
        finally
        {
            _consentDialogOpen = false;
        }
    }

    private ContentDialog? ResolveConsentDialog() =>
        _consentDialog ??= TryFindResource("EnableLoggingConsentDialog") as ContentDialog;

    /// <summary>The shell window's registered dialog host (the <c>ContentDialogHost</c> in MainWindow).</summary>
    private ContentDialogHost? FindDialogHost()
    {
        var window = Window.GetWindow(this);
        return window is null ? null : ContentDialogHost.GetForWindow(window);
    }
}
