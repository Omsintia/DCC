using System.ComponentModel;
using System.Windows;
using DnsCryptControl.UI.ViewModels;
using ContentDialog = Wpf.Ui.Controls.ContentDialog;
using ContentDialogHost = Wpf.Ui.Controls.ContentDialogHost;
using ContentDialogResult = Wpf.Ui.Controls.ContentDialogResult;

namespace DnsCryptControl.UI.Views;

/// <summary>
/// The Resolvers tab's view (C1–C3, D1). Bound via <c>DataContext</c> to the injected
/// <see cref="ResolversViewModel"/> (wired by the shell). Code-behind is view PLUMBING only:
/// it forwards the U2 pick clicks and the per-row probe click to the unit-tested VM methods,
/// forwards Reload to <see cref="ResolversViewModel.LoadAsync"/>, and shows/routes the
/// "Test all latencies" consent <see cref="ContentDialog"/> when the VM raises a
/// <see cref="ResolversViewModel.PendingConsentRequest"/> — the decision to probe (and the
/// fresh kill-switch status fetch, the target derivation, the offline gate) all live in the VM.
/// The dialog's Primary/Close texts are pinned UI strings the automation kit anchors on.
/// </summary>
public partial class ResolversView
{
    private ResolversViewModel? _boundViewModel;
    private ContentDialog? _consentDialog;
    private bool _consentDialogOpen;

    public ResolversView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private ResolversViewModel? ViewModel => DataContext as ResolversViewModel;

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (_boundViewModel is not null)
        {
            _boundViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        }

        _boundViewModel = e.NewValue as ResolversViewModel;
        if (_boundViewModel is not null)
        {
            _boundViewModel.PropertyChanged += OnViewModelPropertyChanged;
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ResolversViewModel.PendingConsentRequest))
        {
            // Fire-and-forget: ShowConsentAsync is fail-closed and routes to the VM's non-throwing
            // Confirm/Cancel. A pending request appearing shows the dialog; it clearing hides it.
            _ = ShowConsentAsync();
        }
    }

    /// <summary>The U2 "Use only this server" pick (server_names=[name] + single-pool warning).</summary>
    private void UseOnlyThisServer_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && ResolverList.SelectedItem is ResolverRowViewModel row)
        {
            vm.UseOnlyThisServer(row);
        }
    }

    /// <summary>The U2 "Add to pool" pick (server_names += name).</summary>
    private void AddToPool_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && ResolverList.SelectedItem is ResolverRowViewModel row)
        {
            vm.AddToPool(row);
        }
    }

    /// <summary>The per-row probe click — its own consent (P5c-U1, no dialog). Fail-closed VM call.</summary>
    private async void ProbeRow_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && ResolverList.SelectedItem is ResolverRowViewModel row)
        {
            await vm.ProbeRowAsync(row).ConfigureAwait(true);
        }
    }

    /// <summary>Automatic mode: stage an empty server_names (the VM switch is idempotent + guarded).</summary>
    private void AutomaticMode_Click(object sender, RoutedEventArgs e)
    {
        ViewModel?.SwitchToAutomaticMode();
    }

    /// <summary>
    /// 5g-2 deep-link: the chip-row hint's "Open Configuration: Server selection" link routes to
    /// <see cref="MainWindow.NavigateToConfigurationSection"/> — tab switch plus section focus,
    /// running the full tab lifecycle. The name is the exact ConfigCatalog group string ("Server
    /// selection", pinned by test). Null-safe: design-time hosts and view-level tests have no
    /// <see cref="MainWindow"/> ancestor — the click is then a no-op. View code-behind on purpose:
    /// window/tab reaching never lives in a ViewModel (MVVM boundary).
    /// </summary>
    private void OpenServerSelection_Click(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow mainWindow)
        {
            mainWindow.NavigateToConfigurationSection("Server selection");
        }
    }

    /// <summary>
    /// 5j deep-link: the ODoH empty-state explainer's "Open Configuration: Sources" link. ODoH
    /// targets/relays come from separate source lists (odoh-servers/odoh-relays) not enabled by
    /// default, so the honest fix is to route the user to the Sources section where they can add
    /// them (the proxy then downloads them on its own schedule). Same MVVM-safe, null-safe pattern
    /// as <see cref="OpenServerSelection_Click"/>; "Sources" is the exact ConfigCatalog group string.
    /// </summary>
    private void OpenSources_Click(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow mainWindow)
        {
            mainWindow.NavigateToConfigurationSection("Sources");
        }
    }

    /// <summary>Relay guidance deep-link: a relay is routing infrastructure, not a pool server, so its
    /// detail pane offers this instead of "Add to pool" — jump straight to the Anonymized DNS route
    /// builder where a relay is actually used (paired with a server). Same MVVM-safe, null-safe,
    /// code-behind pattern as <see cref="OpenServerSelection_Click"/>.</summary>
    private void OpenAnonDnsBuilder_Click(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow mainWindow)
        {
            mainWindow.NavigateToAnonymizedDns();
        }
    }

    /// <summary>"Route through a relay" shortcut for an anonymizable server (DNSCrypt / ODoH target):
    /// navigate to Anonymized DNS AND stage a route for this server (via the auto relay), landing the
    /// user in the builder with the route ready to refine + save. The staging happens BEFORE the tab
    /// switch so the tab-activation reload (which runs only when the VM is clean) can't discard it.</summary>
    private void RouteThroughRelay_Click(object sender, RoutedEventArgs e)
    {
        if (ResolverList.SelectedItem is ResolverRowViewModel row
            && Window.GetWindow(this) is MainWindow mainWindow)
        {
            mainWindow.NavigateToAnonymizedDnsRoute(row.Name);
        }
    }

    /// <summary>
    /// 5j: the ODoH empty-state "Add ODoH server lists" button. Shows the confirmation dialog (which
    /// lists the exact URLs the PROXY will download from — the app itself never connects), then on
    /// Primary runs the VM's fail-closed <see cref="ResolversViewModel.AddOdohSourcesCommand"/>. If no
    /// dialog host is reachable (never expected in the real shell), nothing is written.
    /// </summary>
    private async void AddOdohSources_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm)
        {
            return;
        }

        var dialog = TryFindResource("AddOdohSourcesDialog") as ContentDialog;
        var host = FindDialogHost();
        if (dialog is null || host is null)
        {
            return;
        }

        dialog.DataContext = vm;
        if (dialog.DialogHostEx is null)
        {
            dialog.DialogHostEx = host;
        }

        var result = await dialog.ShowAsync(CancellationToken.None).ConfigureAwait(true);
        if (result == ContentDialogResult.Primary && vm.AddOdohSourcesCommand.CanExecute(null))
        {
            await vm.AddOdohSourcesCommand.ExecuteAsync(null).ConfigureAwait(true);
        }
    }

    /// <summary>The Conflict banner's [Reload] / the load-failure [Retry] — an explicit re-read (fail-closed).</summary>
    private async void ReloadButton_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm)
        {
            await vm.LoadAsync(CancellationToken.None).ConfigureAwait(true);
        }
    }

    /// <summary>
    /// Shows the "Test all latencies" consent dialog while the VM has a
    /// <see cref="ResolversViewModel.PendingConsentRequest"/>, then routes the result: Primary ⇒
    /// <see cref="ResolversViewModel.ConfirmTestAllAsync"/> (the consented act — fetches status
    /// fresh and probes), anything else ⇒ <see cref="ResolversViewModel.CancelTestAll"/>. Re-entrancy
    /// is guarded (one dialog at a time). If no host presenter is reachable (never expected in the real
    /// shell), the consent is cancelled so the batch never proceeds unconsented.
    /// </summary>
    private async Task ShowConsentAsync()
    {
        if (ViewModel is not { } vm)
        {
            return;
        }

        if (vm.PendingConsentRequest is null)
        {
            return; // the request cleared (cancelled elsewhere / tab switch) — nothing to show.
        }

        if (_consentDialogOpen)
        {
            return; // already showing for this request.
        }

        var dialog = ResolveConsentDialog();
        var host = FindDialogHost();
        if (dialog is null || host is null)
        {
            vm.CancelTestAll();
            return;
        }

        dialog.DataContext = vm; // resources don't inherit DataContext — bind the count explicitly.
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
                await vm.ConfirmTestAllAsync().ConfigureAwait(true);
            }
            else
            {
                vm.CancelTestAll();
            }
        }
        finally
        {
            _consentDialogOpen = false;
        }
    }

    private ContentDialog? ResolveConsentDialog() =>
        _consentDialog ??= TryFindResource("TestAllConsentDialog") as ContentDialog;

    /// <summary>The shell window's registered dialog host (the <c>ContentDialogHost</c> in MainWindow).</summary>
    private ContentDialogHost? FindDialogHost()
    {
        var window = Window.GetWindow(this);
        return window is null ? null : ContentDialogHost.GetForWindow(window);
    }
}
