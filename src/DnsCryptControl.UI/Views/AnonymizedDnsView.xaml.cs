using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using DnsCryptControl.UI.ViewModels;
using ToggleSwitch = Wpf.Ui.Controls.ToggleSwitch;

namespace DnsCryptControl.UI.Views;

/// <summary>
/// The Anonymized DNS tab's view (C4, D2). Bound via <c>DataContext</c> to the injected
/// <see cref="AnonymizedDnsViewModel"/> (wired by the shell). Code-behind is view PLUMBING only:
/// it forwards the toggles, the route builder's add/remove, and the two one-click banner fixes to
/// the unit-tested VM methods, and forwards Reload to <see cref="AnonymizedDnsViewModel.LoadAsync"/>.
/// All the policy — strict bundle on enable, stash timing, coverage/DoH/zero-pool honesty, the IC-9
/// save path — lives in the VM.
/// </summary>
public partial class AnonymizedDnsView
{
    public AnonymizedDnsView()
    {
        InitializeComponent();
        // Type-to-filter the builder combos. A WPF editable ComboBox only PREFIX-jumps as you type — with
        // 700+ relays that is unusable (a user typing 'odoh' still saw the whole anon-* list). This filters
        // the open dropdown to items CONTAINING the typed text, live. The server combo carries
        // RouteServerCandidate items; the via combo carries plain relay-name strings.
        AttachComboFilter(AddServerCombo, o => (o as RouteServerCandidate)?.Name ?? o?.ToString() ?? string.Empty);
        AttachComboFilter(AddViaCombo, o => o?.ToString() ?? string.Empty);
        // Default the relay to '*' (any compatible relay) — the reliable choice: the proxy picks a
        // working relay and skips dead ones, so a user who just picks a server and clicks Add doesn't
        // pin a single relay that may complete its handshake yet fail to carry queries (the exact trap
        // a hand-picked, latency-"OK"-but-dead relay causes). Reset to '*' on every server change below;
        // EditRoute deliberately seeds the row's existing relay instead.
        AddViaCombo.Text = DefaultVia;
    }

    /// <summary>The default relay for the add-route builder: '*' = any compatible relay (auto-pick).</summary>
    private const string DefaultVia = "*";

    /// <summary>Adds live "contains" filtering to an editable combo's dropdown, driven by the typed text.
    /// Filters only on genuine user typing (keyboard focus inside the combo) so a programmatic Text change
    /// — the VM repointing the via candidates, or a selection settling — never filters. The filter is
    /// cleared BOTH when the dropdown closes AND when keyboard focus leaves the combo, so a stale filter can
    /// never survive the user tabbing away mid-search (which would make the list look permanently emptied —
    /// the "names disappeared / the tabs seem linked" report). LostKeyboardFocus is the belt to
    /// DropDownClosed's braces: switching tabs while the popup is open does not reliably raise DropDownClosed,
    /// but it always moves keyboard focus.</summary>
    private static void AttachComboFilter(ComboBox combo, Func<object, string> textOf)
    {
        // Our filter is authoritative; disable WPF's built-in prefix auto-jump so it does not fight it.
        combo.IsTextSearchEnabled = false;
        combo.AddHandler(TextBoxBase.TextChangedEvent, new TextChangedEventHandler((_, _) =>
        {
            if (!combo.IsKeyboardFocusWithin) return;
            var view = combo.ItemsSource is null ? null : CollectionViewSource.GetDefaultView(combo.ItemsSource);
            if (view is null) return;
            var text = combo.Text ?? string.Empty;
            view.Filter = text.Length == 0
                ? null
                : o => textOf(o).Contains(text, StringComparison.OrdinalIgnoreCase);
            if (text.Length > 0 && !combo.IsDropDownOpen) combo.IsDropDownOpen = true;
        }));
        combo.DropDownClosed += (_, _) => ClearComboFilter(combo);
        // Belt to the braces: keyboard focus always leaves when the user tabs away or clicks another tab,
        // even in the cases where DropDownClosed does not fire (popup open at tab-switch). Clearing here
        // guarantees the next visit shows the full list.
        combo.LostKeyboardFocus += (_, _) => ClearComboFilter(combo);
    }

    private static void ClearComboFilter(ComboBox combo)
    {
        var view = combo.ItemsSource is null ? null : CollectionViewSource.GetDefaultView(combo.ItemsSource);
        if (view is not null) view.Filter = null;
    }

    private AnonymizedDnsViewModel? ViewModel => DataContext as AnonymizedDnsViewModel;

    /// <summary>Master enable toggle: stage enable (restore stash + strict bundle) / disable (empty routes).</summary>
    private void EnableToggle_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && sender is ToggleSwitch toggle)
        {
            vm.SetEnabled(toggle.IsChecked == true);
        }
    }

    /// <summary>Strict toggle: applies the strict bundle (there is no un-strict path — one-way hardening).</summary>
    private void StrictToggle_Click(object sender, RoutedEventArgs e)
    {
        ViewModel?.ApplyStrictFix();
    }

    /// <summary>The DoH banner's one-click fix: stage doh_servers=false (blocks on a resulting zero pool).</summary>
    private void ApplyDohFix_Click(object sender, RoutedEventArgs e)
    {
        ViewModel?.ApplyDohFix();
    }

    /// <summary>The strict banner's one-click fix: stage the strict bundle.</summary>
    private void ApplyStrictFix_Click(object sender, RoutedEventArgs e)
    {
        ViewModel?.ApplyStrictFix();
    }

    /// <summary>Adds a route from the builder combos. The server may be a candidate name or a typed
    /// value (incl. <c>*</c>); the via is the selected/typed relay (or <c>*</c>). The VM's IC-7 gate
    /// validates both and surfaces AddRouteError on a bad value — the view never validates.</summary>
    private void AddRoute_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm)
        {
            return;
        }

        var server = ReadComboValue(AddServerCombo);
        var via = ReadComboValue(AddViaCombo);
        if (string.IsNullOrWhiteSpace(server) || string.IsNullOrWhiteSpace(via))
        {
            return;
        }

        vm.AddRoute(server, new[] { via });
    }

    /// <summary>Removes the route row whose button carries it as <c>Tag</c>, by its current index.</summary>
    private void RemoveRoute_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm || sender is not FrameworkElement { Tag: RouteRowViewModel row })
        {
            return;
        }

        var index = IndexOfRoute(vm, row);
        if (index >= 0)
        {
            vm.RemoveRoute(index);
        }
    }

    /// <summary>Loads the route (its button carries it as <c>Tag</c>) back into the builder so the user can
    /// change its relay and click "Add route", which now replaces the row for that server. Repoints the via
    /// candidates via <see cref="AnonymizedDnsViewModel.SetBuilderServer"/>, then seeds the current relay (a
    /// single editable combo maps to one relay, so a multi-via route just seeds its first entry).</summary>
    private void EditRoute_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm || sender is not FrameworkElement { Tag: RouteRowViewModel row })
        {
            return;
        }

        AddServerCombo.Text = row.ServerName;
        vm.SetBuilderServer(row.ServerName);
        AddViaCombo.Text = row.Via.Count > 0 ? row.Via[0] : "*";
        AddViaCombo.Focus();
    }

    /// <summary>When a server candidate is picked, repoint the via combo to that server's proto-matched
    /// relay candidates (<c>*</c> + the relays whose proto pairs with the server's). This is what fills the
    /// relay picker — the combo had no ItemsSource before, so an ODoH server could never be paired with its
    /// relay. The VM computes the proto-matched set and surfaces an empty-state hint when only <c>*</c> remains.</summary>
    private void AddServerCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ViewModel?.SetBuilderServer(ReadComboValue(AddServerCombo));
        // Re-default the relay to '*' whenever the server changes (a picked server's proto-matched via
        // list was just repointed) — so the safe auto-relay is the standing default, not a stale pick.
        AddViaCombo.Text = DefaultVia;
    }

    /// <summary>The Conflict banner's [Reload] / the load-failure [Retry] — an explicit re-read (fail-closed).</summary>
    private async void ReloadButton_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm)
        {
            await vm.LoadAsync(CancellationToken.None).ConfigureAwait(true);
        }
    }

    private static string? ReadComboValue(ComboBox combo)
    {
        if (combo.SelectedItem is RouteServerCandidate server)
        {
            return server.Name;
        }

        if (combo.SelectedItem is RouteRelayCandidate relay)
        {
            return relay.Name;
        }

        if (combo.SelectedItem is string s)
        {
            return s;
        }

        return combo.Text;
    }

    private static int IndexOfRoute(AnonymizedDnsViewModel vm, RouteRowViewModel row)
    {
        var routes = vm.Routes;
        for (var i = 0; i < routes.Count; i++)
        {
            if (ReferenceEquals(routes[i], row))
            {
                return i;
            }
        }

        return -1;
    }
}
