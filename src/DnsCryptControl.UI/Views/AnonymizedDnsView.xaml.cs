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

    /// <summary>Adds a route from the builder. The server may be a candidate name or a typed value
    /// (incl. <c>*</c>). The via is the staged multi-relay chips PLUS any non-blank value still in the
    /// via combo (staged first via <see cref="AnonymizedDnsViewModel.AddViaRelay"/>, whose dedupe and
    /// <c>*</c>-exclusivity rules apply) — the Edit-a-route flow seeds the chips and the user's newest
    /// pick sits in the combo, so silently discarding it would re-add the unchanged route with zero
    /// feedback. With no chips, the combo's single selected/typed relay is the zero-extra-clicks quick
    /// path. The VM's IC-7 gate validates everything and surfaces AddRouteError — the view never
    /// validates (a combo value the VM refuses to stage is passed through so that gate names it).</summary>
    private void AddRoute_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm)
        {
            return;
        }

        var server = ReadComboValue(AddServerCombo);
        if (string.IsNullOrWhiteSpace(server))
        {
            return;
        }

        if (vm.AddViaSelection.Count > 0)
        {
            // A non-blank combo value beside staged chips is the user's newest pick — stage it too.
            var typedVia = ReadComboValue(AddViaCombo);
            if (!string.IsNullOrWhiteSpace(typedVia) && !vm.AddViaRelay(typedVia))
            {
                // The VM refused to stage it (invalid value): hand chips + typed to AddRoute so its
                // IC-7 gate names the offending value in AddRouteError instead of dropping it silently.
                vm.AddRoute(server, vm.AddViaSelection.Append(typedVia!).ToList());
                return;
            }

            // Staged (or blank) — the chips now carry everything; clear the consumed combo value.
            AddViaCombo.SelectedItem = null;
            AddViaCombo.Text = string.Empty;

            // Snapshot the chips: a successful AddRoute clears AddViaSelection, and passing the live
            // collection would hand the VM a list it is about to empty.
            vm.AddRoute(server, vm.AddViaSelection.ToList());
            return;
        }

        var via = ReadComboValue(AddViaCombo);
        if (string.IsNullOrWhiteSpace(via))
        {
            return;
        }

        vm.AddRoute(server, new[] { via });
    }

    /// <summary>The builder's "+ Add relay": stages the via combo's current relay as a chip in the
    /// multi-relay list, then resets the combo for the next pick. All the rules (trim, validity gate,
    /// case-insensitive dedupe, <c>*</c>-exclusivity) live in the unit-tested
    /// <see cref="AnonymizedDnsViewModel.AddViaRelay"/> — this handler only reads the combo, and only
    /// clears it when the VM reports the relay staged (a refused value keeps the user's text in place
    /// to fix, instead of silently wiping it). SelectedItem is nulled BEFORE the text so a stale
    /// selection can't shadow the cleared text on the next read.</summary>
    private void AddRelay_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm)
        {
            return;
        }

        var via = ReadComboValue(AddViaCombo);
        if (string.IsNullOrWhiteSpace(via))
        {
            return;
        }

        if (vm.AddViaRelay(via))
        {
            AddViaCombo.SelectedItem = null;
            AddViaCombo.Text = string.Empty;
        }
    }

    /// <summary>A staged relay chip's ✕ button (carries the relay as <c>Tag</c>): unstages that relay.</summary>
    private void RemoveRelay_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && sender is FrameworkElement { Tag: string relay })
        {
            vm.RemoveViaRelay(relay);
        }
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
    /// change its relays and click "Add route", which replaces the row for that server. Repoints the via
    /// candidates via <see cref="AnonymizedDnsViewModel.SetBuilderServer"/>, then seeds the FULL via list
    /// into the chip-adder via <see cref="AnonymizedDnsViewModel.SeedViaSelection"/> — the old single-combo
    /// seed kept only <c>via[0]</c>, so editing a multi-relay route silently DROPPED relays 2..N on re-add.
    /// The via combo is cleared (chips now carry the route's relays) and focused for the next pick — except
    /// a route whose via list is EMPTY (a hand-edited <c>via=[]</c> the codec accepts): zero chips plus an
    /// empty combo would make "Add route" a silent no-op, so that branch defaults the combo to <c>*</c>
    /// (any compatible relay), as the pre-chip-list builder did.</summary>
    private void EditRoute_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm || sender is not FrameworkElement { Tag: RouteRowViewModel row })
        {
            return;
        }

        AddServerCombo.Text = row.ServerName;
        vm.SetBuilderServer(row.ServerName);
        vm.SeedViaSelection(row.Via);
        AddViaCombo.SelectedItem = null;
        AddViaCombo.Text = row.Via.Count > 0 ? string.Empty : DefaultVia;
        AddViaCombo.Focus();
    }

    /// <summary>When a server candidate is picked, repoint the via combo to that server's proto-matched
    /// relay candidates (<c>*</c> + the relays whose proto pairs with the server's). This is what fills the
    /// relay picker — the combo had no ItemsSource before, so an ODoH server could never be paired with its
    /// relay. The VM computes the proto-matched set and surfaces an empty-state hint when only <c>*</c> remains.</summary>
    private void AddServerCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // SetBuilderServer also clears the staged relay CHIPS on a genuine server change (a chip picked
        // for the old server's proto could pair a mismatched relay, which silently kills the server).
        ViewModel?.SetBuilderServer(ReadComboValue(AddServerCombo));
        // Re-default the relay to '*' whenever the server changes (a picked server's proto-matched via
        // list was just repointed) — so the safe auto-relay is the standing default, not a stale pick.
        // SelectedItem is nulled first: a prior selection surviving the ItemsSource repoint would shadow
        // the '*' text on the next ReadComboValue.
        AddViaCombo.SelectedItem = null;
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
