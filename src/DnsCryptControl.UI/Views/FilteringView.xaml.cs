using System;
using System.Threading;
using System.Windows;
using DnsCryptControl.UI.ViewModels;
using ToggleSwitch = Wpf.Ui.Controls.ToggleSwitch;
using NumberBox = Wpf.Ui.Controls.NumberBox;

namespace DnsCryptControl.UI.Views;

/// <summary>
/// The Filtering tab's view (Phase 5d, D1). Bound via <c>DataContext</c> to the injected
/// <see cref="FilteringViewModel"/> (wired by the shell). Code-behind is view PLUMBING only (IC-5):
/// it forwards the per-family Enable/Save/Revert clicks and the block_*/reject_ttl/cloak_* toggle
/// edits to the unit-tested VM methods, and forwards Reload/Retry to
/// <see cref="FilteringViewModel.LoadAsync"/>. All the policy — the ordered enable-and-wire (IC-12),
/// the no-hijack of external files, staleness (IC-13), the IC-9 fresh read-modify-write for the
/// config keys, the strict per-family lint gate (IC-11), and every content-derived honesty banner
/// (IC-16) — lives in the VM. Async-void handlers route to fail-closed VM methods that never throw.
/// </summary>
public partial class FilteringView
{
    public FilteringView()
    {
        InitializeComponent();
    }

    private FilteringViewModel? ViewModel => DataContext as FilteringViewModel;

    /// <summary>Reads a control's <c>Tag</c> as one of the six rule families (set literally in XAML).</summary>
    private static bool TryFamily(object sender, out FilteringViewModel.RuleFamily family)
    {
        family = default;
        return sender is FrameworkElement { Tag: string tag }
            && Enum.TryParse(tag, out family);
    }

    /// <summary>Enable-and-wire a family (IC-12): writes its <c>.txt</c> then, on success, stages the
    /// <c>*_file</c> key. Refused (no-op in the VM) for an externally-managed family.</summary>
    private async void EnableFamily_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && TryFamily(sender, out var family))
        {
            await vm.EnableFamilyAsync(family, CancellationToken.None).ConfigureAwait(true);
        }
    }

    /// <summary>Save a family's edited <c>.txt</c> body (IC-13 no-CAS). The VM's own IsValid gate
    /// refuses a FATAL-lint text (IC-11) and surfaces the per-family error banner.</summary>
    private async void FamilySave_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && TryFamily(sender, out var family))
        {
            await vm.SaveFamilyFileAsync(family, CancellationToken.None).ConfigureAwait(true);
        }
    }

    /// <summary>Per-family Revert: a fresh re-read of every family + the config (the VM has no
    /// per-family revert — Load is the single fail-closed reset path, and it discards staged edits).</summary>
    private async void FamilyRevert_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm)
        {
            await vm.RevertAsync(CancellationToken.None).ConfigureAwait(true);
        }
    }

    /// <summary>Save &amp; apply the staged toggle + <c>*_file</c> config-key edits (IC-9).</summary>
    private async void ConfigSave_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm)
        {
            await vm.SaveConfigAsync(CancellationToken.None).ConfigureAwait(true);
        }
    }

    /// <summary>Revert the staged config edits (a full fresh reload).</summary>
    private async void ConfigRevert_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm)
        {
            await vm.RevertAsync(CancellationToken.None).ConfigureAwait(true);
        }
    }

    /// <summary>A boolean toggle's click stages the edit through the VM (block_ipv6 /
    /// block_unqualified / block_undelegated / cloak_ptr). The IsChecked binding is one-way — the
    /// toggle projects the effective staged-or-loaded value; the click is the only write path.</summary>
    private void BoolToggle_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && sender is ToggleSwitch { Tag: string key } toggle)
        {
            vm.StageToggleBool(key, toggle.IsChecked == true);
        }
    }

    /// <summary>An integer toggle (reject_ttl / cloak_ttl) commits on focus loss: the NumberBox has
    /// already validated its text into <see cref="NumberBox.Value"/> by the time this runs. A cleared
    /// / non-numeric box is ignored (the one-way binding snaps back on the next projection).</summary>
    private void LongBox_LostFocus(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm
            && sender is NumberBox { Tag: string key } box
            && box.Value is { } d
            && !double.IsNaN(d))
        {
            vm.StageToggleLong(key, (long)d);
        }
    }

    /// <summary>The Conflict banner's [Reload] and the load-failure [Retry]: an explicit fail-closed
    /// re-read that discards staged edits.</summary>
    private async void ReloadButton_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm)
        {
            await vm.LoadAsync(CancellationToken.None).ConfigureAwait(true);
        }
    }
}
