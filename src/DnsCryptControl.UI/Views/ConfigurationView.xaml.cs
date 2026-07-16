using System.ComponentModel;
using System.Windows;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using DnsCryptControl.UI.ViewModels;
using NumberBox = Wpf.Ui.Controls.NumberBox;
using TextBox = System.Windows.Controls.TextBox;

namespace DnsCryptControl.UI.Views;

/// <summary>
/// The Configuration tab's view (F1, configuration-v2 mockup). Bound via
/// <c>DataContext</c> to the injected <c>ConfigurationViewModel</c> (wired by the shell
/// in F2). Code-behind is view PLUMBING only: it forwards editor commit events to
/// <see cref="ConfigurationViewModel.ApplyEdit"/> — the commit DECISIONS (what counts
/// as a real change, and the typed value) live in the unit-tested
/// <see cref="StructuredEditCommit"/>; the reload buttons forward to
/// <see cref="ConfigurationViewModel.LoadAsync"/> (E3: reloading after a Conflict is an
/// explicit user action, never automatic). Editors commit on focus loss: WPF invokes an
/// element's CLASS handlers before its instance handlers, so a <c>NumberBox</c> has
/// already validated its text into <c>Value</c> when these run. All value bindings on
/// text editors are TwoWay + Explicit: the binding never writes the source (the doc is
/// mutated ONLY through <c>ApplyEdit</c>, IC-1), it only projects the doc's value back
/// into the control.
/// </summary>
public partial class ConfigurationView
{
    public ConfigurationView()
    {
        InitializeComponent();
    }

    private ConfigurationViewModel? ViewModel => DataContext as ConfigurationViewModel;

    /// <summary>The 5g-2 deep-link's pending section name: non-null while one re-apply on the
    /// next VisibleSections replacement is armed (see <see cref="FocusSection"/>).</summary>
    private string? _pendingFocusSectionName;

    /// <summary>The VM instance whose PropertyChanged carries the armed re-apply — kept so the
    /// handler unsubscribes from the SAME instance it subscribed to (never leaks).</summary>
    private ConfigurationViewModel? _focusRetryViewModel;

    /// <summary>
    /// 5g-2 deep-link target: selects the named section in the section nav. Called by
    /// <see cref="MainWindow.NavigateToConfigurationSection"/> right after it selects the
    /// Configuration tab. Two-step by necessity (the spec-documented race): the tab selection
    /// just triggered the shell's async-void <c>OnTabActivatedAsync</c>, whose silent reload
    /// REPLACES <see cref="ConfigurationViewModel.VisibleSections"/> after this method returns —
    /// and the replacement resets the current-item-synchronized nav to the first section, undoing
    /// an immediate selection. So this applies the selection NOW and — only when the caller
    /// determined a reload is actually coming (<paramref name="armRetry"/>, read from
    /// <see cref="ConfigurationViewModel.WillReloadOnActivation"/> BEFORE the tab switch) — arms
    /// exactly one re-apply on the next VisibleSections change. Arming when no reload is coming
    /// (already-active tab, or a dirty/busy VM that refuses the silent reload) would leave a
    /// stale handler for the next filter keystroke to fire, yanking the selection back (WP2
    /// review finding). The handler unsubscribes after its first change (hit or miss) and on
    /// view unload, so it can never leak or re-fire.
    /// </summary>
    public void FocusSection(string name, bool armRetry)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (ViewModel is not { } vm)
        {
            return; // design-time / test host without a VM — nothing to focus.
        }

        TrySelectSection(vm, name);

        if (!armRetry)
        {
            return; // no VisibleSections replacement coming — the immediate apply is authoritative.
        }

        _pendingFocusSectionName = name;
        if (_focusRetryViewModel is null)
        {
            _focusRetryViewModel = vm;
            vm.PropertyChanged += OnFocusRetryPropertyChanged;
            Unloaded += OnUnloadedCancelFocusRetry;
        }
    }

    private void OnFocusRetryPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        // A FAILED activation reload never replaces VisibleSections (the failure path keeps
        // re-assigning the cached Array.Empty singleton, which raises no PropertyChanged) —
        // but it does set LoadError. Consume the one-shot as a miss on that signal, or the
        // handler would linger and fire on an arbitrarily later replacement, yanking the
        // user's own section choice (whole-branch review finding). Success sets LoadError
        // to null, which is skipped here so the normal re-apply below still runs.
        if (e.PropertyName == nameof(ConfigurationViewModel.LoadError))
        {
            if (_focusRetryViewModel?.LoadError is not null)
            {
                CancelFocusRetry();
            }

            return;
        }

        if (e.PropertyName != nameof(ConfigurationViewModel.VisibleSections))
        {
            return;
        }

        // One-shot: disarm FIRST, then re-apply against the fresh collection.
        var name = _pendingFocusSectionName;
        var vm = _focusRetryViewModel;
        CancelFocusRetry();
        if (name is not null && vm is not null)
        {
            TrySelectSection(vm, name);
        }
    }

    private void OnUnloadedCancelFocusRetry(object sender, RoutedEventArgs e) => CancelFocusRetry();

    private void CancelFocusRetry()
    {
        _pendingFocusSectionName = null;
        if (_focusRetryViewModel is not null)
        {
            _focusRetryViewModel.PropertyChanged -= OnFocusRetryPropertyChanged;
            _focusRetryViewModel = null;
            Unloaded -= OnUnloadedCancelFocusRetry;
        }
    }

    private void TrySelectSection(ConfigurationViewModel vm, string name)
    {
        if (SectionFocus.Find(vm.VisibleSections, name) is { } section)
        {
            SectionNav.SelectedItem = section;
        }
    }

    private void BoolEditor_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm
            || sender is not ToggleButton toggle
            || toggle.DataContext is not SettingEntryViewModel entry)
        {
            return;
        }

        if (StructuredEditCommit.TryPrepareBool(entry, toggle.IsChecked == true, out var value))
        {
            TryApplyEdit(vm, entry, value);
        }
    }

    private void StringEditor_LostFocus(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm
            || sender is not TextBox box
            || box.DataContext is not SettingEntryViewModel entry)
        {
            return;
        }

        if (StructuredEditCommit.TryPrepareText(entry, box.Text, out var value))
        {
            TryApplyEdit(vm, entry, value);
        }
        else
        {
            RefreshTargetBinding(box, TextBox.TextProperty);
        }
    }

    private void NumberEditor_LostFocus(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm
            || sender is not NumberBox box
            || box.DataContext is not SettingEntryViewModel entry)
        {
            return;
        }

        if (StructuredEditCommit.TryPrepareNumber(entry, box.Value, out var value))
        {
            TryApplyEdit(vm, entry, value);
        }
        else
        {
            // Uncommittable content (cleared/out-of-range box) or a no-change traversal:
            // snap the display back to the doc's current value.
            RefreshTargetBinding(box, NumberBox.ValueProperty);
        }
    }

    private void LinesEditor_LostFocus(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm
            || sender is not TextBox box
            || box.DataContext is not SettingEntryViewModel entry)
        {
            return;
        }

        if (StructuredEditCommit.TryPrepareLines(entry, box.Text, out var value))
        {
            TryApplyEdit(vm, entry, value);
        }
        else
        {
            RefreshTargetBinding(box, TextBox.TextProperty);
        }
    }

    /// <summary>The raw-only card's link into the Raw view (P5b-E3).</summary>
    private void OpenRawView_Click(object sender, RoutedEventArgs e)
    {
        RawViewToggle.IsChecked = true;
    }

    /// <summary>
    /// The Conflict banner's [Reload] and the load-failure banner's [Retry]: an EXPLICIT
    /// user re-read of the on-disk file (E3 — a Conflict never reloads automatically;
    /// the user's edits stay until they choose this). <c>LoadAsync</c> is fail-closed and
    /// never throws, so this async-void handler cannot fault the dispatcher.
    /// </summary>
    private async void ReloadButton_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm)
        {
            return;
        }

        await vm.LoadAsync(CancellationToken.None).ConfigureAwait(true);
    }

    private static void TryApplyEdit(ConfigurationViewModel vm, SettingEntryViewModel entry, object? value)
    {
        try
        {
            vm.ApplyEdit(entry, value);
        }
        catch (InvalidOperationException)
        {
            // A pending user raw edit that fails ApplyEdit's synchronous re-parse refuses
            // the structured edit and flips IsStructuredEditable off (E1) — the structured
            // pane greys itself out and the raw text keeps the user's change. Nothing to
            // do here; it must not escape into the dispatcher.
        }
    }

    private static void RefreshTargetBinding(DependencyObject element, DependencyProperty property) =>
        BindingOperations.GetBindingExpression(element, property)?.UpdateTarget();
}
