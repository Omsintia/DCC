using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Threading;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Views;

/// <summary>
/// Shell window. Code-behind is intentionally free of business logic beyond wiring the
/// system theme watcher and forwarding tab lifecycle to the tab view-models:
/// <see cref="DashboardViewModel.StartPolling"/> once on <see cref="Window.Loaded"/> (so
/// the Dashboard reflects ground truth from first paint even if the Dashboard tab is never
/// (re)selected — <c>TabView.SelectionChanged</c> does not reliably fire for the tab that is
/// already selected at load) AND on every selection back to the Dashboard tab;
/// <see cref="DashboardViewModel.StopPolling"/> when navigating away and on window close.
/// <see cref="DashboardViewModel.StartPolling"/> is itself idempotent, so these two start
/// paths can never race into two concurrent poll loops. Selecting the Configuration tab
/// forwards to <see cref="ConfigurationViewModel.OnTabActivatedAsync"/> (E3/F2: silent
/// freshness reload — the VM itself refuses while dirty or busy).
/// </summary>
public partial class MainWindow
{
    private readonly MainWindowViewModel _viewModel;
    private readonly IThemeApplier _themeApplier;
    private readonly IUiStateStore _uiState;

    /// <summary>Set by the tray "Quit" before closing so the close-to-tray intercept is bypassed and the
    /// app actually exits (a plain window close with the pref on hides to the tray instead).</summary>
    private bool _reallyExit;
    private System.Windows.Forms.NotifyIcon? _trayIcon;
    private System.Windows.Forms.ContextMenuStrip? _trayMenu;

    // Status-coloured tray glyphs, generated once and cached (green = verified, orange = leak,
    // grey = everything else). Any may be null if GDI generation failed, in which case the tray
    // keeps the branded exe icon. The window's own taskbar/alt-tab identity is unaffected.
    private System.Drawing.Icon? _trayIconGreen;
    private System.Drawing.Icon? _trayIconOrange;
    private System.Drawing.Icon? _trayIconGrey;

    // The Dashboard PropertyChanged subscription that drives the per-status tray glyph/tooltip.
    private PropertyChangedEventHandler? _dashboardStatusHandler;

    // Defer-show (white-flash fix): the FluentWindow is DWM-cloaked the instant its HWND exists and
    // uncloaked only once its first frame has actually rendered — so a cold launch composites the whole
    // window off-screen and never flashes an unpainted (white) frame before the theme+content paint lands.
    // This is belt-and-suspenders with WindowBackdropType.None (opaque backdrop) and ReadyToRun (cold JIT):
    // those removed the KNOWN white causes; the cloak guarantees no unpainted frame is ever presented at all.
    // Fail-safe: a backstop timer and every explicit show force a reveal, so the window can never get stuck
    // cloaked (invisible) even if ContentRendered never fires or the DWM call fails.
    private bool _revealed;
    private DispatcherTimer? _revealBackstop;

    public MainWindow(MainWindowViewModel viewModel, IThemeApplier themeApplier, IUiStateStore uiState)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        ArgumentNullException.ThrowIfNull(themeApplier);
        ArgumentNullException.ThrowIfNull(uiState);
        _viewModel = viewModel;
        _themeApplier = themeApplier;
        _uiState = uiState;
        // Phase 5f — theme setup spans the ctor and Loaded, and the ORDER is load-bearing:
        //  1. Prime() BEFORE InitializeComponent. It runs SystemThemeWatcher.Watch(this), which injects WPF-UI's
        //     accent resources (SystemAccentColorPrimary, ...) that the ControlsDictionary templates resolve via
        //     {StaticResource} while the window's XAML is PARSED — Apply(Light/Dark) does NOT inject them, so
        //     without priming first the parse throws and the app dies on launch. Restores pre-5f 5a–5e ordering.
        //  2. Apply(persisted) BEFORE InitializeComponent too, right after Prime. Content controls (ui:Card and
        //     the default-foreground text inside) bake their theme brushes when their template is applied during
        //     the parse and do NOT live-refresh on a later theme change — so the persisted theme must be active
        //     BEFORE the parse or the cards build light (white card + a later dark foreground = invisible text).
        //  3. Apply(persisted) AGAIN in MainWindow_Loaded. The FluentWindow chrome (title bar, tab strip) DOES
        //     live-update, but its own SourceInitialized theme init (on Show) runs after the ctor and can flip
        //     the chrome back to the OS theme; re-asserting after Show keeps chrome and content on the same
        //     theme. Apply un-watches for an explicit theme so it never fights the OS follower (invisible-text).
        _themeApplier.AttachWindow(this);
        _themeApplier.Prime();
        _themeApplier.Apply(_uiState.Load().Theme);
        InitializeComponent();
        DataContext = viewModel;
        CreateTrayIcon();
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
        Closed += MainWindow_Closed;
    }

    /// <summary>Defer-show step 1: cloak the window the moment its HWND exists — before it is ever presented
    /// on screen. WPF still renders into the (cloaked) DWM surface, so ContentRendered fires normally; the
    /// backstop timer guarantees the window is revealed even if it never does. Cloaking is transparent to WPF
    /// and independent of the (opaque, None) backdrop.</summary>
    protected override void OnSourceInitialized(EventArgs e)
    {
        SetCloak(true);
        base.OnSourceInitialized(e);

        // Absolute backstop: reveal after a short delay even if ContentRendered never fires (e.g. the window
        // is hidden to the tray before its first render on the "start minimised" path), so a launch can never
        // leave the window cloaked-and-invisible.
        _revealBackstop = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };
        _revealBackstop.Tick += (_, _) => Reveal();
        _revealBackstop.Start();
    }

    /// <summary>Defer-show step 2: the first frame is now on the DWM surface, so it is safe to reveal the
    /// window — the user's first sight of it is already fully painted, never a white unpainted frame.</summary>
    protected override void OnContentRendered(EventArgs e)
    {
        base.OnContentRendered(e);
        Reveal();
    }

    /// <summary>Uncloak the window exactly once (idempotent). Reached from the first content render, the
    /// backstop timer, and every explicit show — so the window can never stay cloaked/invisible.</summary>
    private void Reveal()
    {
        if (_revealed)
        {
            return;
        }

        _revealed = true;
        _revealBackstop?.Stop();
        _revealBackstop = null;
        SetCloak(false);
    }

    /// <summary>Set (or clear) the DWM cloak on this window's HWND. Fail-open: cloaking is a cosmetic
    /// first-paint nicety, so if the HWND isn't ready or the DWM API is unavailable/fails we fall back to the
    /// plain (pre-fix) behaviour rather than risk hiding the window.</summary>
    private void SetCloak(bool cloak)
    {
        try
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            if (hwnd == IntPtr.Zero)
            {
                return;
            }

            int value = cloak ? 1 : 0;
            _ = DwmSetWindowAttribute(hwnd, DWMWA_CLOAK, ref value, sizeof(int));
        }
        catch (Exception)
        {
            // best-effort only — never let a cloaking fault affect whether the window shows
        }
    }

    private const int DWMWA_CLOAK = 13;

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        // Phase 5f: RE-ASSERT the persisted theme after the window is sourced/shown (step 3 above). The ctor
        // already applied it before the parse so the content cards baked the right brushes; this second apply
        // corrects the FluentWindow chrome, whose own SourceInitialized theme init can flip it back to the OS
        // theme after the ctor. Chrome live-updates, so this is the last word for it. Fail-closed in the applier.
        _themeApplier.Apply(_uiState.Load().Theme);

        _viewModel.Dashboard.StartPolling();
        // Phase 5e (FIX HIGH-1, per-session model): query logging must never outlive the session that
        // enabled it. If a prior session (or a crash) left query_log.file SET, the LocalSystem proxy has
        // been appending the user's browsing history to the per-user query log — UNSHREDDED — the entire
        // time the app was closed. InitializeAtLaunchAsync runs ONCE here and HARD-RESETS logging to OFF:
        // it unsets the config key (stopping the proxy writing), purges any accumulated on-disk history,
        // and leaves the poller stopped. Fail-closed; fire-and-forget. NB: this is NOT LoadAsync — the
        // tab-activate LoadAsync (SelectionChanged) only reads+reconciles and must not reset the session.
        _ = _viewModel.QueryMonitor.InitializeAtLaunchAsync(CancellationToken.None);

        // Phase 5f: honour "start minimised to the tray" — hide after load so the tray icon (registered
        // on load) is the only surface. The single-instance activation path or the tray "Open" restores it.
        if (TrayPolicy.StartHidden(_viewModel.Settings.StartMinimized))
        {
            Hide();
        }
    }

    /// <summary>
    /// Phase 5f close-to-tray: when "keep running in the tray on close" is on and this is a real user
    /// close (not the tray "Quit", which sets <see cref="_reallyExit"/>), cancel the close and hide to the
    /// tray instead of exiting. The Dashboard poll loop keeps running while hidden (status stays fresh).
    /// </summary>
    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (TrayPolicy.OnUserClose(_viewModel.Settings.MinimizeToTrayOnClose, _reallyExit)
            == WindowCloseAction.HideToTray)
        {
            e.Cancel = true;
            Hide();
        }
    }

    /// <summary>Restore the window from the tray (Show + un-minimise + focus). Public so the single-instance
    /// activation callback can un-hide a tray-hidden window — a bare <c>Activate()</c> on a hidden window
    /// silently no-ops.</summary>
    public void ShowFromTray()
    {
        Reveal(); // never present a still-cloaked (invisible) window if activated during the initial cloak
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    /// <summary>Programmatic navigation to the Query Monitor tab (5g-4: the Dashboard's
    /// query-logging placeholder links land here). Public so tab views can route through the
    /// shell window (precedent: <see cref="ShowFromTray"/>); the views reach this via
    /// <c>Window.GetWindow(this)</c> in code-behind — ViewModels never see the window (MVVM
    /// boundary). The programmatic <c>SelectedItem</c> set raises <c>SelectionChanged</c> with
    /// <c>OriginalSource == ShellTabView</c>, so it passes the tab-identity guard in
    /// <see cref="ShellTabView_SelectionChanged"/> and runs the full existing lifecycle
    /// (IsActive flip, Dashboard StopPolling, Query Monitor LoadAsync) exactly like a user
    /// click. Navigation never enables logging — the consent gate is untouched.</summary>
    public void NavigateToQueryMonitor()
    {
        ShellTabView.SelectedItem = QueryMonitorTabItem;
    }

    /// <summary>Programmatic navigation to the Configuration tab plus a section-nav focus
    /// (5g-2: the Resolvers hint deep-links to "Server selection"). Same lifecycle guarantees
    /// as <see cref="NavigateToQueryMonitor"/>; the section focus is forwarded to
    /// <see cref="ConfigurationView.FocusSection"/>, which owns the retry across the
    /// tab-activation reload that replaces the section list.</summary>
    /// <param name="sectionName">The exact section (catalog group) name, e.g. "Server selection".</param>
    public void NavigateToConfigurationSection(string sectionName)
    {
        // Decide whether a tab-activation reload (which REPLACES VisibleSections) is coming
        // BEFORE the switch: activation flips IsBusy synchronously, so reading afterwards would
        // see busy on the very reload the focus must retry across. Conversely, arming with no
        // reload coming leaves a stale handler that the next filter keystroke would fire,
        // yanking the user's section selection back (WP2 review finding).
        var activationPending = !ReferenceEquals(ShellTabView.SelectedItem, ConfigurationTabItem);
        var armRetry = activationPending && _viewModel.Configuration.WillReloadOnActivation;

        ShellTabView.SelectedItem = ConfigurationTabItem;
        if (ConfigurationTabItem.Content is ConfigurationView configurationView)
        {
            configurationView.FocusSection(sectionName, armRetry);
        }
    }

    /// <summary>Programmatic navigation to the Anonymized DNS tab (the Resolvers relay-guidance
    /// deep-link — relays are used here, not in the server pool). Same lifecycle guarantees as
    /// <see cref="NavigateToQueryMonitor"/>: the <c>SelectedItem</c> set raises the guarded
    /// <c>SelectionChanged</c> and runs the tab's normal activation.</summary>
    public void NavigateToAnonymizedDns()
    {
        ShellTabView.SelectedItem = AnonymizedDnsTabItem;
    }

    /// <summary>The Resolvers "Route through a relay" shortcut: record a pending route request for
    /// <paramref name="serverName"/>, THEN switch to the Anonymized DNS tab. The tab's own activation
    /// lifecycle picks up the pending server and stages a route for it once its candidates are loaded —
    /// so the route lands with the matching relays available and no cross-dispatch ordering race.</summary>
    public void NavigateToAnonymizedDnsRoute(string serverName)
    {
        _viewModel.AnonymizedDns.PendingRouteServer = serverName;
        ShellTabView.SelectedItem = AnonymizedDnsTabItem;
    }

    /// <summary>
    /// Build the notification-area tray icon. WPF-UI 4.x dropped its NotifyIcon, so this uses the WinForms
    /// one (under UseWindowsForms) driven by the WPF message pump. Right-click → Open / Quit; double-click →
    /// Open. Owned by the window and disposed on real close. The icon is the branded one extracted from
    /// the exe's <c>ApplicationIcon</c>, falling back (fail-closed) to <c>SystemIcons.Application</c>.
    /// </summary>
    private void CreateTrayIcon()
    {
        _trayMenu = new System.Windows.Forms.ContextMenuStrip();
        _trayMenu.Items.Add("Open DnsCrypt Control", null, (_, _) => ShowFromTray());
        _trayMenu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
        _trayMenu.Items.Add("Quit", null, (_, _) =>
        {
            _reallyExit = true;
            Close();
        });

        // Branded shield/DCC icon: extracted from the exe (ApplicationIcon), so the tray,
        // Explorer and the taskbar all show the same identity. Fail-closed to the generic
        // icon if extraction ever fails (e.g. an unusual host process path).
        System.Drawing.Icon trayGlyph;
        try
        {
            trayGlyph = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath!)
                        ?? System.Drawing.SystemIcons.Application;
        }
        catch (Exception)
        {
            trayGlyph = System.Drawing.SystemIcons.Application;
        }

        _trayIcon = new System.Windows.Forms.NotifyIcon
        {
            Icon = trayGlyph,
            Text = "DnsCrypt Control",
            Visible = true,
            ContextMenuStrip = _trayMenu,
        };
        _trayIcon.DoubleClick += (_, _) => ShowFromTray();

        // Feature: the tray colour follows protection state at a glance. Generate the three status
        // glyphs up-front (fail-safe: a null means keep the branded icon for that state), then bind to
        // the Dashboard's Status and prime the initial state so the tray is correct from first paint.
        _trayIconGreen = TrayIconFactory.ForStatus(TrayIconFactory.TrayStatus.Protected);
        _trayIconOrange = TrayIconFactory.ForStatus(TrayIconFactory.TrayStatus.Warning);
        _trayIconGrey = TrayIconFactory.ForStatus(TrayIconFactory.TrayStatus.Neutral);

        _dashboardStatusHandler = OnDashboardPropertyChanged;
        _viewModel.Dashboard.PropertyChanged += _dashboardStatusHandler;
        UpdateTrayForStatus(_viewModel.Dashboard.Status);
    }

    /// <summary>Re-colour the tray glyph and update its tooltip when the Dashboard's protection status
    /// changes. The VM raises PropertyChanged on the UI thread (via its <c>_ui.Post</c>), but marshal
    /// defensively so a future off-thread raise can never touch the NotifyIcon from a non-UI thread.</summary>
    private void OnDashboardPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        // A null PropertyName means "everything changed" and must also refresh the tray.
        if (e.PropertyName is not null && e.PropertyName != nameof(DashboardViewModel.Status))
        {
            return;
        }

        if (Dispatcher.CheckAccess())
        {
            UpdateTrayForStatus(_viewModel.Dashboard.Status);
        }
        else
        {
            _ = Dispatcher.BeginInvoke(() => UpdateTrayForStatus(_viewModel.Dashboard.Status));
        }
    }

    /// <summary>Map a protection status to the cached tray glyph (green = verified, orange = leak, grey
    /// otherwise) and a matching tooltip. Fail-safe: if the mapped glyph is null (GDI generation failed)
    /// the current icon — the branded exe glyph — is kept rather than blanking the tray. No-op when the
    /// tray icon has already been disposed.</summary>
    private void UpdateTrayForStatus(ProtectionStatusView status)
    {
        if (_trayIcon is null)
        {
            return;
        }

        var glyph = status switch
        {
            ProtectionStatusView.ProtectedVerified => _trayIconGreen,
            ProtectionStatusView.PartiallyProtected => _trayIconOrange,
            _ => _trayIconGrey,
        };

        if (glyph is not null)
        {
            _trayIcon.Icon = glyph;
        }

        _trayIcon.Text = status switch
        {
            ProtectionStatusView.ProtectedVerified => "DnsCrypt Control - Protected",
            ProtectionStatusView.PartiallyProtected => "DnsCrypt Control - Leak detected",
            ProtectionStatusView.ProxyStopped => "DnsCrypt Control - Proxy stopped",
            ProtectionStatusView.Unprotected => "DnsCrypt Control - Not protected",
            _ => "DnsCrypt Control",
        };
    }

    /// <summary>
    /// Tab-identity-guarded (F2): <c>SelectionChanged</c> is a bubbling routed event, so
    /// selectors INSIDE a tab's content (e.g. the Configuration section-nav ListBox)
    /// re-raise it up to the TabView — only the shell TabView's OWN selection changes may
    /// drive tab lifecycle, otherwise a nav click inside Configuration would spuriously
    /// re-activate the tab (and, before this guard, re-start Dashboard polling paths).
    /// Each action is further guarded by WHICH tab is now selected, so the Dashboard poll
    /// loop can never be double-started by a Configuration activation or vice versa.
    /// Async-void is safe here: <c>OnTabActivatedAsync</c> routes to the fail-closed
    /// <c>LoadAsync</c>, which never throws.
    /// </summary>
    private async void ShellTabView_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!ReferenceEquals(e.OriginalSource, ShellTabView))
        {
            return;
        }

        // Phase 5e: the Query Monitor's live view only updates while its tab is showing (IsActive). The
        // read-and-shred poller itself keeps running whenever logging is enabled regardless of this flag
        // (QueryMonitorViewModel) — IsActive gates only whether ticks are appended to the display.
        _viewModel.QueryMonitor.IsActive =
            ReferenceEquals(ShellTabView.SelectedItem, QueryMonitorTabItem);

        if (ReferenceEquals(ShellTabView.SelectedItem, DashboardTabItem))
        {
            _viewModel.Dashboard.StartPolling();
            return;
        }

        _viewModel.Dashboard.StopPolling();

        if (ReferenceEquals(ShellTabView.SelectedItem, ConfigurationTabItem))
        {
            await _viewModel.Configuration.OnTabActivatedAsync().ConfigureAwait(true);
        }
        else if (ReferenceEquals(ShellTabView.SelectedItem, ResolversTabItem))
        {
            await _viewModel.Resolvers.OnTabActivatedAsync().ConfigureAwait(true);
        }
        else if (ReferenceEquals(ShellTabView.SelectedItem, AnonymizedDnsTabItem))
        {
            await _viewModel.AnonymizedDns.OnTabActivatedAsync().ConfigureAwait(true);
        }
        else if (ReferenceEquals(ShellTabView.SelectedItem, FilteringTabItem))
        {
            await _viewModel.Filtering.OnTabActivatedAsync().ConfigureAwait(true);
        }
        else if (ReferenceEquals(ShellTabView.SelectedItem, QueryMonitorTabItem))
        {
            await _viewModel.QueryMonitor.LoadAsync(CancellationToken.None).ConfigureAwait(true);
        }
        else if (ReferenceEquals(ShellTabView.SelectedItem, LogsDiagnosticsTabItem))
        {
            await _viewModel.LogsDiagnostics.RefreshAsync(CancellationToken.None).ConfigureAwait(true);
        }
    }

    private void MainWindow_Closed(object? sender, EventArgs e)
    {
        _revealBackstop?.Stop();
        _revealBackstop = null;
        _viewModel.Dashboard.StopPolling();
        DisposeTrayIcon();
    }

    /// <summary>Remove + dispose the tray icon. Idempotent and safe to call from both the window's Closed
    /// handler and the App.OnExit / startup-crash backstops — a WinForms NotifyIcon needs an explicit
    /// Dispose to clear the shell icon, so relying only on Closed would leak a ghost icon on paths that
    /// bypass it.</summary>
    public void DisposeTrayIcon()
    {
        if (_dashboardStatusHandler is not null)
        {
            _viewModel.Dashboard.PropertyChanged -= _dashboardStatusHandler;
            _dashboardStatusHandler = null;
        }

        if (_trayIcon is not null)
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            _trayIcon = null;
        }

        _trayMenu?.Dispose();
        _trayMenu = null;

        // Dispose the cached status glyphs AFTER the NotifyIcon (which referenced one via .Icon) is gone.
        _trayIconGreen?.Dispose();
        _trayIconGreen = null;
        _trayIconOrange?.Dispose();
        _trayIconOrange = null;
        _trayIconGrey?.Dispose();
        _trayIconGrey = null;
    }
}
