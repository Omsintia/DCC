using System;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// The Settings tab (Phase 5f) — the composition point for the appearance/startup/tray preferences
/// (persisted to the per-user <see cref="IUiStateStore"/>), the offline read-only integrity panel
/// (<see cref="IExeIntegrityReader"/> + a verdict derived ONLY from the helper's launch gate), and the
/// two-tier reset (soft <c>DisableProtection</c>; full <c>+ UninstallProxyService</c>, gated on a typed
/// confirmation AND a confirmed-successful soft reset).
///
/// <para>PURE POCO <see cref="ObservableObject"/> — zero WPF references; every post-await observable
/// write goes through <see cref="IUiDispatcher"/>. There is deliberately NO try/catch here: every
/// injected dependency is already fail-closed by contract (the helper returns <c>null</c> rather than
/// throwing; the store/registration/theme/integrity readers swallow their own I/O), so there is no
/// catch-all barrier to suppress — hence no CA1031 stanza is needed for this file.</para>
///
/// <para><b>Single source of pref intent:</b> <see cref="UiState"/> holds the intent; the HKCU Run key
/// is a write-through projection (<see cref="IStartupRegistration"/>). The checkboxes bind this VM only,
/// never the registry directly, so the two cannot drift (5e-VM-1 discipline).</para>
/// </summary>
public partial class SettingsViewModel : ObservableObject
{
    private readonly IUiStateStore _store;
    private readonly IStartupRegistration _startup;
    private readonly IThemeApplier _themeApplier;
    private readonly IExeIntegrityReader _integrity;
    private readonly IHelperClient _helper;
    private readonly IUiDispatcher _ui;
    private readonly string _proxyExePath;
    private readonly UiState _state;
    private readonly bool _loaded;
    private bool _suppressStartupHook;

    [ObservableProperty]
    private string _selectedTheme = "System";

    [ObservableProperty]
    private bool _startWithWindows;

    [ObservableProperty]
    private bool _startMinimized;

    [ObservableProperty]
    private bool _minimizeToTrayOnClose;

    [ObservableProperty]
    private string? _proxyExeDisplayPath;

    [ObservableProperty]
    private string? _proxyVersion;

    [ObservableProperty]
    private string? _proxySha256;

    [ObservableProperty]
    private bool _integrityVerified;

    [ObservableProperty]
    private string _integrityVerdict = "Not checked yet.";

    /// <summary>The typed confirmation gating the destructive "Remove proxy service" command.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RemoveProxyCommand))]
    private string _removeConfirmText = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasResetStatus))]
    private string? _resetStatus;

    /// <summary>Whether a reset result message is present (drives the result InfoBar's visibility without
    /// a value converter or a template-discarding local InfoBar style — 5c BasedOn discipline).</summary>
    public bool HasResetStatus => ResetStatus is not null;

    public SettingsViewModel(
        IUiStateStore store,
        IStartupRegistration startup,
        IThemeApplier themeApplier,
        IExeIntegrityReader integrity,
        IHelperClient helper,
        IUiDispatcher ui,
        string? proxyExePath = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(startup);
        ArgumentNullException.ThrowIfNull(themeApplier);
        ArgumentNullException.ThrowIfNull(integrity);
        ArgumentNullException.ThrowIfNull(helper);
        ArgumentNullException.ThrowIfNull(ui);
        _store = store;
        _startup = startup;
        _themeApplier = themeApplier;
        _integrity = integrity;
        _helper = helper;
        _ui = ui;
        _proxyExePath = proxyExePath ?? UiPaths.ProxyExeFile;

        // Seed from persisted state by assigning the BACKING FIELDS directly (not the properties), so the
        // change hooks below do not fire and re-persist/re-apply during construction. _loaded then arms them.
        _state = store.Load();
        _selectedTheme = _state.Theme ?? "System";
        _startWithWindows = _state.StartWithWindows;
        _startMinimized = _state.StartMinimized;
        _minimizeToTrayOnClose = _state.MinimizeToTrayOnClose;
        _loaded = true;

        // Reconcile the Run-key projection to the persisted intent (self-heal an out-of-band change —
        // Task Manager's Startup tab, regedit, an AV cleanup, or a ui-state.json copied from another
        // machine — so a checked box truly means "launches at logon"). Uses the read-back seam; best-effort
        // (StartupRegistration swallows hive I/O). Direct field/service calls, so no change hook fires.
        if (_startWithWindows && !_startup.IsRegistered()) _startup.Register();
        else if (!_startWithWindows && _startup.IsRegistered()) _startup.Unregister();
    }

    partial void OnSelectedThemeChanged(string value)
    {
        if (!_loaded) return;
        _state.Theme = value;
        _store.Save(_state);
        _themeApplier.Apply(value); // live apply
    }

    partial void OnStartWithWindowsChanged(bool value)
    {
        if (!_loaded || _suppressStartupHook) return;

        // Project to the registry FIRST; persist the intent only if the Run key accepted it. On a rejected
        // write (locked/denied hive) revert the toggle so the checkbox reflects reality and never shows an
        // intent the registry refused — the persisted pref and the real Run-key state can't silently drift.
        var ok = value ? _startup.Register() : _startup.Unregister();
        if (!ok)
        {
            _suppressStartupHook = true;
            StartWithWindows = !value;
            _suppressStartupHook = false;
            return;
        }

        _state.StartWithWindows = value;
        _store.Save(_state);
    }

    partial void OnStartMinimizedChanged(bool value)
    {
        if (!_loaded) return;
        _state.StartMinimized = value;
        _store.Save(_state);
    }

    partial void OnMinimizeToTrayOnCloseChanged(bool value)
    {
        if (!_loaded) return;
        _state.MinimizeToTrayOnClose = value;
        _store.Save(_state);
    }

    /// <summary>
    /// Read the installed proxy exe (path/version/local SHA-256, DISPLAY-ONLY) and derive the trust
    /// verdict from the helper's launch gate: a RUNNING proxy is proof the binary passed the helper's
    /// minisign + hash check. Never a UI-side pin compare (no false green). Doubles as "Re-hash now".
    /// </summary>
    [RelayCommand]
    private async Task RefreshIntegrityAsync(CancellationToken ct)
    {
        // Read off the UI thread: it hashes the (multi-MB) exe and, when the PE version is absent
        // (Go binary), launches a short-lived `-version` process — neither belongs on the UI thread.
        var info = await Task.Run(() => _integrity.Read(_proxyExePath), ct).ConfigureAwait(false);
        var status = await _helper.GetStatusAsync(ct).ConfigureAwait(false);
        // Attest ONLY from a version-matched helper: an incompatible-protocol helper cannot be trusted for
        // ANY field (the F20 handshake the Dashboard/Config also enforce), so its ProxyRunning must never
        // drive a green integrity verdict. running == false → "cannot attest", never a false green.
        var compatible = status is { Success: true, Value.ProtocolVersion: IpcProtocol.Version };
        var running = compatible && status!.Value!.ProxyRunning;
        _ui.Post(() =>
        {
            ProxyExeDisplayPath = info.Path;
            ProxyVersion = info.FileVersion;
            ProxySha256 = info.Sha256Hex;
            IntegrityVerified = running;
            IntegrityVerdict = running
                ? "Verified by the helper — the proxy is running, so the installed binary passed the minisign + hash launch gate."
                : "Cannot attest — the proxy is not running, unavailable, or on an incompatible version. A running, version-matched proxy is the proof the binary passed the helper's gate.";
        });
    }

    /// <summary>
    /// Soft reset: turn protection off and restore normal DNS via the atomic helper-owned teardown
    /// (<c>DisableProtection</c> — kill-switch off → mitigations off → restore DNS last), leaving the
    /// proxy installed. The UI never sequences DNS restore. A null reply is UNKNOWN, never success.
    /// </summary>
    [RelayCommand]
    private async Task SoftResetAsync(CancellationToken ct)
    {
        var result = await _helper.DisableProtectionAsync(ct).ConfigureAwait(false);
        _ui.Post(() => ResetStatus = result switch
        {
            { Success: true } => "Protection is off and your DNS is restored. The proxy is still installed — re-enable any time from the Dashboard.",
            null => "Couldn't confirm the reset — the helper didn't reply. Check the Dashboard before assuming anything changed.",
            _ => "Reset failed: " + result.Message,
        });
    }

    private bool CanRemoveProxy() => string.Equals(RemoveConfirmText, "REMOVE", StringComparison.Ordinal);

    /// <summary>
    /// Full reset: soft reset FIRST, then — only on a confirmed-successful soft reset AND the typed
    /// "REMOVE" confirmation — uninstall the proxy service. On a failed or UNKNOWN (null) soft reset the
    /// uninstall is skipped (fail-closed: never remove the service while DNS might still point at it).
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanRemoveProxy))]
    private async Task RemoveProxyAsync(CancellationToken ct)
    {
        // Re-check the typed confirmation in the BODY, not only via CanExecute: CommunityToolkit's
        // ICommand.Execute/ExecuteAsync run the delegate regardless of CanExecute (which only gates the
        // button's enabled visual). A keybinding / automation / programmatic invoke must NOT be able to
        // uninstall the proxy without "REMOVE" typed. Fail-closed on the irreversible action.
        if (!CanRemoveProxy())
        {
            _ui.Post(() => ResetStatus = "Type REMOVE to confirm before removing the proxy service.");
            return;
        }

        var soft = await _helper.DisableProtectionAsync(ct).ConfigureAwait(false);
        if (soft is not { Success: true })
        {
            _ui.Post(() => ResetStatus = soft is null
                ? "Couldn't confirm turning protection off — the service was NOT removed. Check the Dashboard."
                : "Couldn't turn protection off — the service was NOT removed: " + soft.Message);
            return; // fail-closed: no uninstall unless the soft reset is confirmed successful
        }

        var uninstall = await _helper.UninstallProxyServiceAsync(ct).ConfigureAwait(false);
        _ui.Post(() => ResetStatus = uninstall switch
        {
            { Success: true } => "Protection is off and the dnscrypt-proxy service has been removed.",
            null => "Protection is off, but removal couldn't be confirmed — the helper didn't reply.",
            _ => "Protection is off, but removing the service failed: " + uninstall.Message,
        });
    }
}
