using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using DnsCryptControl.Core.Security;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// The Logs &amp; Diagnostics tab (Phase 5e, design 3.1/3.2). A lower-risk operational surface with NO
/// browsing history: it projects a health snapshot from the SAME read-only status the Dashboard consumes
/// (<see cref="IHelperClient.GetStatusAsync"/> → <see cref="StatusResponse"/> + the off-disk protection
/// intent), offers an opt-in "capture proxy log" toggle that sets <c>log_file</c>/<c>log_level</c> via
/// the existing config Save path, tails that operational log read-only, and copies a health TEXT bundle
/// that EXCLUDES any query data (IC-QM6).
///
/// <para>No new IPC verb (IC-2): everything is a read of the existing status DTO + config edits through
/// the existing Save path + UI-side file I/O. Pure POCO <see cref="ObservableObject"/> (IC-5): zero WPF
/// types; every post-await observable write goes through the injected <see cref="IUiDispatcher"/>.
/// Fail-closed: a helper/read fault degrades to an "unknown/unavailable" snapshot, never a throw.</para>
/// </summary>
public sealed partial class LogsDiagnosticsViewModel : ObservableObject
{
    /// <summary>The proxy log tail cap — enough recent lines to diagnose without buffering the file.</summary>
    private const int TailLineCap = 200;

    private readonly IHelperClient _helper;
    private readonly IProtectionStateReader _stateReader;
    private readonly IActiveResolverReader _resolverReader;
    private readonly IConfigFileService _configFile;
    private readonly ILogTailReader _logTail;
    private readonly IUiDispatcher _ui;

    /// <summary>The directory the untrusted <c>log_file</c> must be confined to before the UI tails it (the
    /// proxy's ProgramData working dir; injectable for tests). See <see cref="LogFilePathGuard"/>.</summary>
    private readonly string _proxyLogBaseDir;

    // ---- health snapshot (design 3.1) ----

    [ObservableProperty]
    private bool _helperReachable;

    [ObservableProperty]
    private bool _proxyRunning;

    [ObservableProperty]
    private bool _protectionEnabled;

    [ObservableProperty]
    private bool _killSwitchEnabled;

    [ObservableProperty]
    private bool _leakMitigationsEnabled;

    /// <summary>The helper's reported protocol version (0 when unreachable). A mismatch with
    /// <see cref="IpcProtocol.Version"/> is surfaced as a caveat — a skewed helper's other fields are
    /// untrustworthy (mirrors the Dashboard's F20 handshake gate).</summary>
    [ObservableProperty]
    private int _helperProtocolVersion;

    /// <summary>True when the helper's protocol version does not match this app's (version skew).</summary>
    [ObservableProperty]
    private bool _helperVersionMismatch;

    /// <summary>The helper's build string (empty when unreachable).</summary>
    [ObservableProperty]
    private string _helperBuild = string.Empty;

    /// <summary>The active resolver display name (the config's first <c>server_names</c> entry), read via
    /// the SAME <see cref="IActiveResolverReader"/> the Dashboard uses so the two views never disagree
    /// (null when the config has none / is unreadable).</summary>
    [ObservableProperty]
    private string? _activeResolver;

    /// <summary>The last-refreshed timestamp (UTC) for the health snapshot, or null before the first load.</summary>
    [ObservableProperty]
    private DateTimeOffset? _lastRefreshedUtc;

    // ---- proxy-log capture (design 3.2) ----

    /// <summary>True when the config's <c>log_file</c> is set (proxy log capture is ON). Off = "not
    /// captured; enable to see proxy diagnostics".</summary>
    [ObservableProperty]
    private bool _proxyLogCaptured;

    /// <summary>The captured proxy-log path (the <c>log_file</c> value), or null when not captured.</summary>
    [ObservableProperty]
    private string? _proxyLogPath;

    /// <summary>The read-only tail of the captured proxy log (oldest first; empty when not captured).</summary>
    public ObservableCollection<string> ProxyLogTail { get; } = new();

    /// <summary>The "not captured" banner (non-null when capture is off): tells the user to enable it.</summary>
    [ObservableProperty]
    private string? _notCapturedBanner = NotCapturedBannerText;

    /// <summary>Single busy owner: true while a capture-toggle config write is in flight.</summary>
    [ObservableProperty]
    private bool _isBusy;

    /// <summary>The verbatim reason the last capture-toggle write failed, or null on success.</summary>
    [ObservableProperty]
    private string? _configError;

    public LogsDiagnosticsViewModel(
        IHelperClient helper,
        IProtectionStateReader stateReader,
        IActiveResolverReader resolverReader,
        IConfigFileService configFile,
        ILogTailReader logTail,
        IUiDispatcher ui,
        string? proxyLogBaseDir = null)
    {
        ArgumentNullException.ThrowIfNull(helper);
        ArgumentNullException.ThrowIfNull(stateReader);
        ArgumentNullException.ThrowIfNull(resolverReader);
        ArgumentNullException.ThrowIfNull(configFile);
        ArgumentNullException.ThrowIfNull(logTail);
        ArgumentNullException.ThrowIfNull(ui);
        _helper = helper;
        _stateReader = stateReader;
        _resolverReader = resolverReader;
        _configFile = configFile;
        _logTail = logTail;
        _ui = ui;
        _proxyLogBaseDir = proxyLogBaseDir ?? UiPaths.ProgramDataDir;
    }

    // --------------------------------------------------------------- health snapshot (design 3.1)

    /// <summary>
    /// Refreshes the whole tab: the health snapshot from the helper's status + off-disk protection intent,
    /// and the proxy-log capture state (+ tail) from config. Fail-closed: a helper/read fault degrades to
    /// an "unavailable" snapshot rather than throwing. Runs the status call off the UI thread; publishes
    /// in dispatcher posts.
    /// </summary>
    public async Task RefreshAsync(CancellationToken ct)
    {
        // Off-disk protection intent is authoritative even when the helper is down (mirrors Dashboard).
        var intent = _stateReader.Read();

        Result<StatusResponse>? status;
        try
        {
            status = await _helper.GetStatusAsync(ct).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Fail-closed: any helper fault is an unreachable helper, never a throw. CA1031 is suppressed
            // for this file in .editorconfig (safety concern for this OPSEC tool).
            status = null;
        }

        var captureSnapshot = await Task.Run(LoadCaptureState, ct).ConfigureAwait(false);
        // FIX 5e-VM-1: the active-resolver display name is a CONFIG value (server_names[0]), read via the
        // SAME UI-side reader the Dashboard uses — NOT the helper's StatusResponse.ActiveResolver, which
        // came back empty and made the Logs health show "(none)" while the Dashboard showed the real
        // resolver (a §1.2 mismatch). We are off the UI thread here (ConfigureAwait(false)); the read is a
        // quick, fail-closed file read.
        var resolverName = _resolverReader.ReadPrimaryName();

        _ui.Post(() =>
        {
            ProtectionEnabled = intent.ProtectionEnabled;

            if (status is null || !status.Success || status.Value is null)
            {
                HelperReachable = false;
                ProxyRunning = false;
                KillSwitchEnabled = false;
                LeakMitigationsEnabled = false;
                HelperProtocolVersion = 0;
                HelperVersionMismatch = false;
                HelperBuild = string.Empty;
            }
            else
            {
                var s = status.Value;
                HelperReachable = true;
                ProxyRunning = s.ProxyRunning;
                KillSwitchEnabled = s.KillSwitchEnabled;
                LeakMitigationsEnabled = s.LeakMitigationsEnabled;
                HelperProtocolVersion = s.ProtocolVersion;
                HelperVersionMismatch = s.ProtocolVersion != IpcProtocol.Version;
                HelperBuild = s.HelperBuild;
            }

            // Config-derived; shown independent of helper reachability (matches the Dashboard's line).
            ActiveResolver = resolverName;

            ApplyCaptureState(captureSnapshot);
            // FIX view LOW-2: the property is named ...Utc and the label says "(UTC)", so record the
            // UTC instant — not local — so the value matches its name and label.
            LastRefreshedUtc = DateTimeOffset.UtcNow;
        });
    }

    // --------------------------------------------------------------- proxy-log capture (design 3.2)

    /// <summary>
    /// Enables opt-in proxy-log capture (design 3.2): sets <c>log_file</c> to a ProgramData path (the
    /// operational log is Users-readable, lower sensitivity than the query log) + <c>log_level</c> via the
    /// same fresh read-modify-write + Save path, then refreshes the capture state + tail. No-op while busy
    /// or already capturing. Never throws.
    /// </summary>
    public Task EnableProxyLogCaptureAsync(CancellationToken ct)
    {
        if (IsBusy || ProxyLogCaptured)
        {
            return Task.CompletedTask;
        }

        var target = UiPaths.ProxyLogFile;
        return WriteCaptureConfigAsync(
            edit: doc =>
            {
                doc.SetString("log_file", target);
                doc.SetLong("log_level", DefaultLogLevel);
            },
            ct);
    }

    /// <summary>
    /// Disables proxy-log capture: unsets <c>log_file</c> so the proxy stops writing the operational log,
    /// then refreshes the capture state + tail. No-op while busy or already not capturing. Never throws.
    /// </summary>
    public Task DisableProxyLogCaptureAsync(CancellationToken ct)
    {
        if (IsBusy || !ProxyLogCaptured)
        {
            return Task.CompletedTask;
        }

        return WriteCaptureConfigAsync(edit: doc => doc.RemoveKey("log_file"), ct);
    }

    private async Task WriteCaptureConfigAsync(Action<Core.Toml.TomlConfigDocument> edit, CancellationToken ct)
    {
        IsBusy = true;
        ConfigError = null;
        try
        {
            var prepared = await Task.Run(() => PrepareCaptureWrite(edit), ct).ConfigureAwait(false);
            if (!prepared.Success)
            {
                _ui.Post(() => ConfigError = prepared.Error);
                return;
            }

            ConfigSaveOutcome outcome;
            try
            {
                outcome = await _configFile
                    .SaveAndApplyAsync(prepared.CandidateText!, prepared.BaseSha256!, ct)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _ui.Post(() => ConfigError = "the save could not be sent to the helper (" + MessageScrub.Redact(ex.Message) + ").");
                return;
            }

            var landed = outcome.Kind is ConfigSaveOutcomeKind.Applied
                or ConfigSaveOutcomeKind.RestartFailed
                or ConfigSaveOutcomeKind.ProxyRejected;

            if (!landed)
            {
                _ui.Post(() => ConfigError = outcome.Message ?? "the change could not be saved.");
                return;
            }

            var caveat = outcome.Kind == ConfigSaveOutcomeKind.Applied ? null : outcome.Message;
            var captureSnapshot = await Task.Run(LoadCaptureState, ct).ConfigureAwait(false);
            _ui.Post(() =>
            {
                ConfigError = caveat;
                ApplyCaptureState(captureSnapshot);
            });
        }
        finally
        {
            _ui.Post(() => IsBusy = false);
        }
    }

    /// <summary>Off-thread: read config, apply the capture edit, and prepare the candidate + fresh sha.
    /// Never throws — any fault becomes a typed failure.</summary>
    private CaptureWriteResult PrepareCaptureWrite(Action<Core.Toml.TomlConfigDocument> edit)
    {
        ConfigLoadResult load;
        try
        {
            load = _configFile.Load();
        }
        catch (Exception ex)
        {
            return CaptureWriteResult.Failed("the config could not be read (" + MessageScrub.Redact(ex.Message) + ").");
        }

        if (!load.Success || load.Text is null || load.Sha256 is null)
        {
            return CaptureWriteResult.Failed(MessageScrub.Redact(load.Error) ?? "the config could not be read.");
        }

        Core.Toml.TomlConfigDocument doc;
        try
        {
            doc = Core.Toml.TomlConfigDocument.Parse(load.Text);
        }
        catch (Exception ex)
        {
            return CaptureWriteResult.Failed("the on-disk config could not be parsed (" + MessageScrub.Redact(ex.Message) + ").");
        }

        if (doc.HasErrors)
        {
            return CaptureWriteResult.Failed(
                "the on-disk config has TOML errors — fix it in the Configuration tab first.");
        }

        try
        {
            edit(doc);
        }
        catch (Exception ex)
        {
            return CaptureWriteResult.Failed("the change could not be applied (" + MessageScrub.Redact(ex.Message) + ").");
        }

        return CaptureWriteResult.Ready(doc.ToText(), load.Sha256);
    }

    /// <summary>Off-thread: read the config's <c>log_file</c>, and (when set) read the tail of that file.
    /// Never throws — any fault reads as "not captured".</summary>
    private CaptureState LoadCaptureState()
    {
        string? logFile = null;
        try
        {
            var load = _configFile.Load();
            if (load.Success && load.Text is not null)
            {
                var doc = Core.Toml.TomlConfigDocument.Parse(load.Text);
                if (!doc.HasErrors && doc.TryGetString("log_file", out var value) && !string.IsNullOrEmpty(value))
                {
                    logFile = value;
                }
            }
        }
        catch (Exception)
        {
            logFile = null;
        }

        if (logFile is null)
        {
            return new CaptureState(false, null, Array.Empty<string>());
        }

        // Confine the (untrusted) config log_file to the proxy dir before reading it: a crafted log_file
        // must never turn this read-only tail into an arbitrary-file reader in the unprivileged UI
        // (finding 2026-07-08). The path shown to the user stays the raw config value; only the READ is guarded.
        var safePath = LogFilePathGuard.ConfineToBase(logFile, _proxyLogBaseDir);
        var tail = safePath is null ? Array.Empty<string>() : _logTail.ReadTail(safePath, TailLineCap);
        return new CaptureState(true, logFile, tail);
    }

    /// <summary>Publishes a loaded capture state onto the observable surfaces (UI-thread-affine).</summary>
    private void ApplyCaptureState(CaptureState state)
    {
        ProxyLogCaptured = state.Captured;
        ProxyLogPath = state.LogPath;
        NotCapturedBanner = state.Captured ? null : NotCapturedBannerText;

        ProxyLogTail.Clear();
        foreach (var line in state.Tail)
        {
            ProxyLogTail.Add(line);
        }
    }

    // --------------------------------------------------------------- copy diagnostics (design 3.1, IC-QM6)

    /// <summary>
    /// Builds the health TEXT bundle for the "Copy diagnostics" action (design 3.1): versions, service
    /// states, and protection/kill-switch/leak flags with a timestamp. It contains ONLY health data and
    /// EXPLICITLY NO query data (IC-QM6) — the query stream never touches this VM, so it cannot leak here.
    /// Pure/total: composes from the current observable snapshot, never re-queries, never throws.
    /// </summary>
    public string BuildDiagnosticsText()
    {
        var sb = new StringBuilder();
        sb.AppendLine("DnsCryptControl — health diagnostics");
        sb.Append("Captured: ").AppendLine(
            (LastRefreshedUtc ?? DateTimeOffset.UtcNow).ToString("u", CultureInfo.InvariantCulture));
        sb.AppendLine();
        sb.Append("App IPC protocol version: ")
            .AppendLine(IpcProtocol.Version.ToString(CultureInfo.InvariantCulture));
        sb.Append("Helper reachable: ").AppendLine(HelperReachable ? "yes" : "no");
        sb.Append("Helper protocol version: ")
            .AppendLine(HelperProtocolVersion.ToString(CultureInfo.InvariantCulture));
        sb.Append("Helper protocol matches app: ").AppendLine(HelperVersionMismatch ? "NO (version skew)" : "yes");
        sb.Append("Helper build: ").AppendLine(string.IsNullOrEmpty(HelperBuild) ? "(unknown)" : HelperBuild);
        sb.AppendLine();
        sb.Append("Proxy running: ").AppendLine(ProxyRunning ? "yes" : "no");
        sb.Append("Protection enabled: ").AppendLine(ProtectionEnabled ? "yes" : "no");
        sb.Append("Kill switch enabled: ").AppendLine(KillSwitchEnabled ? "yes" : "no");
        sb.Append("Leak mitigations enabled: ").AppendLine(LeakMitigationsEnabled ? "yes" : "no");
        sb.Append("Active resolver: ").AppendLine(string.IsNullOrEmpty(ActiveResolver) ? "(none)" : ActiveResolver);
        sb.AppendLine();
        sb.Append("Proxy log capture: ").AppendLine(ProxyLogCaptured ? "on" : "off");
        sb.AppendLine();
        sb.AppendLine("This bundle contains health/diagnostic data only. It intentionally excludes all");
        sb.AppendLine("query data (no domains, clients, timestamps, or actions from the Query Monitor).");
        return sb.ToString();
    }

    // --------------------------------------------------------------- static text + support types

    /// <summary>The "not captured" banner (design 3.2).</summary>
    public const string NotCapturedBannerText =
        "The proxy's operational log is not captured — enable capture to see proxy diagnostics. " +
        "(This log is operational, not browsing history, but can contain resolver hostnames, so it is opt-in.)";

    /// <summary>The default <c>log_level</c> set when enabling capture (2 = notice; dnscrypt-proxy's
    /// default operational verbosity — enough to diagnose without flooding).</summary>
    private const long DefaultLogLevel = 2;

    /// <summary>An off-thread snapshot of the capture state (whether <c>log_file</c> is set + its tail).</summary>
    private sealed record CaptureState(bool Captured, string? LogPath, IReadOnlyList<string> Tail);

    /// <summary>The result of preparing a capture-toggle config write.</summary>
    private sealed record CaptureWriteResult(bool Success, string? CandidateText, string? BaseSha256, string? Error)
    {
        public static CaptureWriteResult Ready(string candidate, string sha) => new(true, candidate, sha, null);

        public static CaptureWriteResult Failed(string error) => new(false, null, null, error);
    }
}
