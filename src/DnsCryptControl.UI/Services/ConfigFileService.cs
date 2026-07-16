using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// D2: the single read-modify-write path for <c>dnscrypt-proxy.toml</c> (§4.2/§7.3).
/// <see cref="Load"/> follows <see cref="ActiveResolverReader"/>'s fail-closed off-disk
/// read pattern (path-injected ctor defaulting to the real <c>%ProgramData%</c> path;
/// never throws). Per IC-9 the file is read ONCE as bytes: the sha covers the raw bytes
/// (including any BOM — the helper hashes on-disk bytes, so hashing anything re-encoded
/// would manufacture false conflicts), while the returned text strips a single leading
/// U+FEFF so the BOM never reaches the parser or the saved file.
/// <see cref="SaveAndApplyAsync"/> owns the whole save orchestration; the UI never
/// writes the file itself.
/// </summary>
public sealed class ConfigFileService : IConfigFileService
{
    private static readonly TimeSpan DefaultStatusPollInterval = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan DefaultStatusPollTimeout = TimeSpan.FromSeconds(10);

    private readonly IHelperClient _helper;
    private readonly string _configFilePath;
    private readonly TimeSpan _statusPollInterval;
    private readonly TimeSpan _statusPollTimeout;

    /// <param name="helper">The pipe client every save is sent through.</param>
    /// <param name="configFilePath">Defaults to <see cref="UiPaths.ConfigFile"/> (the real
    /// <c>%ProgramData%</c> path). Tests inject a temp file path.</param>
    /// <param name="statusPollInterval">Post-restart status poll cadence; injectable so
    /// tests never depend on wall-clock defaults (IC-5).</param>
    /// <param name="statusPollTimeout">How long the post-restart poll waits for
    /// <c>ProxyRunning</c> before declaring <see cref="ConfigSaveOutcomeKind.ProxyRejected"/>.</param>
    public ConfigFileService(
        IHelperClient helper,
        string? configFilePath = null,
        TimeSpan? statusPollInterval = null,
        TimeSpan? statusPollTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(helper);
        _helper = helper;
        _configFilePath = configFilePath ?? UiPaths.ConfigFile;
        _statusPollInterval = statusPollInterval ?? DefaultStatusPollInterval;
        _statusPollTimeout = statusPollTimeout ?? DefaultStatusPollTimeout;
    }

    public ConfigLoadResult Load()
    {
        try
        {
            if (!File.Exists(_configFilePath))
            {
                return ConfigLoadResult.Fail($"Config file not found: {_configFilePath}");
            }

            // Reject a pathologically large file BEFORE reading it: a corrupt/mis-encoded config
            // (or a log written into it) would otherwise throw the raw "file is too long" IOException
            // at ~2 GB or balloon this process's memory. Fail cleanly and actionably instead.
            if (ConfigReadGuard.IsOversized(_configFilePath, out var oversizeLen))
            {
                return ConfigLoadResult.Fail(ConfigReadGuard.OversizeMessage(oversizeLen));
            }

            var bytes = File.ReadAllBytes(_configFilePath);
            var sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

            // Encoding.UTF8.GetString never throws — invalid sequences (e.g. a UTF-16
            // file on disk) decode to U+FFFD and surface downstream as parse errors in
            // validation; the sha above is still byte-exact either way.
            var text = Encoding.UTF8.GetString(bytes);
            if (text.Length > 0 && text[0] == '\uFEFF')
            {
                text = text[1..]; // IC-9: strip a SINGLE leading BOM character only
            }

            return ConfigLoadResult.Ok(text, sha256);
        }
        catch (IOException ex)
        {
            return ConfigLoadResult.Fail($"Could not read config file: {ex.Message}");
        }
        catch (UnauthorizedAccessException ex)
        {
            return ConfigLoadResult.Fail($"Could not read config file: {ex.Message}");
        }
    }

    public async Task<ConfigSaveOutcome> SaveAndApplyAsync(string candidateText, string baseSha256, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(candidateText);
        ArgumentNullException.ThrowIfNull(baseSha256);

        // Step 0 — version-skew gate (P5b-E1). A v1 helper deserializing the v2 payload
        // silently IGNORES BaseSha256 (unknown JSON property) and writes with no CAS and
        // no OPSEC write policy, so a mismatched helper must be refused BEFORE any
        // WriteConfig frame is ever sent — fail-open otherwise.
        var status = await _helper.GetStatusAsync(ct).ConfigureAwait(false);
        if (status is null || !status.Success || status.Value is null)
        {
            return new ConfigSaveOutcome(
                ConfigSaveOutcomeKind.HelperUnavailable,
                "helper unavailable — the save was not attempted");
        }

        if (status.Value.ProtocolVersion != IpcProtocol.Version)
        {
            return new ConfigSaveOutcome(
                ConfigSaveOutcomeKind.HelperIncompatible,
                $"helper protocol version {status.Value.ProtocolVersion} does not match this app's ({IpcProtocol.Version}) — update the helper and app together, then retry");
        }

        // Step 1 — size pre-check on the ACTUAL request frame (envelope + JSON string-
        // escaping inflation, exactly the bytes HelperClient would send). The transport
        // itself fails closed on oversize (C1), but that surfaces as a lost reply —
        // this gives the friendly outcome without touching the pipe again. The
        // comparison mirrors IpcFraming.WriteFrameAsync's guard (> MaxBytes rejects).
        var payloadJson = IpcSerializer.SerializePayload(new WriteConfigPayload(candidateText, baseSha256));
        var requestJson = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.WriteConfig, payloadJson));
        if (Encoding.UTF8.GetByteCount(requestJson) > IpcSerializer.MaxBytes)
        {
            return new ConfigSaveOutcome(
                ConfigSaveOutcomeKind.TooLarge,
                "config is too large to send to the helper (limit 1 MiB per request) — trim it before saving");
        }

        // Step 2 — the policy-gated compare-and-swap write (BE-6/IC-3, enforced
        // helper-side). Refusal messages are surfaced verbatim (IC-10).
        var write = await _helper.WriteConfigAsync(candidateText, baseSha256, ct).ConfigureAwait(false);
        if (write is null)
        {
            return new ConfigSaveOutcome(
                ConfigSaveOutcomeKind.HelperUnavailable,
                "the helper did not reply to the save — it may not have been applied; reload before retrying");
        }

        if (!write.Success)
        {
            return write.Code == IpcErrorCode.Conflict
                ? new ConfigSaveOutcome(ConfigSaveOutcomeKind.Conflict, write.Message)
                : new ConfigSaveOutcome(ConfigSaveOutcomeKind.Rejected, write.Message);
        }

        // Step 3 — apply: restart the proxy, then verify it actually came back up.
        // The write ALREADY happened past this point, so a lost/failed restart is
        // RestartFailed — never HelperUnavailable (which implies nothing changed).
        var restart = await _helper.RestartProxyAsync(ct).ConfigureAwait(false);
        if (restart is null || !restart.Success)
        {
            return new ConfigSaveOutcome(
                ConfigSaveOutcomeKind.RestartFailed,
                "config saved, but the proxy restart failed or its reply was lost — status unverified");
        }

        var stopwatch = Stopwatch.StartNew();
        while (true)
        {
            var poll = await _helper.GetStatusAsync(ct).ConfigureAwait(false);
            if (poll is { Success: true, Value.ProxyRunning: true })
            {
                return new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null);
            }

            if (stopwatch.Elapsed >= _statusPollTimeout)
            {
                // §7.3: DNS stays pointed at loopback by construction — nothing to roll
                // back here — but the outcome is distinct and never rendered green.
                return new ConfigSaveOutcome(
                    ConfigSaveOutcomeKind.ProxyRejected,
                    "config saved and restart issued, but the proxy did not report running — the new config appears rejected by the proxy");
            }

            await Task.Delay(_statusPollInterval, ct).ConfigureAwait(false);
        }
    }
}
