using Microsoft.Extensions.Logging;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Service;

/// <summary>Atomic, helper-owned enable/disable of DNS-leak protection (contracts BE-8, F8/F10).
/// Reuses <see cref="BootReconciler"/>'s leak-safe invariants: protection intent is persisted BEFORE
/// any core step runs, so a crash mid-apply still re-asserts loopback DNS on boot rather than
/// leaking; and <c>RestoreDns</c> is only ever invoked inside a full teardown that also stops the
/// proxy — never as a partial rollback that restores DNS while leaving the proxy configured.</summary>
public sealed class ProtectionOrchestrator : IProtectionOrchestrator
{
    private readonly IProxyServiceController _proxy;
    private readonly IDnsAdapterConfigurator _adapters;
    private readonly ILeakMitigationPolicy _leak;
    private readonly IFirewallKillSwitch _killSwitch;
    private readonly IProtectionStateWriter _protectionWriter;
    private readonly IConfigStore _configStore;
    private readonly ILogger<ProtectionOrchestrator> _logger;

    private static readonly Action<ILogger, Exception?> LogEnableIntentFailed =
        LoggerMessage.Define(LogLevel.Warning, new EventId(30, "EnableIntentPersistFailed"),
            "EnableProtection: failed to persist protection intent; denying enable (fail-closed).");

    private static readonly Action<ILogger, string, string, Exception?> LogEnableCoreStepFailed =
        LoggerMessage.Define<string, string>(LogLevel.Warning, new EventId(31, "EnableCoreStepFailed"),
            "EnableProtection: core step failed ({Step}); rolling back. {Detail}.");

    private static readonly Action<ILogger, string, Exception?> LogKillSwitchAdvisory =
        LoggerMessage.Define<string>(LogLevel.Information, new EventId(32, "EnableKillSwitchAdvisory"),
            "EnableProtection: kill switch refused (benign); keeping protection without it. {Detail}.");

    private static readonly Action<ILogger, string, string, Exception?> LogDisableStepFailed =
        LoggerMessage.Define<string, string>(LogLevel.Warning, new EventId(33, "DisableStepFailed"),
            "DisableProtection: step failed (continuing teardown): {Step} — {Detail}.");

    public ProtectionOrchestrator(
        IProxyServiceController proxy,
        IDnsAdapterConfigurator adapters,
        ILeakMitigationPolicy leak,
        IFirewallKillSwitch killSwitch,
        IProtectionStateWriter protectionWriter,
        IConfigStore configStore,
        ILogger<ProtectionOrchestrator> logger)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        ArgumentNullException.ThrowIfNull(adapters);
        ArgumentNullException.ThrowIfNull(leak);
        ArgumentNullException.ThrowIfNull(killSwitch);
        ArgumentNullException.ThrowIfNull(protectionWriter);
        ArgumentNullException.ThrowIfNull(configStore);
        ArgumentNullException.ThrowIfNull(logger);
        _proxy = proxy;
        _adapters = adapters;
        _leak = leak;
        _killSwitch = killSwitch;
        _protectionWriter = protectionWriter;
        _configStore = configStore;
        _logger = logger;
    }

    public PlatformResult<ProtectionOutcome> EnableProtection(bool withKillSwitch)
    {
        // (1) Persist intent FIRST: a crash mid-apply must still re-assert loopback on boot
        // (fail-closed). If we cannot even persist intent, deny rather than apply unprotected.
        var intent = _protectionWriter.EnableProtection();
        if (!intent.Success)
        {
            LogEnableIntentFailed(_logger, null);
            return PlatformResult<ProtectionOutcome>.Fail(
                intent.Error, intent.Message ?? "record protection intent failed");
        }

        // (2) Core step: seed the bundled default source cache unless the on-disk pair verifies.
        // dnscrypt-proxy treats a source with no loadable cache as FATAL when the list URL can't
        // be resolved — and the shipped off-53 config's bootstrap never can — so starting the
        // proxy without a valid cache leaves the machine on loopback DNS with a dead proxy (the
        // fresh-install brick). The launch chokepoint (IntegrityGatedProxyServiceController) seeds
        // too; this explicit step keeps the named-step rollback semantics for the enable flow.
        var seed = _configStore.EnsureDefaultSourceCaches();
        if (!seed.Success)
            return RollBackAndFail("EnsureDefaultSourceCaches", seed.Error, seed.Message);

        // (3) Core step: start the proxy.
        var start = _proxy.Start();
        if (!start.Success)
            return RollBackAndFail("Start(proxy)", start.Error, start.Message);

        // (4) Core step: pin DNS to loopback (captures the backup).
        var apply = _adapters.ApplyLoopbackToAllAdapters();
        if (!apply.Success)
            return RollBackAndFail("ApplyLoopbackToAllAdapters", apply.Error, apply.Message);

        // (5) Core step: leak mitigations.
        var leak = _leak.SetLeakMitigations(true);
        if (!leak.Success)
            return RollBackAndFail("SetLeakMitigations(true)", leak.Error, leak.Message);
        // Deliberate discard: core protection intent was already persisted in step (1); a failed sub-flag persist only lags the recorded state until the next successful write.
        _ = _protectionWriter.SetLeakMitigationsEnabled(true);
        var rebootRecommended = leak.Value == RebootAdvisory.Recommended;

        // (6) Optional: firewall kill switch. A benign off-53 refusal is success-with-advisory —
        // protection stays up without the kill switch, and we do NOT roll back for it.
        var killSwitchEnabled = false;
        string? advisory = null;
        if (withKillSwitch)
        {
            var ks = _killSwitch.SetKillSwitch(true);
            if (ks.Success)
            {
                killSwitchEnabled = true;
            }
            else if (ks.Error == PlatformErrorKind.InvalidArgument)
            {
                advisory = ks.Message;
                LogKillSwitchAdvisory(_logger, advisory ?? string.Empty, null);
            }
            else
            {
                return RollBackAndFail("SetKillSwitch(true)", ks.Error, ks.Message);
            }
        }

        // Persist the ACTUAL kill-switch outcome in BOTH directions. Previously the persist happened
        // only inside the withKillSwitch==true && success branch, so enabling protection WITHOUT the
        // kill switch left a stale KillSwitchEnabled=true from a prior armed session — and
        // BootReconciler then re-armed on reboot the kill switch the user had turned off (T10). This
        // unconditional persist keeps the recorded intent equal to what actually happened, so a
        // disarm survives a reboot. Deliberate discard: core protection intent was already persisted
        // in step (1); a failed sub-flag persist only lags the recorded state until the next write.
        _ = _protectionWriter.SetKillSwitchEnabled(killSwitchEnabled);

        return PlatformResult<ProtectionOutcome>.Ok(
            new ProtectionOutcome(killSwitchEnabled, LeakMitigationsEnabled: true, rebootRecommended, advisory));
    }

    public PlatformResult DisableProtection()
    {
        // Ordered teardown; intent is cleared LAST so a crash mid-teardown still re-asserts on boot.
        var ks = _killSwitch.SetKillSwitch(false);
        if (!ks.Success)
            LogDisableStepFailed(_logger, "SetKillSwitch(false)", ks.Message ?? ks.Error.ToString(), null);

        var leak = _leak.SetLeakMitigations(false);
        if (!leak.Success)
            LogDisableStepFailed(_logger, "SetLeakMitigations(false)", leak.Message ?? leak.Error.ToString(), null);

        var restore = _adapters.RestoreDns();
        if (!restore.Success)
            LogDisableStepFailed(_logger, "RestoreDns", restore.Message ?? restore.Error.ToString(), null);

        var stop = _proxy.Stop();
        if (!stop.Success)
            LogDisableStepFailed(_logger, "Stop(proxy)", stop.Message ?? stop.Error.ToString(), null);

        var clearIntent = _protectionWriter.DisableProtection();
        if (!clearIntent.Success)
            LogDisableStepFailed(_logger, "DisableProtection(intent)", clearIntent.Message ?? clearIntent.Error.ToString(), null);

        if (!ks.Success) return ks;
        if (!leak.Success) return PlatformResult.Fail(leak.Error, leak.Message ?? "leak mitigation teardown failed");
        if (!restore.Success) return restore;
        if (!stop.Success) return stop;
        if (!clearIntent.Success) return clearIntent;
        return PlatformResult.Ok();
    }

    /// <summary>Best-effort teardown of whatever core steps already ran, then clear intent, and
    /// return the original hard failure. RestoreDns is only ever reached here — inside the full
    /// teardown that also stops the proxy — never as a partial, leak-prone rollback.</summary>
    private PlatformResult<ProtectionOutcome> RollBackAndFail(string step, PlatformErrorKind error, string? message)
    {
        LogEnableCoreStepFailed(_logger, step, message ?? error.ToString(), null);

        _killSwitch.SetKillSwitch(false);
        _leak.SetLeakMitigations(false);
        _adapters.RestoreDns();
        _proxy.Stop();
        _protectionWriter.DisableProtection();

        return PlatformResult<ProtectionOutcome>.Fail(error, message ?? $"{step} failed");
    }
}
