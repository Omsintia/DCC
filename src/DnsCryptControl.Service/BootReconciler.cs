using Microsoft.Extensions.Logging;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;

namespace DnsCryptControl.Service;

/// <summary>Fail-closed + auto-recover startup reconciliation (contracts §7). Run once at host
/// startup, after DI and before/at the pipe server starting. If protection was enabled, re-asserts
/// loopback DNS, re-asserts the kill switch and leak mitigations if those were on, and best-effort
/// restarts the proxy. NEVER restores ISP/DHCP DNS on a missing proxy (that would leak). Never
/// throws: a failing subsystem is logged so the dispatcher still comes up as the user's escape hatch.</summary>
public sealed class BootReconciler
{
    private readonly ProtectionStateStore _stateStore;
    private readonly IDnsAdapterConfigurator _adapters;
    private readonly IFirewallKillSwitch _killSwitch;
    private readonly ILeakMitigationPolicy _leak;
    private readonly IProxyServiceController _proxy;
    private readonly IConfigStore _configStore;
    private readonly ILogger<BootReconciler> _logger;

    private static readonly Action<ILogger, Exception?> LogProtectionOff =
        LoggerMessage.Define(LogLevel.Information, new EventId(10, "BootProtectionOff"),
            "Boot reconciliation: protection is disabled; no action taken.");

    private static readonly Action<ILogger, Exception?> LogProtectionOn =
        LoggerMessage.Define(LogLevel.Information, new EventId(11, "BootProtectionOn"),
            "Boot reconciliation: protection is enabled; re-asserting fail-closed state.");

    private static readonly Action<ILogger, string, string, Exception?> LogStepFailed =
        LoggerMessage.Define<string, string>(LogLevel.Warning, new EventId(12, "BootStepFailed"),
            "Boot reconciliation step failed (non-fatal): {Step} — {Detail}.");

    private static readonly Action<ILogger, string, Exception?> LogStepOk =
        LoggerMessage.Define<string>(LogLevel.Information, new EventId(13, "BootStepOk"),
            "Boot reconciliation step succeeded: {Step}.");

    public BootReconciler(
        ProtectionStateStore stateStore,
        IDnsAdapterConfigurator adapters,
        IFirewallKillSwitch killSwitch,
        ILeakMitigationPolicy leak,
        IProxyServiceController proxy,
        IConfigStore configStore,
        ILogger<BootReconciler> logger)
    {
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(adapters);
        ArgumentNullException.ThrowIfNull(killSwitch);
        ArgumentNullException.ThrowIfNull(leak);
        ArgumentNullException.ThrowIfNull(proxy);
        ArgumentNullException.ThrowIfNull(configStore);
        ArgumentNullException.ThrowIfNull(logger);
        _stateStore = stateStore;
        _adapters = adapters;
        _killSwitch = killSwitch;
        _leak = leak;
        _proxy = proxy;
        _configStore = configStore;
        _logger = logger;
    }

    /// <summary>Reconcile persisted protection intent against current system state. Never throws.</summary>
    public void Reconcile()
    {
        var state = _stateStore.Load();
        if (!state.ProtectionEnabled)
        {
            LogProtectionOff(_logger, null);
            return;
        }

        LogProtectionOn(_logger, null);

        // (a) Keep protection up: loopback DNS first (fails safe — DNS stays loopback even on error).
        Record("ReassertLoopback", _adapters.ReassertLoopback());

        if (state.KillSwitchEnabled)
            Record("SetKillSwitch(true)", _killSwitch.SetKillSwitch(true));

        if (state.LeakMitigationsEnabled)
        {
            var leakResult = _leak.SetLeakMitigations(true);
            Record("SetLeakMitigations(true)",
                new PlatformResult(leakResult.Success, leakResult.Error, leakResult.Message));
        }

        // (b) Auto-recover the proxy (best-effort). Seed the bundled default source cache first —
        // without a cache the proxy start is a guaranteed FATAL under the off-53 config (the
        // fresh-install brick). Best-effort like every boot step: a seed failure is logged, and the
        // proxy start below then reports its own failure. (c) Never RestoreDns here — that would leak.
        Record("EnsureDefaultSourceCaches", _configStore.EnsureDefaultSourceCaches());
        Record("Start(proxy)", _proxy.Start());
    }

    private void Record(string step, PlatformResult result)
    {
        if (result.Success)
            LogStepOk(_logger, step, null);
        else
            LogStepFailed(_logger, step, result.Message ?? result.Error.ToString(), null);
    }
}
