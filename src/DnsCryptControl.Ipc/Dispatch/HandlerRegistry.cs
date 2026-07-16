using System;
using System.Collections.Generic;
using System.Linq;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch;

/// <summary>
/// Single source of truth for the dispatcher's verb coverage. Builds the implemented handlers
/// (Phase 2 lifecycle/config + Phase 3 OPSEC + Phase 4 supply-chain + Phase 5a master-toggle +
/// Phase 5b policy-gated WriteConfig) and
/// fills every remaining IpcCommandType with an UnsupportedHandler, so the returned list always
/// has exactly one handler per enum value. Every verb is implemented as of Phase 5a task A4; the
/// UnsupportedHandler fill-loop is now a no-op safety net for any future enum addition. Both the
/// Service host and the adversarial tests build their dispatcher from here.
/// </summary>
public static class HandlerRegistry
{
    public static IReadOnlyList<ICommandHandler> Build(
        IProxyServiceController proxy,
        IConfigStore store,
        IDnsAdapterConfigurator adapters,
        ILeakMitigationPolicy leak,
        IFirewallKillSwitch killSwitch,
        IBrowserDohPolicy browserDoh,
        IDnsCacheFlusher flusher,
        IDiagnosticsProbe diagnostics,
        IProtectionStateWriter protectionWriter,
        IBinaryVerifyInstaller binaryInstaller,
        IProtectionOrchestrator orchestrator,
        IConfigWritePolicy writePolicy)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(adapters);
        ArgumentNullException.ThrowIfNull(leak);
        ArgumentNullException.ThrowIfNull(killSwitch);
        ArgumentNullException.ThrowIfNull(browserDoh);
        ArgumentNullException.ThrowIfNull(flusher);
        ArgumentNullException.ThrowIfNull(diagnostics);
        ArgumentNullException.ThrowIfNull(protectionWriter);
        ArgumentNullException.ThrowIfNull(binaryInstaller);
        ArgumentNullException.ThrowIfNull(orchestrator);
        ArgumentNullException.ThrowIfNull(writePolicy);

        var handlers = new List<ICommandHandler>
        {
            // Phase 2 — lifecycle + config.
            new StatusHandler(proxy, killSwitch, leak),
            new StartProxyHandler(proxy),
            new StopProxyHandler(proxy),
            new RestartProxyHandler(proxy),
            new InstallProxyServiceHandler(proxy),
            new UninstallProxyServiceHandler(proxy),
            // Phase 5b (B4): WriteConfig v2 — OPSEC write policy + compare-and-swap store.
            new WriteConfigHandler(store, writePolicy),
            new WriteRuleFileHandler(store),
            // Post-5j ODoH fix: place the bundled signed ODoH caches so the proxy loads them
            // from cache instead of a fatal boot-time download (verb 19, protocol 3).
            new PlaceOdohCacheHandler(store),
            // Phase 3 — OPSEC (mutating handlers record intent via IProtectionStateWriter).
            new ApplyDnsToAllAdaptersHandler(adapters, protectionWriter),
            new RestoreDnsHandler(adapters, protectionWriter),
            new LeakMitigationHandler(leak, protectionWriter),
            new KillSwitchHandler(killSwitch, protectionWriter),
            new BrowserDohHandler(browserDoh),
            new FlushDnsCacheHandler(flusher),
            new RunDiagnosticsHandler(diagnostics),
            // v4 (FIX #1): the post-apply real-name resolve check — reuses the same probe seam
            // (deliberately NOT a new Build parameter; that would ripple every test call site).
            new VerifyResolutionHandler(diagnostics),
            // Phase 4 — supply chain (the last Unsupported verb becomes real).
            new VerifyAndInstallBinaryHandler(binaryInstaller),
            // Phase 5a (A4) — BE-8: the atomic master-toggle enable/disable verbs.
            new EnableProtectionHandler(orchestrator),
            new DisableProtectionHandler(orchestrator),
        };

        var implemented = handlers.Select(h => h.Command).ToHashSet();
        foreach (var verb in Enum.GetValues<IpcCommandType>())
        {
            if (!implemented.Contains(verb))
                handlers.Add(new UnsupportedHandler(verb));
        }

        return handlers;
    }
}
