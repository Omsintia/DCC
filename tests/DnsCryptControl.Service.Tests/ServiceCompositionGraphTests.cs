using System;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using DnsCryptControl.Ipc.Dispatch;
using DnsCryptControl.Platform;
using DnsCryptControl.Service;
using Xunit;

namespace DnsCryptControl.Service.Tests;

/// <summary>Proves the Phase 3 composition root is fully satisfiable: building the provider with
/// ValidateOnBuild resolves the dispatcher, the boot reconciler, every OPSEC platform interface,
/// and the hosted services without throwing — i.e. every new ctor wired in I3 has its dependencies.</summary>
public class ServiceCompositionGraphTests
{
    [Fact]
    public async Task Composition_resolvesEntireGraph_withoutThrowing()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041)) return;

        var services = new ServiceCollection();
        services.AddLogging();
        ServiceComposition.ConfigureServices(
            services,
            resolveInteractiveUser: () => WindowsIdentity.GetCurrent().User);

        // IpcPipeServer is IAsyncDisposable, so the provider must be disposed asynchronously.
        await using var provider = services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });

        // Core dispatch + boot path.
        Assert.NotNull(provider.GetRequiredService<CommandDispatcher>());
        Assert.NotNull(provider.GetRequiredService<BootReconciler>());

        // Phase 5a (A4): the atomic enable/disable orchestrator backing EnableProtection/DisableProtection.
        Assert.NotNull(provider.GetRequiredService<IProtectionOrchestrator>());

        // Phase 5b (B4): the OPSEC-aware save gate backing WriteConfig v2 must be a resolvable
        // singleton (over the SHARED ProtectionStateStore), not an inline construction only.
        Assert.NotNull(provider.GetRequiredService<IConfigWritePolicy>());

        // Every new OPSEC platform interface resolves (proves each impl ctor is satisfied).
        Assert.NotNull(provider.GetRequiredService<IDnsAdapterConfigurator>());
        Assert.NotNull(provider.GetRequiredService<ILeakMitigationPolicy>());
        Assert.NotNull(provider.GetRequiredService<IFirewallKillSwitch>());
        Assert.NotNull(provider.GetRequiredService<IBrowserDohPolicy>());
        Assert.NotNull(provider.GetRequiredService<IDnsCacheFlusher>());
        Assert.NotNull(provider.GetRequiredService<IDiagnosticsProbe>());

        // Phase 4 supply chain: verify/install installer + launch-time integrity gate.
        Assert.NotNull(provider.GetRequiredService<DnsCryptControl.Platform.IBinaryVerifyInstaller>());
        Assert.NotNull(provider.GetRequiredService<DnsCryptControl.Service.Supplychain.BinaryIntegrityGate>());

        // The resolved proxy controller MUST be the integrity-gating decorator so every consumer
        // (BootReconciler, the Start/Restart handlers, the installer) goes through the launch gate.
        Assert.IsType<IntegrityGatedProxyServiceController>(
            provider.GetRequiredService<DnsCryptControl.Platform.IProxyServiceController>());

        // Both hosted services are registered (pipe server worker + network-change watcher).
        var hosted = provider.GetServices<IHostedService>();
        Assert.Contains(hosted, h => h is PipeServerWorker);
        Assert.Contains(hosted, h => h.GetType().Name == "NetworkChangeWatcher");
    }
}
