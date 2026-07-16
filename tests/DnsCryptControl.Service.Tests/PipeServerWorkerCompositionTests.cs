using System;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using DnsCryptControl.Service;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class PipeServerWorkerCompositionTests
{
    [Fact]
    public async Task ServiceCollection_buildsResolvableWorker()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041)) return;

        var services = new ServiceCollection();
        // Logging is provided by the host (AddWindowsService) in production; the OPSEC subsystems
        // and BootReconciler / NetworkChangeWatcher take ILogger<T>, so the bare ServiceCollection
        // must register logging to mirror the host.
        services.AddLogging();
        // The host's composition root is factored into a static so tests can exercise it
        // without starting the Windows service host.
        ServiceComposition.ConfigureServices(services, resolveInteractiveUser: () => System.Security.Principal.WindowsIdentity.GetCurrent().User);

        await using var provider = services.BuildServiceProvider();
        // After Phase 3 there are two hosted services (pipe server + network-change watcher);
        // assert the pipe server worker is resolvable among them.
        var hosted = provider.GetServices<IHostedService>().ToList();
        Assert.Contains(hosted, h => h is PipeServerWorker);
    }
}
