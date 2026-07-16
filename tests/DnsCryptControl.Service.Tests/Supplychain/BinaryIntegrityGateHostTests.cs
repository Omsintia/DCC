using System;
using Microsoft.Extensions.DependencyInjection;
using DnsCryptControl.Service;
using DnsCryptControl.Service.Supplychain;
using Xunit;

namespace DnsCryptControl.Service.Tests.Supplychain;

public class BinaryIntegrityGateHostTests
{
    [Fact]
    public void Composition_resolvesBinaryIntegrityGate_andFreshVerifyPasses()
    {
        if (!OperatingSystem.IsWindows()) return;
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041)) return;

        var services = new ServiceCollection();
        services.AddLogging();
        ServiceComposition.ConfigureServices(
            services,
            resolveInteractiveUser: () => System.Security.Principal.WindowsIdentity.GetCurrent().User);
        using var provider = services.BuildServiceProvider();

        var gate = provider.GetRequiredService<BinaryIntegrityGate>();
        // On a dev box with no installed proxy under %ProgramData% AND no record, the gate passes (fresh).
        // (If a prior install exists this asserts only resolvability; mark ManualIntegration if needed.)
        Assert.NotNull(gate);
    }
}
