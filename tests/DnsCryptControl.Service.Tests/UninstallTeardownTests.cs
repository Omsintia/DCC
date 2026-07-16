using System;
using System.Collections.Generic;
using DnsCryptControl.Platform;
using DnsCryptControl.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace DnsCryptControl.Service.Tests;

/// <summary>The `--teardown` CLI mode (IC-PKG, phase-6 packaging): the MSI uninstall's fail-safe
/// revert. Pins the two invariants the uninstaller depends on: EVERY step always runs
/// (continue-on-failure — a partly-broken install still tears down as much as possible), and the
/// exit code is 0 iff ALL steps succeeded (the MSI logs a non-zero code but never aborts the
/// uninstall on it).</summary>
public class UninstallTeardownTests
{
    private sealed class FakeOrchestrator : IProtectionOrchestrator
    {
        public PlatformResult DisableResult { get; set; } = PlatformResult.Ok();
        public List<string> Calls { get; } = new();

        public PlatformResult<ProtectionOutcome> EnableProtection(bool withKillSwitch) =>
            throw new InvalidOperationException("teardown must never enable protection");

        public PlatformResult DisableProtection()
        {
            Calls.Add("DisableProtection");
            return DisableResult;
        }
    }

    private sealed class FakeBrowserDoh : IBrowserDohPolicy
    {
        public PlatformResult SetResult { get; set; } = PlatformResult.Ok();
        public List<bool> SetCalls { get; } = new();

        public PlatformResult SetBrowserDohPolicy(bool enable)
        {
            SetCalls.Add(enable);
            return SetResult;
        }

        public bool IsBrowserDohPolicyApplied() => false;
    }

    private static (UninstallTeardown Teardown, FakeOrchestrator Orch, FakeBrowserDoh Doh) Build()
    {
        var orch = new FakeOrchestrator();
        var doh = new FakeBrowserDoh();
        var teardown = new UninstallTeardown(orch, doh, NullLogger<UninstallTeardown>.Instance);
        return (teardown, orch, doh);
    }

    [Fact]
    public void Run_allStepsSucceed_returns0_andRevertsBothProtectionAndBrowserDoh()
    {
        var (teardown, orch, doh) = Build();

        var exit = teardown.Run();

        Assert.Equal(0, exit);
        Assert.Equal(new[] { "DisableProtection" }, orch.Calls);
        // The browser-DoH policy is Settings-owned (outside DisableProtection) and must be
        // explicitly reverted — enable:false — or the HKLM policy outlives the uninstall.
        Assert.Equal(new[] { false }, doh.SetCalls);
    }

    [Fact]
    public void Run_disableProtectionFails_stillRevertsBrowserDoh_andReturns1()
    {
        var (teardown, orch, doh) = Build();
        orch.DisableResult = PlatformResult.Fail(PlatformErrorKind.OperationFailed, "firewall API broken");

        var exit = teardown.Run();

        Assert.Equal(1, exit);
        Assert.Single(doh.SetCalls); // continue-on-failure: the later step still ran
    }

    [Fact]
    public void Run_browserDohRevertFails_returns1_afterDisableProtectionRan()
    {
        var (teardown, orch, doh) = Build();
        doh.SetResult = PlatformResult.Fail(PlatformErrorKind.OperationFailed, "registry locked");

        var exit = teardown.Run();

        Assert.Equal(1, exit);
        Assert.Single(orch.Calls); // the earlier step ran (and its success is not undone by the later failure)
    }

    [Fact]
    public void Run_everyStepFails_returns1_andAllStepsStillRan()
    {
        var (teardown, orch, doh) = Build();
        orch.DisableResult = PlatformResult.Fail(PlatformErrorKind.Timeout, "scm timeout");
        doh.SetResult = PlatformResult.Fail(PlatformErrorKind.NotFound, "key gone");

        var exit = teardown.Run();

        Assert.Equal(1, exit);
        Assert.Single(orch.Calls);
        Assert.Single(doh.SetCalls);
    }
}
