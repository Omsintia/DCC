using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging.Abstractions;
using DnsCryptControl.Platform;
using DnsCryptControl.Service;
using Xunit;

namespace DnsCryptControl.Service.Tests;

/// <summary>Unit tests for <see cref="ProtectionOrchestrator"/> — the atomic, helper-owned
/// enable/disable operation. Correctness of ordering + rollback is security-critical: a bug here
/// can leave DNS resolving in plaintext (a leak). Fakes below follow the same local, per-seam-fake
/// convention as <c>BootReconcilerTests</c> (the other consumer of these five Platform seams).</summary>
public class ProtectionOrchestratorTests
{
    // ── Fakes (reusing the BootReconcilerTests convention: local, minimal, settable failure hooks) ──

    private sealed class FakeAdapters : IDnsAdapterConfigurator
    {
        public List<string> Calls { get; } = new();
        public List<string>? Order { get; set; }
        public PlatformErrorKind? FailApply { get; set; }
        public PlatformErrorKind? FailRestore { get; set; }

        public PlatformResult ApplyLoopbackToAllAdapters()
        {
            Calls.Add(nameof(ApplyLoopbackToAllAdapters));
            Order?.Add($"Adapters.{nameof(ApplyLoopbackToAllAdapters)}");
            return FailApply is { } k ? PlatformResult.Fail(k, "apply failed") : PlatformResult.Ok();
        }

        public PlatformResult ReassertLoopback() { Calls.Add(nameof(ReassertLoopback)); return PlatformResult.Ok(); }

        public PlatformResult RestoreDns()
        {
            Calls.Add(nameof(RestoreDns));
            Order?.Add($"Adapters.{nameof(RestoreDns)}");
            return FailRestore is { } k ? PlatformResult.Fail(k, "restore failed") : PlatformResult.Ok();
        }

        public bool IsLoopbackApplied() => true;
    }

    private sealed class FakeKillSwitch : IFirewallKillSwitch
    {
        public List<bool> Calls { get; } = new();
        public List<string>? Order { get; set; }
        public PlatformResult? FailOnEnable { get; set; }

        public PlatformResult SetKillSwitch(bool enable)
        {
            Calls.Add(enable);
            Order?.Add($"KillSwitch.SetKillSwitch({enable})");
            if (enable && FailOnEnable is { } fail)
                return fail;
            return PlatformResult.Ok();
        }

        public bool IsKillSwitchActive() => false;
    }

    private sealed class FakeLeak : ILeakMitigationPolicy
    {
        public List<bool> Calls { get; } = new();
        public List<string>? Order { get; set; }
        public PlatformErrorKind? FailApply { get; set; }
        public RebootAdvisory AdvisoryOnEnable { get; set; } = RebootAdvisory.None;

        public PlatformResult<RebootAdvisory> SetLeakMitigations(bool enable)
        {
            Calls.Add(enable);
            Order?.Add($"Leak.SetLeakMitigations({enable})");
            if (enable && FailApply is { } k)
                return PlatformResult<RebootAdvisory>.Fail(k, "leak apply failed");
            return PlatformResult<RebootAdvisory>.Ok(enable ? AdvisoryOnEnable : RebootAdvisory.None);
        }

        public bool AreLeakMitigationsEnabled() => false;
    }

    private sealed class FakeProxy : IProxyServiceController
    {
        public List<string> Calls { get; } = new();
        public List<string>? Order { get; set; }
        public PlatformErrorKind? FailStart { get; set; }

        public PlatformResult<ProxyServiceState> GetState() => PlatformResult<ProxyServiceState>.Ok(ProxyServiceState.Stopped);
        public PlatformResult Install() => PlatformResult.Ok();
        public PlatformResult Uninstall() => PlatformResult.Ok();

        public PlatformResult Start()
        {
            Calls.Add(nameof(Start));
            Order?.Add($"Proxy.{nameof(Start)}");
            return FailStart is { } k ? PlatformResult.Fail(k, "start failed") : PlatformResult.Ok();
        }

        public PlatformResult Stop() { Calls.Add(nameof(Stop)); Order?.Add($"Proxy.{nameof(Stop)}"); return PlatformResult.Ok(); }
        public PlatformResult Restart() => PlatformResult.Ok();
    }

    private sealed class FakeProtectionStateWriter : IProtectionStateWriter
    {
        public List<string> Calls { get; } = new();
        public List<string>? Order { get; set; }
        public PlatformErrorKind? FailEnable { get; set; }

        public PlatformResult EnableProtection()
        {
            Calls.Add(nameof(EnableProtection));
            Order?.Add($"Writer.{nameof(EnableProtection)}");
            return FailEnable is { } k ? PlatformResult.Fail(k, "persist intent failed") : PlatformResult.Ok();
        }

        public PlatformResult DisableProtection()
        {
            Calls.Add(nameof(DisableProtection));
            Order?.Add($"Writer.{nameof(DisableProtection)}");
            return PlatformResult.Ok();
        }

        public PlatformResult SetKillSwitchEnabled(bool enabled) { Calls.Add($"{nameof(SetKillSwitchEnabled)}({enabled})"); return PlatformResult.Ok(); }
        public PlatformResult SetLeakMitigationsEnabled(bool enabled) { Calls.Add($"{nameof(SetLeakMitigationsEnabled)}({enabled})"); return PlatformResult.Ok(); }
    }

    private sealed class FakeSeedConfigStore : IConfigStore
    {
        public List<string> Calls { get; } = new();
        public List<string>? Order { get; set; }
        public PlatformErrorKind? FailNextEnsure { get; set; }

        public PlatformResult EnsureDefaultSourceCaches()
        {
            Calls.Add(nameof(EnsureDefaultSourceCaches));
            Order?.Add($"Store.{nameof(EnsureDefaultSourceCaches)}");
            return FailNextEnsure is { } k
                ? PlatformResult.Fail(k, "default cache seed failed")
                : PlatformResult.Ok();
        }

        // The orchestrator only seeds; the rest of the store surface is out of scope here.
        public PlatformResult<string> ReadConfig() => PlatformResult<string>.Fail(PlatformErrorKind.NotFound, "not used");
        public PlatformResult WriteConfig(string tomlText) => PlatformResult.Ok();
        public PlatformResult WriteConfigIfBaseMatches(string tomlText, string expectedBaseSha256) => PlatformResult.Ok();
        public PlatformResult WriteRuleFile(RuleFileKind kind, string content) => PlatformResult.Ok();
        public PlatformResult PlaceOdohSourceCaches() => PlatformResult.Ok();
    }

    private sealed class Rig
    {
        public FakeProxy Proxy { get; } = new();
        public FakeAdapters Adapters { get; } = new();
        public FakeLeak Leak { get; } = new();
        public FakeKillSwitch KillSwitch { get; } = new();
        public FakeProtectionStateWriter Writer { get; } = new();
        public FakeSeedConfigStore Store { get; } = new();

        /// <summary>Shared cross-fake ledger for order assertions. Each fake call appends its own
        /// tag here in addition to its per-fake Calls list, so tests can assert relative ordering
        /// across different seams (e.g. writer.EnableProtection before proxy.Start).</summary>
        public List<string> Order { get; } = new();

        public Rig()
        {
            Proxy.Order = Order;
            Adapters.Order = Order;
            Writer.Order = Order;
            KillSwitch.Order = Order;
            Leak.Order = Order;
            Store.Order = Order;
        }

        public ProtectionOrchestrator Build() =>
            new(Proxy, Adapters, Leak, KillSwitch, Writer, Store, NullLogger<ProtectionOrchestrator>.Instance);
    }

    // ── Enable: ordering ──────────────────────────────────────────────────────

    [Fact]
    public void enable_persists_intent_first_then_start_apply_mitigate()
    {
        var rig = new Rig();
        var orchestrator = rig.Build();

        var result = orchestrator.EnableProtection(withKillSwitch: false);

        Assert.True(result.Success);
        Assert.Equal(
            new[]
            {
                "Writer.EnableProtection",
                "Store.EnsureDefaultSourceCaches",
                "Proxy.Start",
                "Adapters.ApplyLoopbackToAllAdapters",
                "Leak.SetLeakMitigations(True)",
            },
            rig.Order);
    }

    // ── Enable: the default source cache is seeded BEFORE the proxy starts ──
    // (dnscrypt-proxy treats a source with no cache as FATAL under the off-53
    // config, so starting without the seed is the fresh-install DNS brick).

    [Fact]
    public void enable_seed_failure_rolls_back_and_clears_intent_without_starting_proxy()
    {
        var rig = new Rig();
        rig.Store.FailNextEnsure = PlatformErrorKind.OperationFailed;
        var orchestrator = rig.Build();

        var result = orchestrator.EnableProtection(withKillSwitch: false);

        Assert.False(result.Success);
        Assert.DoesNotContain("Proxy.Start", rig.Order);
        Assert.Contains(nameof(IProtectionStateWriter.DisableProtection), rig.Writer.Calls);
        // The rollback's RestoreDns only runs inside the full teardown — leak-safe by construction.
        Assert.Contains(nameof(IDnsAdapterConfigurator.RestoreDns), rig.Adapters.Calls);
    }

    [Fact]
    public void enable_seeds_exactly_once_per_enable()
    {
        var rig = new Rig();
        var orchestrator = rig.Build();

        Assert.True(orchestrator.EnableProtection(withKillSwitch: false).Success);
        Assert.True(orchestrator.DisableProtection().Success);
        Assert.True(orchestrator.EnableProtection(withKillSwitch: false).Success);

        Assert.Equal(2, rig.Store.Calls.Count);
    }

    // ── Enable: rollback on hard core-step failure ───────────────────────────

    [Fact]
    public void enable_core_step_failure_rolls_back_and_clears_intent()
    {
        var rig = new Rig();
        rig.Adapters.FailApply = PlatformErrorKind.OperationFailed;
        var orchestrator = rig.Build();

        var result = orchestrator.EnableProtection(withKillSwitch: false);

        Assert.False(result.Success);
        Assert.Contains(nameof(IDnsAdapterConfigurator.RestoreDns), rig.Adapters.Calls);
        Assert.Contains(nameof(IProxyServiceController.Stop), rig.Proxy.Calls);
        Assert.Contains(nameof(IProtectionStateWriter.DisableProtection), rig.Writer.Calls);
    }

    // ── Enable: off-53 kill-switch refusal is success-with-advisory ─────────

    [Fact]
    public void enable_killswitch_off53_refusal_is_success_with_advisory()
    {
        var rig = new Rig();
        rig.KillSwitch.FailOnEnable = PlatformResult.Fail(PlatformErrorKind.InvalidArgument, "port 53 in use");
        var orchestrator = rig.Build();

        var result = orchestrator.EnableProtection(withKillSwitch: true);

        Assert.True(result.Success);
        Assert.NotNull(result.Value);
        Assert.False(result.Value!.KillSwitchEnabled);
        Assert.NotNull(result.Value.KillSwitchAdvisory);
        Assert.Contains("port 53 in use", result.Value.KillSwitchAdvisory);
        Assert.DoesNotContain(nameof(IDnsAdapterConfigurator.RestoreDns), rig.Adapters.Calls);
    }

    // ── Enable: reboot advisory capture ──────────────────────────────────────

    [Fact]
    public void enable_captures_reboot_recommended_from_leak()
    {
        var rig = new Rig();
        rig.Leak.AdvisoryOnEnable = RebootAdvisory.Recommended;
        var orchestrator = rig.Build();

        var result = orchestrator.EnableProtection(withKillSwitch: false);

        Assert.True(result.Success);
        Assert.True(result.Value!.RebootRecommended);
    }

    // ── Enable: kill switch never touched when not requested ────────────────

    [Fact]
    public void enable_without_killswitch_never_calls_killswitch_set()
    {
        var rig = new Rig();
        var orchestrator = rig.Build();

        var result = orchestrator.EnableProtection(withKillSwitch: false);

        Assert.True(result.Success);
        Assert.Empty(rig.KillSwitch.Calls);
        Assert.False(result.Value!.KillSwitchEnabled);
        Assert.Null(result.Value.KillSwitchAdvisory);
    }

    // ── Enable: the persisted kill-switch INTENT always matches the actual outcome ──
    // Regression for the T10 reboot bug: enabling protection WITHOUT the kill switch must persist
    // KillSwitchEnabled=false. Previously the persist happened only in the with-kill-switch-success
    // branch, so a disarm (enable without KS after a prior armed session) left a stale
    // KillSwitchEnabled=true in protection.json — and BootReconciler re-armed the kill switch on the
    // next reboot the user had just turned off.

    [Fact]
    public void enable_without_killswitch_persists_killSwitchEnabled_false_so_a_disarm_survives_reboot()
    {
        var rig = new Rig();
        var orchestrator = rig.Build();

        var result = orchestrator.EnableProtection(withKillSwitch: false);

        Assert.True(result.Success);
        Assert.Contains("SetKillSwitchEnabled(False)", rig.Writer.Calls);
        Assert.DoesNotContain("SetKillSwitchEnabled(True)", rig.Writer.Calls);
    }

    [Fact]
    public void enable_with_killswitch_success_persists_killSwitchEnabled_true()
    {
        var rig = new Rig();
        var orchestrator = rig.Build();

        var result = orchestrator.EnableProtection(withKillSwitch: true);

        Assert.True(result.Success);
        Assert.True(result.Value!.KillSwitchEnabled);
        Assert.Contains("SetKillSwitchEnabled(True)", rig.Writer.Calls);
        Assert.DoesNotContain("SetKillSwitchEnabled(False)", rig.Writer.Calls);
    }

    [Fact]
    public void enable_with_killswitch_off53_refusal_persists_killSwitchEnabled_false()
    {
        var rig = new Rig();
        rig.KillSwitch.FailOnEnable = PlatformResult.Fail(PlatformErrorKind.InvalidArgument, "port 53 in use");
        var orchestrator = rig.Build();

        var result = orchestrator.EnableProtection(withKillSwitch: true);

        // Requested the kill switch, but it was refused (advisory) — the persisted intent must be
        // false so a reboot does not re-arm a kill switch that isn't actually up.
        Assert.True(result.Success);
        Assert.False(result.Value!.KillSwitchEnabled);
        Assert.Contains("SetKillSwitchEnabled(False)", rig.Writer.Calls);
    }

    // ── Disable: ordered teardown ─────────────────────────────────────────────

    [Fact]
    public void disable_teardown_order_killswitch_then_leak_then_restore_then_stop_then_clear_intent()
    {
        var rig = new Rig();
        var orchestrator = rig.Build();

        var result = orchestrator.DisableProtection();

        Assert.True(result.Success);
        Assert.Equal(
            new[]
            {
                "KillSwitch.SetKillSwitch(False)",
                "Leak.SetLeakMitigations(False)",
                "Adapters.RestoreDns",
                "Proxy.Stop",
                "Writer.DisableProtection",
            },
            rig.Order);
    }
}
