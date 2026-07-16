using System.Collections.Generic;
using DnsCryptControl.Ipc.Dispatch;
using DnsCryptControl.Platform;
using DnsCryptControl.Platform.Diagnostics;

namespace DnsCryptControl.Ipc.Tests;

// Shared, top-level OPSEC seam fakes so every dispatcher-building call site (the adversarial
// boundary suite + the pipe-server tests) can construct the full 12-arg HandlerRegistry.Build
// without re-declaring fakes per file. FakeDnsAdapterConfigurator + FakeLeakMitigationPolicy
// already live in their own files; these cover the remaining four OPSEC interfaces plus the
// IProtectionStateWriter spine seam, (Phase 4) IBinaryVerifyInstaller, and (Phase 5b)
// IConfigWritePolicy.

internal sealed class FakeFirewallKillSwitch : IFirewallKillSwitch
{
    public PlatformErrorKind? FailWith { get; set; }
    public bool Active { get; set; }

    public PlatformResult SetKillSwitch(bool enable) =>
        FailWith is { } kind ? PlatformResult.Fail(kind, "kill switch failed") : PlatformResult.Ok();

    public bool IsKillSwitchActive() => Active;
}

internal sealed class FakeBrowserDoh : IBrowserDohPolicy
{
    public PlatformErrorKind? FailWith { get; set; }
    public bool Applied { get; set; }

    public PlatformResult SetBrowserDohPolicy(bool enable) =>
        FailWith is { } kind ? PlatformResult.Fail(kind, "browser DoH failed") : PlatformResult.Ok();

    public bool IsBrowserDohPolicyApplied() => Applied;
}

internal sealed class FakeDnsCacheFlusher : IDnsCacheFlusher
{
    public PlatformErrorKind? FailWith { get; set; }

    public PlatformResult Flush() =>
        FailWith is { } kind ? PlatformResult.Fail(kind, "flush failed") : PlatformResult.Ok();
}

internal sealed class FakeDiagnosticsProbe : IDiagnosticsProbe
{
    public PlatformResult<DiagnosticsSnapshot> Run() =>
        PlatformResult<DiagnosticsSnapshot>.Fail(PlatformErrorKind.OperationFailed, "not run in test");

    public PlatformResult<ResolveVerification> VerifyUpstreamResolution() =>
        PlatformResult<ResolveVerification>.Fail(PlatformErrorKind.OperationFailed, "not run in test");
}

/// <summary>Recording fake for <see cref="IProtectionStateWriter"/>. Per-method failure
/// injection (null = success); records call names and last boolean arg for assertions.</summary>
internal sealed class FakeProtectionStateWriter : IProtectionStateWriter
{
    // Per-method failure injection; null => success.
    public PlatformErrorKind? FailEnable, FailDisable, FailKillSwitch, FailLeak;
    public readonly List<string> Calls = new();
    public bool? LastKillSwitch, LastLeak;

    public PlatformResult EnableProtection() { Calls.Add(nameof(EnableProtection)); return R(FailEnable); }
    public PlatformResult DisableProtection() { Calls.Add(nameof(DisableProtection)); return R(FailDisable); }
    public PlatformResult SetKillSwitchEnabled(bool e) { Calls.Add(nameof(SetKillSwitchEnabled)); LastKillSwitch = e; return R(FailKillSwitch); }
    public PlatformResult SetLeakMitigationsEnabled(bool e) { Calls.Add(nameof(SetLeakMitigationsEnabled)); LastLeak = e; return R(FailLeak); }
    private static PlatformResult R(PlatformErrorKind? k) => k is { } kind ? PlatformResult.Fail(kind, "intent persist failed") : PlatformResult.Ok();
}

/// <summary>Fake binary verify/installer for the dispatcher-building helpers. Result is injectable
/// so a test can assert fail-closed propagation of a verification failure.</summary>
internal sealed class FakeBinaryVerifyInstaller : IBinaryVerifyInstaller
{
    public PlatformResult Result { get; set; } = PlatformResult.Ok();
    public PlatformResult VerifyAndInstall(string tempZipPath, string expectedTag) => Result;
}

/// <summary>Recording fake for <see cref="IProtectionOrchestrator"/> (Task A4). Settable results
/// let a test inject enable/disable failures without exercising the real Service-layer orchestrator.</summary>
internal sealed class FakeProtectionOrchestrator : IProtectionOrchestrator
{
    public bool? LastWithKillSwitch { get; private set; }
    public int EnableCallCount { get; private set; }
    public int DisableCallCount { get; private set; }
    public PlatformResult<ProtectionOutcome> EnableResult { get; set; } =
        PlatformResult<ProtectionOutcome>.Ok(new ProtectionOutcome(false, false, false, null));
    public PlatformResult DisableResult { get; set; } = PlatformResult.Ok();

    public PlatformResult<ProtectionOutcome> EnableProtection(bool withKillSwitch)
    {
        EnableCallCount++;
        LastWithKillSwitch = withKillSwitch;
        return EnableResult;
    }

    public PlatformResult DisableProtection()
    {
        DisableCallCount++;
        return DisableResult;
    }
}

/// <summary>Recording fake for <see cref="IConfigWritePolicy"/> (Phase 5b, B4). Pass-through Ok
/// by default so every existing dispatcher-building call site behaves unchanged; a test injects a
/// refusal via <see cref="Result"/> and asserts IC-3 ordering via the recorded candidates.</summary>
internal sealed class FakeConfigWritePolicy : IConfigWritePolicy
{
    public PlatformResult Result { get; set; } = PlatformResult.Ok();
    public List<string> Checked { get; } = new();

    public PlatformResult Check(string candidateTomlText)
    {
        Checked.Add(candidateTomlText);
        return Result;
    }
}

/// <summary>Centralizes the 12-arg HandlerRegistry.Build wiring for the test suites so every call
/// site uses the same full set of OPSEC fakes. Overloads let a test inject a specific failing
/// subsystem (e.g. a failing kill switch for the IC-10 failure-propagation test). All optional
/// params default so existing call sites compile unchanged.</summary>
internal static class TestHandlerRegistry
{
    public static IReadOnlyList<ICommandHandler> BuildHandlers(
        FakeProxyServiceController proxy,
        FakeConfigStore store,
        IFirewallKillSwitch? killSwitch = null,
        ILeakMitigationPolicy? leak = null,
        IProtectionStateWriter? protectionWriter = null,
        IBinaryVerifyInstaller? binaryInstaller = null,
        IProtectionOrchestrator? orchestrator = null,
        IConfigWritePolicy? writePolicy = null) =>
        HandlerRegistry.Build(
            proxy,
            store,
            new FakeDnsAdapterConfigurator(),
            leak ?? new FakeLeakMitigationPolicy(),
            killSwitch ?? new FakeFirewallKillSwitch(),
            new FakeBrowserDoh(),
            new FakeDnsCacheFlusher(),
            new FakeDiagnosticsProbe(),
            protectionWriter ?? new FakeProtectionStateWriter(),
            binaryInstaller ?? new FakeBinaryVerifyInstaller(),
            orchestrator ?? new FakeProtectionOrchestrator(),
            writePolicy ?? new FakeConfigWritePolicy());

    public static CommandDispatcher BuildDispatcher(
        FakeProxyServiceController proxy,
        FakeConfigStore store,
        IFirewallKillSwitch? killSwitch = null,
        ILeakMitigationPolicy? leak = null,
        IProtectionStateWriter? protectionWriter = null,
        IBinaryVerifyInstaller? binaryInstaller = null,
        IProtectionOrchestrator? orchestrator = null,
        IConfigWritePolicy? writePolicy = null) =>
        new(BuildHandlers(proxy, store, killSwitch, leak, protectionWriter, binaryInstaller, orchestrator, writePolicy));
}
