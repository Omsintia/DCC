using System;
using System.Collections.Generic;
using System.Linq;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Security;
using DnsCryptControl.Ipc.Serialization;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class AdversarialBoundaryTests
{
    private static CommandDispatcher BuildDispatcher(out FakeConfigStore store)
    {
        var proxy = new FakeProxyServiceController();
        store = new FakeConfigStore { Config = "existing = 1\n" };
        return TestHandlerRegistry.BuildDispatcher(proxy, store);
    }

    private sealed class ThrowingHandler : ICommandHandler
    {
        public IpcCommandType Command => IpcCommandType.GetStatus;
        public string Handle(IpcRequest request) => throw new InvalidOperationException("boom");
    }

    [Fact]
    public void Registry_coversEveryVerbExactlyOnce()
    {
        var handlers = TestHandlerRegistry.BuildHandlers(new FakeProxyServiceController(), new FakeConfigStore());
        var covered = handlers.Select(h => h.Command).ToHashSet();
        Assert.Equal(Enum.GetValues<IpcCommandType>().Length, covered.Count);
        Assert.Equal(Enum.GetValues<IpcCommandType>().Length, handlers.Count); // exactly one handler per verb
        foreach (var c in Enum.GetValues<IpcCommandType>())
            Assert.Contains(c, covered);
    }

    [Fact]
    public void NoVerb_remainsUnsupported_afterPhase4()
    {
        // Re-tightened (Phase 5a, task A4): EnableProtection/DisableProtection now resolve to real
        // handlers (EnableProtectionHandler/DisableProtectionHandler), so zero verbs remain Unsupported.
        var stubVerbs = TestHandlerRegistry.BuildHandlers(new FakeProxyServiceController(), new FakeConfigStore())
            .Where(h => h is UnsupportedHandler)
            .Select(h => h.Command)
            .ToHashSet();
        Assert.Empty(stubVerbs);
    }

    [Fact]
    public void VerifyAndInstallBinary_isImplemented_notUnsupported()
    {
        var d = TestHandlerRegistry.BuildDispatcher(new FakeProxyServiceController(), new FakeConfigStore());
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.VerifyAndInstallBinary, null));
        var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch(req));
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code); // implemented handler rejects the null payload
        Assert.NotEqual(IpcErrorCode.Unsupported, result.Code);
    }

    [Theory]
    [InlineData(IpcCommandType.ApplyDnsToAllAdapters, typeof(ApplyDnsToAllAdaptersHandler))]
    [InlineData(IpcCommandType.RestoreDns, typeof(RestoreDnsHandler))]
    [InlineData(IpcCommandType.SetLeakMitigations, typeof(LeakMitigationHandler))]
    [InlineData(IpcCommandType.SetKillSwitch, typeof(KillSwitchHandler))]
    [InlineData(IpcCommandType.SetBrowserDohPolicy, typeof(BrowserDohHandler))]
    [InlineData(IpcCommandType.FlushDnsCache, typeof(FlushDnsCacheHandler))]
    [InlineData(IpcCommandType.RunDiagnostics, typeof(RunDiagnosticsHandler))]
    [InlineData(IpcCommandType.GetStatus, typeof(StatusHandler))]
    public void Opsec_verbs_resolveToTheirRealHandler(IpcCommandType verb, Type expected)
    {
        var handler = TestHandlerRegistry
            .BuildHandlers(new FakeProxyServiceController(), new FakeConfigStore())
            .Single(h => h.Command == verb);
        Assert.IsType(expected, handler);
        Assert.IsNotType<UnsupportedHandler>(handler);
    }

    [Fact]
    public void FailingOpsecSubsystem_propagatesAsOperationFailed_throughRealDispatcher()
    {
        // IC-10: a failing OPSEC subsystem must surface as the mapped IPC error, not a swallowed
        // happy-path. Inject a kill switch that fails, dispatch SetKillSwitch through the REAL
        // CommandDispatcher built from HandlerRegistry.Build, and assert the failure propagates.
        var failingKillSwitch = new FakeFirewallKillSwitch
        {
            FailWith = DnsCryptControl.Platform.PlatformErrorKind.OperationFailed,
        };
        var dispatcher = TestHandlerRegistry.BuildDispatcher(
            new FakeProxyServiceController(), new FakeConfigStore(), killSwitch: failingKillSwitch);

        var req = IpcSerializer.Serialize(
            new IpcRequest(IpcCommandType.SetKillSwitch, IpcSerializer.SerializePayload(new SetTogglePayload(true))));
        var result = IpcSerializer.DeserializePayload<Result>(dispatcher.Dispatch(req));

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
    }

    [Fact]
    public void PathTraversal_inWriteRuleFile_failsClosed_nothingWritten()
    {
        var d = BuildDispatcher(out var store);
        var payload = IpcSerializer.SerializePayload(new WriteRuleFilePayload("..\\..\\Windows\\System32\\evil", "x"));
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.WriteRuleFile, payload));
        var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch(req));
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Empty(store.RuleFiles);
    }

    [Fact]
    public void OversizedFrame_failsClosed()
    {
        var d = BuildDispatcher(out _);
        var huge = "{\"Command\":0,\"PayloadJson\":\"" + new string('a', 2_000_000) + "\"}";
        var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch(huge));
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code); // deserialize rejected -> ValidationFailed
    }

    [Fact]
    public void MalformedFrame_failsClosed()
    {
        var d = BuildDispatcher(out _);
        var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch("}{ not json"));
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
    }

    [Fact]
    public void UnknownCommand_failsClosed_asUnsupported()
    {
        var d = BuildDispatcher(out _);
        var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch("{\"Command\":999,\"PayloadJson\":null}"));
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.Unsupported, result.Code);
    }

    [Fact]
    public void StubVerbs_ifAny_returnUnsupported()
    {
        var d = BuildDispatcher(out _);
        // Derive stub verbs dynamically from the real registry so this can't silently go
        // stale when a verb is promoted to a real handler. After Phase 4, stubVerbs is empty
        // (all verbs are implemented); the loop becomes a no-op and the test remains valid.
        var stubVerbs = TestHandlerRegistry
            .BuildHandlers(new FakeProxyServiceController(), new FakeConfigStore())
            .Where(h => h is UnsupportedHandler)
            .Select(h => h.Command)
            .ToList();
        foreach (var verb in stubVerbs)
        {
            var req = IpcSerializer.Serialize(new IpcRequest(verb, null));
            var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch(req));
            Assert.False(result!.Success);
            Assert.Equal(IpcErrorCode.Unsupported, result.Code);
        }
    }

    [Fact]
    public void InvalidConfig_isRejected_andFileUnchanged()
    {
        var d = BuildDispatcher(out var store);
        var payload = IpcSerializer.SerializePayload(new WriteConfigPayload("max_clients = = bad", TestSha.Of("existing = 1\n")));
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.WriteConfig, payload));
        var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch(req));
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Equal("existing = 1\n", store.Config); // unchanged
    }

    [Fact]
    public void WriteFailure_simulatesRollback_configUnchanged()
    {
        var d = BuildDispatcher(out var store);
        store.FailNextWrite = DnsCryptControl.Platform.PlatformErrorKind.OperationFailed;
        var payload = IpcSerializer.SerializePayload(new WriteConfigPayload("max_clients = 1\n", TestSha.Of("existing = 1\n")));
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.WriteConfig, payload));
        var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch(req));
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
        Assert.Equal("existing = 1\n", store.Config); // rollback: unchanged
    }

    // ---- G1: WriteConfig v2 adversarial boundary, end-to-end through the REAL dispatcher ----
    // (stale sha → Conflict; OPSEC refusal verbatim; schema garbage never reaches policy/store;
    // v1-shaped payload rejected; happy path delivers the exact text+sha to the CAS surface.)

    [Fact]
    public void WriteConfig_staleBaseSha_surfacesAsConflict_configUnchanged()
    {
        // The editor loaded one version of the file; an external writer changed it since.
        // The CAS must refuse with Conflict (IC-2) and the IC-10 message, never overwrite.
        var d = BuildDispatcher(out var store);
        var payload = IpcSerializer.SerializePayload(
            new WriteConfigPayload("max_clients = 250\n", TestSha.Of("some other on-disk content\n")));
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.WriteConfig, payload));
        var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch(req));

        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.Conflict, result.Code);
        Assert.Equal("config file changed on disk since it was loaded — reload before saving", result.Message);
        Assert.Equal("existing = 1\n", store.Config); // CAS refused: on-disk config unchanged
    }

    [Fact]
    public void WriteConfig_opsecPolicyRefusal_propagatesVerbatim_storeUntouched()
    {
        // P5b-U1 server-side enforcement: a policy refusal must reach the caller VERBATIM
        // (IC-10) as ValidationFailed (InvalidArgument mapping) and provably never touch
        // the store's CAS surface. (The Service suite drives the same path through the
        // REAL ProtectionAwareConfigWritePolicy; this pins the Ipc-side propagation.)
        var refusing = new FakeConfigWritePolicy
        {
            Result = DnsCryptControl.Platform.PlatformResult.Fail(
                DnsCryptControl.Platform.PlatformErrorKind.InvalidArgument,
                "OPSEC guard: netprobe_timeout must be 0 while protected"),
        };
        var store = new FakeConfigStore { Config = "existing = 1\n" };
        var d = TestHandlerRegistry.BuildDispatcher(new FakeProxyServiceController(), store, writePolicy: refusing);

        var payload = IpcSerializer.SerializePayload(
            new WriteConfigPayload("netprobe_timeout = 60\n", TestSha.Of("existing = 1\n")));
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.WriteConfig, payload));
        var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch(req));

        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code); // InvalidArgument → ValidationFailed on the wire
        Assert.Equal("OPSEC guard: netprobe_timeout must be 0 while protected", result.Message); // IC-10 verbatim
        Assert.Empty(store.CasWrites); // refusal provably never touched the CAS surface
        Assert.Equal("existing = 1\n", store.Config);
    }

    [Fact]
    public void WriteConfig_schemaGarbage_isRejected_policyAndCasSurfaceNeverTouched()
    {
        // Parses clean but violates the catalog (max_clients expects Long, got String):
        // schema validation must refuse BEFORE the policy or the store run (IC-3 ordering).
        var policy = new FakeConfigWritePolicy();
        var store = new FakeConfigStore { Config = "existing = 1\n" };
        var d = TestHandlerRegistry.BuildDispatcher(new FakeProxyServiceController(), store, writePolicy: policy);

        var payload = IpcSerializer.SerializePayload(
            new WriteConfigPayload("max_clients = 'lots'\n", TestSha.Of("existing = 1\n")));
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.WriteConfig, payload));
        var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch(req));

        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.StartsWith("Invalid config: max_clients:", result.Message, StringComparison.Ordinal);
        Assert.Empty(policy.Checked); // schema rejection happens before the OPSEC policy runs
        Assert.Empty(store.CasWrites);
        Assert.Equal("existing = 1\n", store.Config);
    }

    [Fact]
    public void WriteConfig_v1ShapedPayload_missingBaseSha_isRejected_storeUntouched()
    {
        // Version-skew adversarial case (P5b-E1): a v1 client's payload shape carries no
        // BaseSha256. The v2 helper must refuse it (no un-CAS'd write path exists); the D2
        // handshake gate protects the reverse skew — this pins the helper-side half.
        var d = BuildDispatcher(out var store);
        var req = IpcSerializer.Serialize(
            new IpcRequest(IpcCommandType.WriteConfig, "{\"TomlText\":\"max_clients = 250\\n\"}"));
        var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch(req));

        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Equal("WriteConfig requires TomlText and BaseSha256.", result.Message);
        Assert.Empty(store.CasWrites);
        Assert.Equal("existing = 1\n", store.Config);
    }

    [Fact]
    public void WriteConfig_happyPath_storeReceivesExactTextAndSha_throughRealDispatcher()
    {
        var d = BuildDispatcher(out var store);
        var sha = TestSha.Of("existing = 1\n");
        var payload = IpcSerializer.SerializePayload(new WriteConfigPayload("max_clients = 250\n", sha));
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.WriteConfig, payload));
        var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch(req));

        Assert.True(result!.Success);
        var cas = Assert.Single(store.CasWrites);
        Assert.Equal("max_clients = 250\n", cas.TomlText);  // exact text over the wire
        Assert.Equal(sha, cas.BaseSha256);                   // exact sha over the wire
        Assert.Equal("max_clients = 250\n", store.Config);
    }

    [Fact]
    public void UnauthorizedCaller_isDenied_beforeDispatch()
    {
        // Mimic the server's gate order: verify caller, only then dispatch.
        var verifier = new FakeCallerVerifier { Allow = false };
        var d = BuildDispatcher(out var store);

        string GatedHandle(CallerIdentity who, string requestJson) =>
            verifier.IsTrusted(who)
                ? d.Dispatch(requestJson)
                : IpcSerializer.SerializePayload(Result.Fail(IpcErrorCode.NotAuthorized, "caller not trusted"));

        var payload = IpcSerializer.SerializePayload(new WriteConfigPayload("max_clients = 1\n", TestSha.Of("existing = 1\n")));
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.WriteConfig, payload));
        var result = IpcSerializer.DeserializePayload<Result>(
            GatedHandle(new CallerIdentity(1234, @"C:\evil\hacker.exe"), req));

        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.NotAuthorized, result.Code);
        Assert.Equal("existing = 1\n", store.Config); // unchanged: dispatch never ran
    }

    [Fact]
    public void HandlerFault_isContained_asOperationFailed()
    {
        // Replace the real GetStatus handler with a throwing one; all 16 verbs still covered.
        var proxy = new FakeProxyServiceController();
        var store = new FakeConfigStore();
        var handlers = TestHandlerRegistry.BuildHandlers(proxy, store)
            .Where(h => h.Command != IpcCommandType.GetStatus)
            .Concat(new[] { (ICommandHandler)new ThrowingHandler() });
        var d = new CommandDispatcher(handlers);

        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.GetStatus, null));
        // Must return normally (no exception escapes the dispatcher).
        var respJson = d.Dispatch(req);
        var result = IpcSerializer.DeserializePayload<Result>(respJson);
        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
    }

    [Fact]
    public void VerifyAndInstallBinary_tamperedBinary_isRejected_failClosed()
    {
        var failing = new FakeBinaryVerifyInstaller
        {
            Result = DnsCryptControl.Platform.PlatformResult.Fail(
                DnsCryptControl.Platform.PlatformErrorKind.OperationFailed,
                "signature verification failed: MessageSignatureInvalid"),
        };
        var d = TestHandlerRegistry.BuildDispatcher(
            new FakeProxyServiceController(), new FakeConfigStore(), binaryInstaller: failing);

        var payload = IpcSerializer.SerializePayload(
            new VerifyAndInstallBinaryPayload(@"C:\ProgramData\DnsCryptControl\staging\dnscrypt-proxy-win64-2.1.16.zip", "2.1.16"));
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.VerifyAndInstallBinary, payload));
        var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch(req));

        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code); // verification failure propagates fail-closed
    }

    [Fact]
    public void VerifyAndInstallBinary_garbledPayload_isRejected_validationFailed()
    {
        var d = TestHandlerRegistry.BuildDispatcher(new FakeProxyServiceController(), new FakeConfigStore());
        var req = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.VerifyAndInstallBinary, "{ not the expected shape }"));
        var result = IpcSerializer.DeserializePayload<Result>(d.Dispatch(req));

        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
    }
}
