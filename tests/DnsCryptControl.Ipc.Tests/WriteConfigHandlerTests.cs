using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

/// <summary>
/// WriteConfigHandler v2 (B4, IC-3 fail-closed ordering): payload-validate → parse →
/// schema-validate → OPSEC write policy → compare-and-swap store write. Every reject
/// path asserts the store's CAS write surface was NEVER touched (config provably
/// unchanged), and the policy is only consulted after schema validation passes.
/// </summary>
public class WriteConfigHandlerTests
{
    // The fake store derives its "on-disk" sha from Config, so requests carrying
    // TestSha.Of(OnDisk) pass the B2 compare-and-swap; any other sha is a Conflict.
    private const string OnDisk = "old = 1\n";

    private static IpcRequest Req(string toml, string? sha = null) =>
        new(IpcCommandType.WriteConfig,
            IpcSerializer.SerializePayload(new WriteConfigPayload(toml, sha ?? TestSha.Of(OnDisk))));

    private static (WriteConfigHandler Handler, FakeConfigStore Store, FakeConfigWritePolicy Policy) Make()
    {
        var store = new FakeConfigStore { Config = OnDisk };
        var policy = new FakeConfigWritePolicy();
        return (new WriteConfigHandler(store, policy), store, policy);
    }

    private static Result Response(string json)
    {
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.NotNull(result);
        return result!;
    }

    [Fact]
    public void Ctor_nullGuards()
    {
        Assert.Throws<ArgumentNullException>(() => new WriteConfigHandler(null!, new FakeConfigWritePolicy()));
        Assert.Throws<ArgumentNullException>(() => new WriteConfigHandler(new FakeConfigStore(), null!));
    }

    [Fact]
    public void ValidConfig_isWritten_viaCompareAndSwap_withExactTextAndSha()
    {
        var (handler, store, policy) = Make();
        var result = Response(handler.Handle(Req("max_clients = 250\n")));

        Assert.True(result.Success);
        Assert.Equal("max_clients = 250\n", store.Config);
        var cas = Assert.Single(store.CasWrites);
        Assert.Equal("max_clients = 250\n", cas.TomlText);        // exact text received
        Assert.Equal(TestSha.Of(OnDisk), cas.BaseSha256);         // exact sha received
        Assert.Equal("max_clients = 250\n", Assert.Single(policy.Checked)); // policy saw the candidate
    }

    [Fact]
    public void MissingPayload_isRejected_storeAndPolicyUntouched()
    {
        var (handler, store, policy) = Make();
        var result = Response(handler.Handle(new IpcRequest(IpcCommandType.WriteConfig, null)));

        Assert.False(result.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Equal("WriteConfig requires TomlText and BaseSha256.", result.Message);
        Assert.Empty(store.CasWrites);
        Assert.Equal(OnDisk, store.Config);
        Assert.Empty(policy.Checked);
    }

    [Fact]
    public void MissingFields_areRejected_beforeAnythingRuns()
    {
        // Null TomlText, null BaseSha256, empty BaseSha256 — each fails the payload gate
        // (first step of IC-3) so neither the policy nor the store is ever consulted.
        var payloads = new[]
        {
            new WriteConfigPayload(null!, TestSha.Of(OnDisk)),
            new WriteConfigPayload("max_clients = 1\n", null!),
            new WriteConfigPayload("max_clients = 1\n", ""),
        };
        foreach (var payload in payloads)
        {
            var (handler, store, policy) = Make();
            var request = new IpcRequest(IpcCommandType.WriteConfig, IpcSerializer.SerializePayload(payload));
            var result = Response(handler.Handle(request));

            Assert.False(result.Success);
            Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
            Assert.Equal("WriteConfig requires TomlText and BaseSha256.", result.Message);
            Assert.Empty(store.CasWrites);
            Assert.Equal(OnDisk, store.Config);
            Assert.Empty(policy.Checked);
        }
    }

    [Fact]
    public void InvalidToml_isRejected_storeAndPolicyUntouched()
    {
        var (handler, store, policy) = Make();
        var result = Response(handler.Handle(Req("max_clients = = 3")));

        Assert.False(result.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Empty(store.CasWrites);
        Assert.Equal(OnDisk, store.Config);
        Assert.Empty(policy.Checked); // schema validation runs BEFORE the policy (IC-3)
    }

    [Fact]
    public void WrongType_forKnownKey_isRejected_withFirstErrorMessageShape()
    {
        var (handler, store, policy) = Make();
        var result = Response(handler.Handle(Req("max_clients = 'lots'\n")));

        Assert.False(result.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.StartsWith("Invalid config: max_clients:", result.Message, StringComparison.Ordinal);
        Assert.Empty(store.CasWrites);
        Assert.Equal(OnDisk, store.Config);
        Assert.Empty(policy.Checked);
    }

    [Fact]
    public void PolicyRefusal_mapsToValidationFailed_messageVerbatim_storeUntouched()
    {
        var (handler, store, policy) = Make();
        policy.Result = PlatformResult.Fail(
            PlatformErrorKind.InvalidArgument,
            "OPSEC guard: netprobe_timeout must be 0 while protected");
        var result = Response(handler.Handle(Req("max_clients = 250\n")));

        Assert.False(result.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code); // InvalidArgument → ValidationFailed
        Assert.Equal("OPSEC guard: netprobe_timeout must be 0 while protected", result.Message); // IC-10 verbatim
        Assert.Empty(store.CasWrites); // refusal provably never touches the store
        Assert.Equal(OnDisk, store.Config);
    }

    [Fact]
    public void StaleBaseSha_surfacesAsConflict_messagePassthrough_configUnchanged()
    {
        var (handler, store, _) = Make();
        var result = Response(handler.Handle(Req("max_clients = 250\n", TestSha.Of("something else entirely\n"))));

        Assert.False(result.Success);
        Assert.Equal(IpcErrorCode.Conflict, result.Code); // Conflict flows through the mapping
        Assert.Equal("config file changed on disk since it was loaded — reload before saving", result.Message);
        Assert.Equal(OnDisk, store.Config); // the CAS refused: on-disk config unchanged
    }

    [Fact]
    public void StoreFailure_reportsOperationFailed_configUnchanged()
    {
        var (handler, store, _) = Make();
        store.FailNextWrite = PlatformErrorKind.OperationFailed;
        var result = Response(handler.Handle(Req("max_clients = 1\n")));

        Assert.False(result.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
        Assert.Equal(OnDisk, store.Config); // simulated rollback: config unchanged
    }
}
