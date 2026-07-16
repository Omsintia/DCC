using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class IpcSerializerTests
{
    [Fact]
    public void Request_roundTrips()
    {
        var req = new IpcRequest(IpcCommandType.WriteConfig, "{\"TomlText\":\"max_clients = 1\"}");
        var json = IpcSerializer.Serialize(req);
        var back = IpcSerializer.DeserializeRequest(json);
        Assert.NotNull(back);
        Assert.Equal(IpcCommandType.WriteConfig, back!.Command);
        Assert.Equal(req.PayloadJson, back.PayloadJson);
    }

    [Fact]
    public void Payload_roundTrips()
    {
        var json = IpcSerializer.SerializePayload(new WriteConfigPayload("max_clients = 1", TestSha.Of("old = 1\n")));
        var back = IpcSerializer.DeserializePayload<WriteConfigPayload>(json);
        Assert.NotNull(back);
        Assert.Equal("max_clients = 1", back!.TomlText);
    }

    [Fact]
    public void WriteConfigPayload_v2_roundTrips_tomlText_and_baseSha256()
    {
        // IC-2: BaseSha256 is a required second field, PascalCase on the wire, riding
        // the existing IpcJsonContext registration (no new [JsonSerializable] needed).
        var sha = new string('a', 64);
        var json = IpcSerializer.SerializePayload(new WriteConfigPayload("x", sha));
        Assert.Contains("\"BaseSha256\"", json, StringComparison.Ordinal);
        var back = IpcSerializer.DeserializePayload<WriteConfigPayload>(json);
        Assert.NotNull(back);
        Assert.Equal("x", back!.TomlText);
        Assert.Equal(sha, back.BaseSha256);
    }

    [Fact]
    public void DeserializeRequest_garbage_returnsNull()
    {
        Assert.Null(IpcSerializer.DeserializeRequest("}{ not json"));
    }

    [Fact]
    public void DeserializeRequest_oversizedInput_isRejected()
    {
        var huge = "{\"Command\":0,\"PayloadJson\":\"" + new string('a', 2_000_000) + "\"}";
        Assert.Null(IpcSerializer.DeserializeRequest(huge));
    }

    [Fact]
    public void DeserializeRequest_unknownProperty_isIgnoredNotThrown()
    {
        // A hostile/extra field must not crash the SYSTEM helper; it is ignored.
        var back = IpcSerializer.DeserializeRequest("{\"Command\":0,\"PayloadJson\":null,\"evil\":\"x\"}");
        Assert.NotNull(back);
        Assert.Equal(IpcCommandType.GetStatus, back!.Command);
    }

    [Fact]
    public void DeserializePayload_garbage_returnsNull()
    {
        Assert.Null(IpcSerializer.DeserializePayload<WriteConfigPayload>("}{ not json"));
    }

    [Fact]
    public void DeserializePayload_oversizedInput_isRejected()
    {
        Assert.Null(IpcSerializer.DeserializePayload<WriteConfigPayload>(new string('a', 2_000_000)));
    }

    [Fact]
    public void StatusResponse_payload_roundTrips()
    {
        var json = IpcSerializer.SerializePayload(
            new StatusResponse(ProxyRunning: true, ActiveResolver: "cloudflare", KillSwitchEnabled: false, LeakMitigationsEnabled: true, ProtocolVersion: IpcProtocol.Version, HelperBuild: "test"));
        var back = IpcSerializer.DeserializePayload<StatusResponse>(json);
        Assert.NotNull(back);
        Assert.True(back!.ProxyRunning);
        Assert.Equal("cloudflare", back.ActiveResolver);
        Assert.False(back.KillSwitchEnabled);
        Assert.True(back.LeakMitigationsEnabled);
    }

    [Fact]
    public void ResultOfStatusResponse_roundTrips()
    {
        var ok = Result<StatusResponse>.Ok(new StatusResponse(true, null, false, false, IpcProtocol.Version, "test"));
        var json = IpcSerializer.SerializePayload(ok);
        var back = IpcSerializer.DeserializePayload<Result<StatusResponse>>(json);
        Assert.NotNull(back);
        Assert.True(back!.Success);
        Assert.NotNull(back.Value);
        Assert.True(back.Value!.ProxyRunning);
    }
}
