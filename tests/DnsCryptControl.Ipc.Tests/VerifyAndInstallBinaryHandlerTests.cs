using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class VerifyAndInstallBinaryHandlerTests
{
    private sealed class FakeInstaller : IBinaryVerifyInstaller
    {
        public PlatformResult Result { get; init; } = PlatformResult.Ok();
        public string? SeenPath { get; private set; }
        public string? SeenTag { get; private set; }
        public PlatformResult VerifyAndInstall(string tempZipPath, string expectedTag)
        {
            SeenPath = tempZipPath; SeenTag = expectedTag;
            return Result;
        }
    }

    private static string Dispatch(IBinaryVerifyInstaller installer, string? payloadJson)
    {
        var req = new IpcRequest(IpcCommandType.VerifyAndInstallBinary, payloadJson);
        return new VerifyAndInstallBinaryHandler(installer).Handle(req);
    }

    [Fact]
    public void Command_isVerifyAndInstallBinary()
    {
        Assert.Equal(IpcCommandType.VerifyAndInstallBinary,
            new VerifyAndInstallBinaryHandler(new FakeInstaller()).Command);
    }

    [Fact]
    public void Handle_validPayload_delegatesAndReturnsOk()
    {
        var fake = new FakeInstaller();
        var payload = IpcSerializer.SerializePayload(new VerifyAndInstallBinaryPayload(@"C:\stage\x.zip", "2.1.16"));
        var json = Dispatch(fake, payload);
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.True(result!.Success);
        Assert.Equal(@"C:\stage\x.zip", fake.SeenPath);
        Assert.Equal("2.1.16", fake.SeenTag);
    }

    [Fact]
    public void Handle_nullPayload_failsValidationWithoutCallingInstaller()
    {
        var fake = new FakeInstaller();
        var json = Dispatch(fake, null);
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Null(fake.SeenPath);
    }

    [Fact]
    public void Handle_installerFailure_mapsPlatformErrorToIpcCode()
    {
        var fake = new FakeInstaller { Result = PlatformResult.Fail(PlatformErrorKind.OperationFailed, "bad sig") };
        var payload = IpcSerializer.SerializePayload(new VerifyAndInstallBinaryPayload(@"C:\stage\x.zip", "2.1.16"));
        var json = Dispatch(fake, payload);
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
        Assert.Equal("bad sig", result.Message);
    }
}
