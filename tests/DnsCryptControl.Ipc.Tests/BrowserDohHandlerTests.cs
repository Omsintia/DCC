using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class BrowserDohHandlerTests
{
    private sealed class FakeBrowserDohPolicy : IBrowserDohPolicy
    {
        public bool? LastEnable;
        public PlatformResult NextResult = PlatformResult.Ok();

        public PlatformResult SetBrowserDohPolicy(bool enable)
        {
            LastEnable = enable;
            return NextResult;
        }

        public bool IsBrowserDohPolicyApplied() => LastEnable == true;
    }

    private static IpcRequest Req(bool enable) =>
        new(IpcCommandType.SetBrowserDohPolicy, IpcSerializer.SerializePayload(new SetTogglePayload(enable)));

    [Fact]
    public void Command_isSetBrowserDohPolicy()
    {
        var handler = new BrowserDohHandler(new FakeBrowserDohPolicy());
        Assert.Equal(IpcCommandType.SetBrowserDohPolicy, handler.Command);
    }

    [Fact]
    public void Enable_callsPolicyWithTrue_andReturnsOk()
    {
        var policy = new FakeBrowserDohPolicy();
        var json = new BrowserDohHandler(policy).Handle(Req(true));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.True(policy.LastEnable);
    }

    [Fact]
    public void Disable_callsPolicyWithFalse()
    {
        var policy = new FakeBrowserDohPolicy();
        new BrowserDohHandler(policy).Handle(Req(false));
        Assert.False(policy.LastEnable);
    }

    [Fact]
    public void PolicyFailure_isMappedToOperationFailed()
    {
        var policy = new FakeBrowserDohPolicy
        {
            NextResult = PlatformResult.Fail(PlatformErrorKind.OperationFailed, "registry write denied"),
        };
        var json = new BrowserDohHandler(policy).Handle(Req(true));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
        Assert.Equal("registry write denied", result.Message);
    }

    [Fact]
    public void MissingPayload_isRejected_andPolicyNeverCalled()
    {
        var policy = new FakeBrowserDohPolicy();
        var json = new BrowserDohHandler(policy).Handle(new IpcRequest(IpcCommandType.SetBrowserDohPolicy, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Null(policy.LastEnable); // never invoked
    }

    [Fact]
    public void GarbledPayload_isRejected_andPolicyNeverCalled()
    {
        var policy = new FakeBrowserDohPolicy();
        var json = new BrowserDohHandler(policy)
            .Handle(new IpcRequest(IpcCommandType.SetBrowserDohPolicy, "{not valid json"));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Null(policy.LastEnable);
    }
}
