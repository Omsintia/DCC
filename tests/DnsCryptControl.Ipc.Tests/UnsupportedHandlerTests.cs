using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Serialization;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class UnsupportedHandlerTests
{
    [Fact]
    public void Unsupported_alwaysFailsWithUnsupportedCode()
    {
        var handler = new UnsupportedHandler(IpcCommandType.SetKillSwitch);
        Assert.Equal(IpcCommandType.SetKillSwitch, handler.Command);
        var json = handler.Handle(new IpcRequest(IpcCommandType.SetKillSwitch, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.Unsupported, result.Code);
    }
}
