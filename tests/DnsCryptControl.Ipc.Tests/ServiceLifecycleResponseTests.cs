using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class ServiceLifecycleResponseTests
{
    [Fact]
    public void ServiceLifecycleResponse_roundTrips_throughResultEnvelope()
    {
        var payload = Result<ServiceLifecycleResponse>.Ok(new ServiceLifecycleResponse("Running"));
        var json = IpcSerializer.SerializePayload(payload);
        var back = IpcSerializer.DeserializePayload<Result<ServiceLifecycleResponse>>(json);

        Assert.NotNull(back);
        Assert.True(back!.Success);
        Assert.Equal("Running", back.Value!.State);
    }

    [Fact]
    public void ServiceLifecycleResponse_failEnvelope_roundTrips()
    {
        var payload = Result<ServiceLifecycleResponse>.Fail(IpcErrorCode.OperationFailed, "could not start");
        var json = IpcSerializer.SerializePayload(payload);
        var back = IpcSerializer.DeserializePayload<Result<ServiceLifecycleResponse>>(json);

        Assert.NotNull(back);
        Assert.False(back!.Success);
        Assert.Null(back.Value);
        Assert.Equal(IpcErrorCode.OperationFailed, back.Code);
    }
}
