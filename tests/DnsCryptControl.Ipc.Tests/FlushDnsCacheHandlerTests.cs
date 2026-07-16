using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class FlushDnsCacheHandlerTests
{
    private sealed class FakeFlusher : IDnsCacheFlusher
    {
        public PlatformResult Next { get; set; } = PlatformResult.Ok();
        public int Calls { get; private set; }

        public PlatformResult Flush()
        {
            Calls++;
            return Next;
        }
    }

    [Fact]
    public void Command_isFlushDnsCache()
    {
        var handler = new FlushDnsCacheHandler(new FakeFlusher());
        Assert.Equal(IpcCommandType.FlushDnsCache, handler.Command);
    }

    [Fact]
    public void Flush_succeeds_returnsOk()
    {
        var flusher = new FakeFlusher();
        var json = new FlushDnsCacheHandler(flusher).Handle(new IpcRequest(IpcCommandType.FlushDnsCache, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.Equal(1, flusher.Calls);
        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.Equal(IpcErrorCode.None, result.Code);
    }

    [Fact]
    public void Flush_failure_isMappedToIpcErrorCode()
    {
        var flusher = new FakeFlusher { Next = PlatformResult.Fail(PlatformErrorKind.OperationFailed, "both backends failed") };
        var json = new FlushDnsCacheHandler(flusher).Handle(new IpcRequest(IpcCommandType.FlushDnsCache, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
        Assert.Equal("both backends failed", result.Message);
    }

    [Fact]
    public void Ctor_rejectsNullFlusher()
    {
        Assert.Throws<System.ArgumentNullException>(() => new FlushDnsCacheHandler(null!));
    }
}
