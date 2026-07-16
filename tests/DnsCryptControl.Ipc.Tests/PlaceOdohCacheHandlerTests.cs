using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

/// <summary>
/// PlaceOdohCache (verb 19): the handler simply delegates to the store's own embedded-asset placement —
/// no caller-supplied content — and maps the store result to the non-generic wire <see cref="Result"/>.
/// </summary>
public class PlaceOdohCacheHandlerTests
{
    [Fact]
    public void Command_isPlaceOdohCache()
    {
        Assert.Equal(IpcCommandType.PlaceOdohCache, new PlaceOdohCacheHandler(new FakeConfigStore()).Command);
    }

    [Fact]
    public void Handle_delegatesToTheStore_andReportsOk()
    {
        var store = new FakeConfigStore();
        var json = new PlaceOdohCacheHandler(store).Handle(new IpcRequest(IpcCommandType.PlaceOdohCache, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.Equal(1, store.PlaceOdohCalls);
        Assert.True(result!.Success);
    }

    [Fact]
    public void Handle_mapsAStoreFailure_toAFailedResult()
    {
        var store = new FakeConfigStore { FailNextOdohPlace = PlatformErrorKind.OperationFailed };
        var json = new PlaceOdohCacheHandler(store).Handle(new IpcRequest(IpcCommandType.PlaceOdohCache, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);

        Assert.Equal(1, store.PlaceOdohCalls);
        Assert.False(result!.Success);
    }
}
