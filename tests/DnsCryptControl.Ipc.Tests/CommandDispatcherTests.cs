using System;
using System.Collections.Generic;
using System.Linq;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch;
using DnsCryptControl.Ipc.Serialization;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class CommandDispatcherTests
{
    private sealed class EchoHandler : ICommandHandler
    {
        public EchoHandler(IpcCommandType command) => Command = command;
        public IpcCommandType Command { get; }
        public string Handle(IpcRequest request) => IpcSerializer.SerializePayload(Result.Ok());
    }

    private static IEnumerable<ICommandHandler> AllHandlers() =>
        Enum.GetValues<IpcCommandType>().Select(c => (ICommandHandler)new EchoHandler(c));

    [Fact]
    public void Ctor_withFullCoverage_succeeds()
    {
        var d = new CommandDispatcher(AllHandlers());
        Assert.NotNull(d);
    }

    [Fact]
    public void Ctor_missingVerb_throws()
    {
        var partial = AllHandlers().Where(h => h.Command != IpcCommandType.RunDiagnostics);
        Assert.Throws<InvalidOperationException>(() => new CommandDispatcher(partial));
    }

    [Fact]
    public void Ctor_duplicateVerb_throws()
    {
        var dupes = AllHandlers().Concat(new[] { (ICommandHandler)new EchoHandler(IpcCommandType.GetStatus) });
        Assert.Throws<InvalidOperationException>(() => new CommandDispatcher(dupes));
    }

    [Fact]
    public void Dispatch_validRequest_routesToHandler()
    {
        var d = new CommandDispatcher(AllHandlers());
        var json = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.GetStatus, null));
        var respJson = d.Dispatch(json);
        var result = IpcSerializer.DeserializePayload<Result>(respJson);
        Assert.NotNull(result);
        Assert.True(result!.Success);
    }

    [Fact]
    public void Dispatch_garbageJson_failsClosed()
    {
        var d = new CommandDispatcher(AllHandlers());
        var respJson = d.Dispatch("}{ not json");
        var result = IpcSerializer.DeserializePayload<Result>(respJson);
        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
    }

    [Fact]
    public void Dispatch_outOfRangeCommand_failsClosed()
    {
        var d = new CommandDispatcher(AllHandlers());
        // Hand-craft a request whose Command number is outside the enum.
        var json = "{\"Command\":999,\"PayloadJson\":null}";
        var respJson = d.Dispatch(json);
        var result = IpcSerializer.DeserializePayload<Result>(respJson);
        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.Unsupported, result.Code);
    }

    [Fact]
    public void Dispatch_handlerThrows_isContainedAsOperationFailed()
    {
        var throwing = new ThrowingHandler();
        var handlers = AllHandlers().Where(h => h.Command != IpcCommandType.GetStatus).Concat(new[] { (ICommandHandler)throwing });
        var d = new CommandDispatcher(handlers);
        var json = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.GetStatus, null));
        var respJson = d.Dispatch(json);
        var result = IpcSerializer.DeserializePayload<Result>(respJson);
        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
    }

    private sealed class ThrowingHandler : ICommandHandler
    {
        public IpcCommandType Command => IpcCommandType.GetStatus;
        public string Handle(IpcRequest request) => throw new InvalidOperationException("boom");
    }
}
