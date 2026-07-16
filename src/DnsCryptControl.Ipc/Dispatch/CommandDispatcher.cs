using System;
using System.Collections.Generic;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;

namespace DnsCryptControl.Ipc.Dispatch;

/// <summary>
/// The single funnel for every privileged request. Deserializes the request (failing
/// closed on malformed/oversized input via IpcSerializer), routes to the one handler for
/// the command, and returns its JSON Result. Construction asserts that EVERY IpcCommandType
/// has exactly one handler, so the full vocabulary is provably covered and a future verb
/// cannot be silently dropped. Any exception escaping a handler is contained as
/// OperationFailed so a single bad request can never crash the SYSTEM helper.
/// </summary>
public sealed class CommandDispatcher
{
    private readonly Dictionary<IpcCommandType, ICommandHandler> _handlers;

    public CommandDispatcher(IEnumerable<ICommandHandler> handlers)
    {
        ArgumentNullException.ThrowIfNull(handlers);
        var map = new Dictionary<IpcCommandType, ICommandHandler>();
        foreach (var handler in handlers)
        {
            if (!map.TryAdd(handler.Command, handler))
                throw new InvalidOperationException($"Duplicate handler for command {handler.Command}.");
        }

        foreach (var command in Enum.GetValues<IpcCommandType>())
        {
            if (!map.ContainsKey(command))
                throw new InvalidOperationException($"No handler registered for command {command}.");
        }

        _handlers = map;
    }

    public string Dispatch(string requestJson)
    {
        var request = IpcSerializer.DeserializeRequest(requestJson);
        if (request is null)
            return IpcSerializer.SerializePayload(
                Result.Fail(IpcErrorCode.ValidationFailed, "Malformed or oversized request."));

        if (!Enum.IsDefined(request.Command) || !_handlers.TryGetValue(request.Command, out var handler))
            return IpcSerializer.SerializePayload(
                Result.Fail(IpcErrorCode.Unsupported, $"Unsupported command '{(int)request.Command}'."));

        try
        {
            return handler.Handle(request);
        }
        catch (Exception ex)
        {
            return IpcSerializer.SerializePayload(
                Result.Fail(IpcErrorCode.OperationFailed, $"Handler faulted: {ex.GetType().Name}."));
        }
    }
}
