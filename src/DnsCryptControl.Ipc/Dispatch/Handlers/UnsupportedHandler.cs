using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>
/// Safety-net handler for enum values with no registered implementation (e.g. a newer
/// client verb hitting an older helper). Always fails closed with
/// IpcErrorCode.Unsupported; the dispatcher registers this for any unimplemented verb so
/// it keeps full enum coverage.
/// </summary>
public sealed class UnsupportedHandler : ICommandHandler
{
    public UnsupportedHandler(IpcCommandType command) => Command = command;

    public IpcCommandType Command { get; }

    public string Handle(IpcRequest request) =>
        IpcSerializer.SerializePayload(
            Result.Fail(IpcErrorCode.Unsupported, $"Command '{Command}' is not supported by this helper version."));
}
