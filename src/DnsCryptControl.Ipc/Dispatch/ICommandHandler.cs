using DnsCryptControl.Ipc.Commands;

namespace DnsCryptControl.Ipc.Dispatch;

/// <summary>
/// Handles exactly one privileged verb. Implementations re-validate the payload, perform
/// the operation, and return a JSON-serialized Result/Result&lt;T&gt; envelope. A handler
/// must never throw for input it can reject; the dispatcher contains any escaping exception
/// as OperationFailed.
/// </summary>
public interface ICommandHandler
{
    /// <summary>The single verb this handler serves.</summary>
    IpcCommandType Command { get; }

    /// <summary>Process the request and return a serialized Result envelope.</summary>
    string Handle(IpcRequest request);
}
