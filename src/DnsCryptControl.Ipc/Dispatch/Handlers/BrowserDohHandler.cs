using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>SetBrowserDohPolicy: deserializes a SetTogglePayload and forces browser-internal
/// DoH off (enable) or restores the prior policy (disable) via IBrowserDohPolicy. Returns the
/// non-generic Result envelope. Rejects missing/garbled input without invoking the policy.</summary>
public sealed class BrowserDohHandler : ICommandHandler
{
    private readonly IBrowserDohPolicy _policy;

    public BrowserDohHandler(IBrowserDohPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        _policy = policy;
    }

    public IpcCommandType Command => IpcCommandType.SetBrowserDohPolicy;

    public string Handle(IpcRequest request)
    {
        if (request.PayloadJson is null
            || IpcSerializer.DeserializePayload<SetTogglePayload>(request.PayloadJson) is not { } payload)
        {
            return IpcSerializer.SerializePayload(
                Result.Fail(IpcErrorCode.ValidationFailed, "SetBrowserDohPolicy requires an Enable payload."));
        }

        var op = _policy.SetBrowserDohPolicy(payload.Enable);
        return op.Success
            ? IpcSerializer.SerializePayload(Result.Ok())
            : IpcSerializer.SerializePayload(
                Result.Fail(PlatformResultMapping.ToIpc(op.Error), op.Message ?? "browser DoH policy change failed"));
    }
}
