using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>
/// VerifyAndInstallBinary: deserializes the untrusted {TempPath, ExpectedTag} payload and delegates
/// to IBinaryVerifyInstaller, which minisign-verifies the zip against the pinned release key and
/// installs from the verified bytes. The heavy validation/crypto/install lives in the Platform impl;
/// this handler only rejects a missing/garbled payload (ValidationFailed, installer untouched) and
/// maps the PlatformResult onto the wire error code. Returns the non-generic Result envelope.
/// </summary>
public sealed class VerifyAndInstallBinaryHandler : ICommandHandler
{
    private readonly IBinaryVerifyInstaller _installer;

    public VerifyAndInstallBinaryHandler(IBinaryVerifyInstaller installer)
    {
        ArgumentNullException.ThrowIfNull(installer);
        _installer = installer;
    }

    public IpcCommandType Command => IpcCommandType.VerifyAndInstallBinary;

    public string Handle(IpcRequest request)
    {
        if (request.PayloadJson is null
            || IpcSerializer.DeserializePayload<VerifyAndInstallBinaryPayload>(request.PayloadJson) is not { } payload
            || string.IsNullOrEmpty(payload.TempPath)
            || string.IsNullOrEmpty(payload.ExpectedTag))
        {
            return IpcSerializer.SerializePayload(
                Result.Fail(IpcErrorCode.ValidationFailed, "VerifyAndInstallBinary requires TempPath and ExpectedTag."));
        }

        var op = _installer.VerifyAndInstall(payload.TempPath, payload.ExpectedTag);
        return op.Success
            ? IpcSerializer.SerializePayload(Result.Ok())
            : IpcSerializer.SerializePayload(
                Result.Fail(PlatformResultMapping.ToIpc(op.Error), op.Message ?? "binary verify/install failed"));
    }
}
