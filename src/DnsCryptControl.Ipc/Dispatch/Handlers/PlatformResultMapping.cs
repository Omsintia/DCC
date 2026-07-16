using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>Maps a Platform-layer failure category onto the IPC wire error code so every
/// handler translates errors identically.</summary>
internal static class PlatformResultMapping
{
    public static IpcErrorCode ToIpc(PlatformErrorKind kind) => kind switch
    {
        PlatformErrorKind.None => IpcErrorCode.None,
        PlatformErrorKind.NotFound => IpcErrorCode.NotFound,
        PlatformErrorKind.InvalidArgument => IpcErrorCode.ValidationFailed,
        PlatformErrorKind.Timeout => IpcErrorCode.OperationFailed,
        PlatformErrorKind.OperationFailed => IpcErrorCode.OperationFailed,
        PlatformErrorKind.Conflict => IpcErrorCode.Conflict,
        _ => IpcErrorCode.OperationFailed,
    };
}
