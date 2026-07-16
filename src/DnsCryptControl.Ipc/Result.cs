using DnsCryptControl.Core.Security;

namespace DnsCryptControl.Ipc;

// Serialized as NUMBERS on the wire (no string converter in IpcJsonContext):
// new members are APPEND-ONLY — inserting mid-enum would renumber every existing code.
public enum IpcErrorCode { None, ValidationFailed, NotAuthorized, NotFound, OperationFailed, Unsupported, Conflict }

public sealed record Result(bool Success, IpcErrorCode Code, string? Message)
{
    public static Result Ok() => new(true, IpcErrorCode.None, null);

    // Every failure message crosses the privileged-helper -> unprivileged-UI wire, so scrub filesystem
    // paths / SIDs out of it at this single chokepoint (F6). Redact is a no-op on the static validation
    // literals and only rewrites platform-origin messages that carry a path/SID.
    public static Result Fail(IpcErrorCode code, string message) => new(false, code, MessageScrub.Redact(message));
}

public sealed record Result<T>(bool Success, T? Value, IpcErrorCode Code, string? Message)
{
    public static Result<T> Ok(T value) => new(true, value, IpcErrorCode.None, null);
    public static Result<T> Fail(IpcErrorCode code, string message) => new(false, default, code, MessageScrub.Redact(message));
}
