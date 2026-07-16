namespace DnsCryptControl.Platform;

/// <summary>Machine-readable failure category for platform operations. Mapped to
/// <c>IpcErrorCode</c> by the IPC handlers (numeric on the wire — append-only).</summary>
public enum PlatformErrorKind { None, NotFound, OperationFailed, InvalidArgument, Timeout, Conflict }

/// <summary>Outcome of a void platform operation.</summary>
public sealed record PlatformResult(bool Success, PlatformErrorKind Error, string? Message)
{
    public static PlatformResult Ok() => new(true, PlatformErrorKind.None, null);
    public static PlatformResult Fail(PlatformErrorKind error, string message) => new(false, error, message);
}

/// <summary>Outcome of a platform operation that yields a value.</summary>
public sealed record PlatformResult<T>(bool Success, T? Value, PlatformErrorKind Error, string? Message)
{
    public static PlatformResult<T> Ok(T value) => new(true, value, PlatformErrorKind.None, null);
    public static PlatformResult<T> Fail(PlatformErrorKind error, string message) => new(false, default, error, message);
}
