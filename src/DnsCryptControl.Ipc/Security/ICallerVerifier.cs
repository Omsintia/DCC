namespace DnsCryptControl.Ipc.Security;

/// <summary>
/// Server-side gate: decides whether a connected client is a trusted peer. The real impl
/// (in the Service project) resolves the client's image via GetNamedPipeClientProcessId,
/// validates its Authenticode signature with WinVerifyTrust, and matches the signer against
/// a publisher allow-list. Abstracted so the dispatcher/server are unit-testable with a fake.
/// </summary>
public interface ICallerVerifier
{
    /// <summary>True only if the caller is an allowed, validly signed executable.
    /// Implementations must fail closed (return false) on any uncertainty.</summary>
    bool IsTrusted(CallerIdentity caller);
}
