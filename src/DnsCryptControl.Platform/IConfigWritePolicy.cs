namespace DnsCryptControl.Platform;

/// <summary>
/// Save gate consulted by the WriteConfig handler AFTER schema validation and BEFORE the
/// config store is touched (IC-3 ordering): decides whether a candidate dnscrypt-proxy.toml
/// may be written right now. Ok = save may proceed. The production implementation
/// (ProtectionAwareConfigWritePolicy in the Service) refuses OPSEC-unsafe candidates while
/// protection is enabled (P5b-U1) — this is the server-side trust-boundary enforcement; the
/// UI's mirrored check is UX only and never replaces it. Defined as an interface so the
/// handler is unit-testable with a fake.
/// </summary>
public interface IConfigWritePolicy
{
    /// <summary>Returns Ok when <paramref name="candidateTomlText"/> may be written, or a
    /// failure whose <c>Message</c> is human-actionable and shown verbatim by the UI —
    /// prefixed <c>"OPSEC guard: "</c> per IC-10. Refusals use
    /// <see cref="PlatformErrorKind.InvalidArgument"/> (→ ValidationFailed on the wire);
    /// <see cref="PlatformErrorKind.Conflict"/> is reserved for the base-sha race.</summary>
    PlatformResult Check(string candidateTomlText);
}
