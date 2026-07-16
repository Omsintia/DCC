namespace DnsCryptControl.Platform;

using DnsCryptControl.Platform.Diagnostics;

/// <summary>Read-only health + DNS-leak self-check. Never mutates state.
/// <para><see cref="Run"/> makes no external server contact (its self-check name is answered locally
/// by the proxy). <see cref="VerifyUpstreamResolution"/> deliberately does NOT share that guarantee:
/// it sends one real query to the LOOPBACK proxy, which egresses it through the proxy's configured
/// (possibly anonymized) route — that upstream round trip is exactly what it exists to prove, because
/// the local self-check false-greens on a dead route. It is invoked only on an explicit user action
/// (post-apply), never on the continuous badge poll.</para></summary>
public interface IDiagnosticsProbe
{
    PlatformResult<DiagnosticsSnapshot> Run();

    /// <summary>Resolves one random real-delegated name via the loopback proxy to prove the configured
    /// upstream route actually resolves. Bounded (a few seconds); a dead route returns an Ok result
    /// with <c>Resolved=false</c>, not a Fail — Fail means the probe itself could not run.</summary>
    PlatformResult<ResolveVerification> VerifyUpstreamResolution();
}
