namespace DnsCryptControl.UI.Models;

/// <summary>
/// The Dashboard's truthful, diagnostics-backed protection status (§7.1).
/// <c>HelperUntrusted</c> is deliberately dropped because <c>IpcPipeClient.SendAsync</c>
/// returns <c>null</c> for both "unreachable" and "owner-check failed" (F11); C1 cannot
/// distinguish them from a <c>null</c> alone, so both fail closed to
/// <see cref="HelperUnavailable"/>. Distinguishing untrusted is deferred (D1).
/// <para><see cref="ProtectedVerified"/> (the green badge) is only ever set after a
/// <c>RunDiagnostics</c> pass proves no leak — never from <c>GetStatus</c> flags alone.</para>
/// <para><see cref="HelperIncompatible"/> (F20) is set when the helper's reported
/// <c>StatusResponse.ProtocolVersion</c> does not match <c>IpcProtocol.Version</c> — the UI
/// must never trust any other field in that response, so this state is a hard stop that is
/// never followed by diagnostics and can never lead to <see cref="ProtectedVerified"/>.</para>
/// </summary>
public enum ProtectionStatusView
{
    Unprotected,
    Applying,

    /// <summary>5j: transitional cold-start state shown for a bounded window right after enabling,
    /// while adapters are already pinned to loopback but the proxy hasn't answered its first
    /// self-check yet. Amber, NOT "leak detected". Can never be green (that still requires a real
    /// no-leak pass) and falls through to <see cref="PartiallyProtected"/> if the window elapses,
    /// so a genuine persistent leak is never masked.</summary>
    Verifying,
    ProtectedVerified,
    PartiallyProtected,
    HelperUnavailable,
    HelperIncompatible,

    /// <summary>Protection is ON by intent (adapters pinned to loopback) but the dnscrypt-proxy
    /// SERVICE is not running, so no local resolver is answering. Honestly "the DNS proxy isn't
    /// running" (amber, with a Restart hint) — NOT <see cref="PartiallyProtected"/>'s "leak detected",
    /// which implies the proxy IS up but something bypasses it. Distinct so the words + guidance match
    /// reality (a stopped proxy is fail-closed: DNS is pointed at a dead loopback listener, not leaking).</summary>
    ProxyStopped,

    /// <summary>Protection is ON, the helper is reachable and the proxy IS running (both proven by the
    /// trusted <c>GetStatus</c> frame), but the follow-up DNS self-check (<c>RunDiagnostics</c>) returned
    /// null/!Success this cycle — i.e. the DNS path could not be VERIFIED right now, NOT that the helper is
    /// gone. Amber, retried automatically by the ~1.5s poll. Deliberately distinct from
    /// <see cref="HelperUnavailable"/> so a merely-unverifiable-this-tick self-check never raises the blocking
    /// helper banner or disables the controls the user needs — the deadlock where a broken route (which makes
    /// the self-check fail) locks the user out of fixing it. Never green (that still requires a real no-leak
    /// pass) and never claims "leak detected" (that is <see cref="PartiallyProtected"/>, set only when
    /// diagnostics DID run and the leak/resolve check genuinely failed).</summary>
    DiagnosticsUnavailable,
}
