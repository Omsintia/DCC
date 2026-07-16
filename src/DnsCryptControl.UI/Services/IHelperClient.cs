using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Platform.Diagnostics;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// The single serialized typed pipe client every UI screen talks to the helper
/// through (BE-2). Every method fails closed: a broken pipe, timeout, or an
/// untrusted server (F11) surfaces as a <c>null</c> result, never a silent success.
/// </summary>
public interface IHelperClient : IAsyncDisposable
{
    Task<Result<StatusResponse>?> GetStatusAsync(CancellationToken ct);

    Task<Result<ProtectionResponse>?> EnableProtectionAsync(bool withKillSwitch, CancellationToken ct);

    Task<Result<ProtectionResponse>?> DisableProtectionAsync(CancellationToken ct);

    Task<Result<DiagnosticsSnapshot>?> RunDiagnosticsAsync(CancellationToken ct);

    /// <summary>v4 (FIX #1): the post-apply real-name resolve check — proves the proxy's configured
    /// upstream route actually resolves, which <see cref="RunDiagnosticsAsync"/> structurally cannot
    /// (its undelegated .test self-check is answered locally, so it false-greens on a dead
    /// anonymized route). Bounded (≤ ~5 s in the helper, inside the 30 s pipe cap). A dead route is
    /// a SUCCESSFUL result whose value says <c>Resolved=false</c>; a failed/<c>null</c> result means
    /// the check itself could not run (UNKNOWN — surface the softer "couldn't verify" copy, never
    /// silence). Call only on an explicit user apply, never on a poll.</summary>
    Task<Result<ResolveVerification>?> VerifyResolutionAsync(CancellationToken ct);

    Task<Result<ServiceLifecycleResponse>?> RestartProxyAsync(CancellationToken ct);

    /// <summary>Non-generic <see cref="Result"/> — FlushDnsCache's handler returns the
    /// non-generic wire type, unlike every other verb here.</summary>
    Task<Result?> FlushDnsCacheAsync(CancellationToken ct);

    /// <summary>Sends the full config text for the helper to validate, policy-check, and
    /// compare-and-swap write (BE-6). <paramref name="baseSha256"/> is the lowercase-hex
    /// SHA-256 of the on-disk file BYTES the editor loaded (IC-9); a stale base surfaces
    /// as a failed <see cref="Result"/> with <see cref="IpcErrorCode.Conflict"/>.
    /// Non-generic <see cref="Result"/> response, like FlushDnsCache.</summary>
    Task<Result?> WriteConfigAsync(string tomlText, string baseSha256, CancellationToken ct);

    /// <summary>Sends a full rule-file body for the helper to line-validate (per-line cap,
    /// no NUL) and SafePath-confined atomic-write (BE-6, Phase 5d). Unlike
    /// <see cref="WriteConfigAsync"/> there is NO baseSha — rule writes are unconditional
    /// last-writer-wins (IC-13; staleness is handled by the caller re-reading before save).
    /// <paramref name="kind"/> is the <c>RuleFileKind</c> member NAME string; the helper
    /// parses it into the closed enum and never uses it as a path component (CWE-22).
    /// Non-generic <see cref="Result"/> response, like WriteConfig.</summary>
    Task<Result?> WriteRuleFileAsync(string kind, string content, CancellationToken ct);

    /// <summary>Uninstalls the dnscrypt-proxy service (Settings "Remove proxy service", Phase 5f).
    /// Non-generic <see cref="Result"/>, like FlushDnsCache. The UI calls this ONLY after a
    /// confirmed-successful soft reset (<see cref="DisableProtectionAsync"/>); a null reply is
    /// UNKNOWN, never success (never uninstall while DNS may still point at the proxy).</summary>
    Task<Result?> UninstallProxyServiceAsync(CancellationToken ct);

    /// <summary>Applies or restores the browsers'-built-in-DoH-disable policy (Phase 5f).
    /// <paramref name="enable"/> = true disables browser DoH (so browsers can't bypass DnsCrypt);
    /// false restores the prior policy. Non-generic <see cref="Result"/>; reuses the existing
    /// SetBrowserDohPolicy verb + SetTogglePayload (no new wire — IC-2).</summary>
    Task<Result?> SetBrowserDohPolicyAsync(bool enable, CancellationToken ct);

    /// <summary>Places the helper's bundled, minisign-signed ODoH source-list caches into the
    /// proxy's protected dir (byte-exact) so the proxy loads ODoH FROM CACHE at startup instead
    /// of the boot-time download that dnscrypt-proxy treats as FATAL when it can't resolve the
    /// list URL yet — the sole cause of "adding ODoH bricks all DNS". No payload; non-generic
    /// <see cref="Result"/>, like FlushDnsCache. A null reply is UNKNOWN, never success — the
    /// caller must NOT add the odoh-* sources unless this returns a successful result (adding
    /// sources without their cache is exactly what bricks the proxy).</summary>
    Task<Result?> PlaceOdohCacheAsync(CancellationToken ct);
}
