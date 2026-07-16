namespace DnsCryptControl.UI.Services;

/// <summary>
/// Result of a one-shot config-file load (IC-9). <see cref="Sha256"/> is the lowercase
/// hex SHA-256 of the exact RAW on-disk bytes — the optimistic-concurrency base the
/// helper re-hashes on save — and <see cref="Text"/> is the UTF-8 decode of those SAME
/// bytes with a single leading U+FEFF stripped (so a BOM never leaks into the Tomlyn
/// parse or into the saved file, while the CAS base stays byte-exact).
/// </summary>
public sealed record ConfigLoadResult(bool Success, string? Text, string? Sha256, string? Error)
{
    public static ConfigLoadResult Ok(string text, string sha256) => new(true, text, sha256, null);
    public static ConfigLoadResult Fail(string error) => new(false, null, null, error);
}

/// <summary>How a Save &amp; apply attempt ended. The distinctions matter to the editor:
/// everything up to and including <see cref="HelperUnavailable"/>-on-write means NOTHING
/// was written; <see cref="RestartFailed"/> and <see cref="ProxyRejected"/> mean the
/// config WAS saved but its application is unverified/rejected.</summary>
public enum ConfigSaveOutcomeKind
{
    /// <summary>Written, proxy restarted, and status confirmed the proxy running.</summary>
    Applied,

    /// <summary>The handshake reported a protocol version other than ours (P5b-E1) —
    /// a mismatched helper must never receive a WriteConfig frame (a v1 helper would
    /// silently ignore <c>BaseSha256</c>: no CAS, no OPSEC policy). Nothing written.</summary>
    HelperIncompatible,

    /// <summary>The serialized request would exceed the transport's frame cap.
    /// Nothing sent, nothing written.</summary>
    TooLarge,

    /// <summary>No usable reply from the helper (down, broken pipe, untrusted owner).
    /// On the write step this means the save may or may not have landed — the editor
    /// reloads before retrying — but no restart was attempted.</summary>
    HelperUnavailable,

    /// <summary>The on-disk file no longer matches the loaded base sha (BE-6) — the
    /// helper refused the compare-and-swap. Nothing written.</summary>
    Conflict,

    /// <summary>The helper refused the write (schema validation or the OPSEC guard) —
    /// <see cref="ConfigSaveOutcome.Message"/> carries its reason verbatim (IC-10).
    /// Nothing written.</summary>
    Rejected,

    /// <summary>The write SUCCEEDED but the proxy restart failed or its reply was lost —
    /// status unverified. Never conflated with <see cref="HelperUnavailable"/>.</summary>
    RestartFailed,

    /// <summary>Write and restart succeeded but the proxy never reported running before
    /// the poll timeout — the new config appears rejected by the proxy (§7.3; DNS stays
    /// at loopback by construction). Never a green state.</summary>
    ProxyRejected,
}

/// <summary>Outcome of <see cref="IConfigFileService.SaveAndApplyAsync"/>: a
/// discriminated kind plus the human-actionable message the editor shows verbatim.</summary>
public sealed record ConfigSaveOutcome(ConfigSaveOutcomeKind Kind, string? Message);

/// <summary>
/// The Configuration editor's single read path for <c>dnscrypt-proxy.toml</c>
/// (§4.2/§7.3). The UI process may READ the file directly (it is world-readable under
/// <c>%ProgramData%</c>); every WRITE goes through the helper's policy-gated
/// compare-and-swap verb — never through this service touching the disk.
/// </summary>
public interface IConfigFileService
{
    /// <summary>Reads the on-disk config ONCE as bytes and derives both the editor text
    /// and the save-time CAS base from that single read (IC-9). Fails closed
    /// (missing/locked/unreadable file → failure result); never throws.</summary>
    ConfigLoadResult Load();

    /// <summary>Outcome-typed save orchestration (§7.3): version-skew handshake gate →
    /// frame-size pre-check → policy-gated compare-and-swap <c>WriteConfig</c> →
    /// <c>RestartProxy</c> → status poll until the proxy reports running (or timeout).
    /// <paramref name="baseSha256"/> is the LOAD-time snapshot sha (P5b-E8): any
    /// concurrent on-disk change surfaces as an explicit <see cref="ConfigSaveOutcomeKind.Conflict"/>
    /// rather than being silently rebased over.</summary>
    Task<ConfigSaveOutcome> SaveAndApplyAsync(string candidateText, string baseSha256, CancellationToken ct);
}
