using System;
using System.Buffers;
using System.IO;
using System.Text;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// The single home for the file-system locations the UI reads and writes. Consolidates the
/// <c>%ProgramData%\DnsCryptControl</c> literals that were duplicated across the readers, and
/// adds the Phase 5c per-user store (<c>%LOCALAPPDATA%</c>) and the bundled resolver-snapshot
/// location (F21). Pure path composition — no I/O.
/// </summary>
public static class UiPaths
{
    /// <summary>The shared, ACL'd data directory the helper owns and Users can read.</summary>
    public static string ProgramDataDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DnsCryptControl");

    /// <summary>The managed <c>dnscrypt-proxy.toml</c>.</summary>
    public static string ConfigFile => Path.Combine(ProgramDataDir, "dnscrypt-proxy.toml");

    /// <summary>The installed proxy binary (next to the toml, per upstream's working-dir convention).
    /// Read-only, offline, by the Phase 5f integrity panel; the read fails closed if the path is wrong.</summary>
    public static string ProxyExeFile => Path.Combine(ProgramDataDir, "dnscrypt-proxy.exe");

    /// <summary>The helper's persisted protection intent (<c>state\protection.json</c>),
    /// matching <c>ProtectedPaths.ProtectionStateFile</c> — the default
    /// <see cref="ProtectionStateReader"/> reads.</summary>
    public static string ProtectionStateFile => Path.Combine(ProgramDataDir, "state", "protection.json");

    /// <summary>The per-user, non-roaming UI state directory (favorites, stashed routes, prefs).</summary>
    public static string LocalAppDataDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DnsCryptControl");

    /// <summary>The per-user UI state file.</summary>
    public static string UiStateFile => Path.Combine(LocalAppDataDir, "ui-state.json");

    /// <summary>
    /// The Query Monitor's read-and-shred query log (Phase 5e, IC-QM3). It deliberately lives under
    /// per-user <c>%LOCALAPPDATA%</c> — NOT the Users-readable <c>%ProgramData%</c> tree — so it
    /// inherits that directory's owner-only ACL (SYSTEM + Admins + the interactive user): the log is
    /// the user's plaintext browsing history, and no other local user may read it. The proxy
    /// (LocalSystem) is pointed at this absolute path via <c>query_log.file</c>; the UI reads all
    /// current bytes then truncates the file to zero each poll so at-rest content is at most one poll
    /// interval of queries (IC-QM4).
    /// </summary>
    public static string QueryLogFile => Path.Combine(LocalAppDataDir, "query.log");

    /// <summary>
    /// The proxy's own operational log (<c>dnscrypt-proxy.log</c>) for the Phase 5e Logs &amp; Diagnostics
    /// opt-in capture (design 3.2). Unlike the query log this lives under Users-readable
    /// <c>%ProgramData%</c>: it is OPERATIONAL diagnostics (proxy lifecycle, resolver hostnames), NOT
    /// browsing history, so it is not shredded — capture is opt-in and disabling it stops the writes. The
    /// UI reads it read-only via <see cref="ILogTailReader"/>.
    /// </summary>
    public static string ProxyLogFile => Path.Combine(ProgramDataDir, "dnscrypt-proxy.log");

    /// <summary>
    /// The bundled resolver/relay snapshot directory (shipped alongside the app for an offline
    /// first run — F21). In Phase 5c this is normally empty; the reader renders that honestly.
    /// </summary>
    public static string BundledSnapshotDir => Path.Combine(AppContext.BaseDirectory, "resolver-snapshot");

    // On Windows GetInvalidFileNameChars() already includes '/' and '\' plus the control/reserved
    // set, so a bare-filename check against it also rejects any path separator (CWE-22 guard).
    private static readonly SearchValues<char> InvalidFileNameChars =
        SearchValues.Create(new string(Path.GetInvalidFileNameChars()));

    /// <summary>
    /// True when <paramref name="cacheFileName"/> is a safe bare filename (no path separator, no
    /// <c>..</c>, no invalid/reserved character) — used to confine a dnscrypt-proxy
    /// <c>cache_file</c> value to a single directory (defense in depth against a hostile config).
    /// </summary>
    public static bool IsSafeCacheFileName(string? cacheFileName) =>
        !string.IsNullOrEmpty(cacheFileName)
        && !cacheFileName.AsSpan().ContainsAny(InvalidFileNameChars)
        && !cacheFileName.Contains("..", StringComparison.Ordinal);

    /// <summary>
    /// Resolves a dnscrypt-proxy <c>cache_file</c> to its path under <paramref name="baseDir"/>
    /// (the proxy resolves a relative cache_file against its config directory), or null when the
    /// name is not a safe bare filename.
    /// </summary>
    public static string? ResolveCacheFile(string cacheFileName, string? baseDir = null) =>
        IsSafeCacheFileName(cacheFileName) ? Path.Combine(baseDir ?? ProgramDataDir, cacheFileName) : null;

    /// <summary>
    /// True when a <c>WriteRuleFile</c> request carrying <paramref name="content"/> for
    /// <paramref name="kind"/> would exceed the transport's per-request byte cap. Mirrors
    /// <c>ConfigFileService</c>'s size pre-check: it serializes the ACTUAL envelope+payload
    /// frame the client would send (JSON string-escaping inflation included) and compares
    /// the UTF-8 byte count against <see cref="IpcSerializer.MaxBytes"/> — the same
    /// <c>&gt; MaxBytes</c> boundary <c>IpcFraming.WriteFrameAsync</c> enforces, so a body
    /// sized to land exactly at the cap is accepted. The transport itself fails closed on
    /// oversize (C1), but that surfaces as a lost reply; this gives the friendly outcome
    /// without touching the pipe.
    /// </summary>
    public static bool RuleFileTooLarge(string kind, string content)
    {
        var payloadJson = IpcSerializer.SerializePayload(new WriteRuleFilePayload(kind, content));
        var requestJson = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.WriteRuleFile, payloadJson));
        return Encoding.UTF8.GetByteCount(requestJson) > IpcSerializer.MaxBytes;
    }
}
