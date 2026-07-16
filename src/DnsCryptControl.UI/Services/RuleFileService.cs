using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// The Filtering tab's read/write path for the six rule-family <c>.txt</c> files (Phase 5d).
/// Reads mirror <see cref="ResolverListReader"/>: shared <c>FileShare.ReadWrite | FileShare.Delete</c>
/// access so a read never fails just because the helper is atomically replacing the file
/// mid-read (temp + Replace/Move), and fail-closed — any error becomes a typed
/// <see cref="RuleFileState"/>, never a throw. Writes orchestrate the 1 MiB pre-check (IC-14)
/// then the helper's unconditional <c>WriteRuleFile</c> verb (IC-13, no CAS), mapping the reply
/// into a typed <see cref="RuleFileWriteOutcome"/> with verbatim helper messages (IC-10).
/// </summary>
public sealed class RuleFileService : IRuleFileService
{
    private readonly IHelperClient _helper;
    private readonly string _programDataDir;

    /// <param name="helper">The pipe client every write is sent through.</param>
    /// <param name="programDataDir">The directory the rule <c>.txt</c> files live in
    /// (defaults to the real <see cref="UiPaths.ProgramDataDir"/>; tests inject a temp dir).</param>
    public RuleFileService(IHelperClient helper, string? programDataDir = null)
    {
        ArgumentNullException.ThrowIfNull(helper);
        _helper = helper;
        _programDataDir = programDataDir ?? UiPaths.ProgramDataDir;
    }

    /// <summary>The fixed leaf filename for a rule kind — MUST equal
    /// <c>Service.ProtectedPaths.RuleFilePath(kind)</c>'s leaf byte-for-byte (the single
    /// source of truth the helper writes to). The E1 gate pins these across the assembly line.
    /// Returns <see langword="null"/> for an out-of-range (invalid-cast) kind so the read/stat
    /// paths stay fail-closed (their "never throws" contract) rather than throwing on a bad cast.</summary>
    private static string? LeafName(RuleFileKind kind) => kind switch
    {
        RuleFileKind.BlockedNames => "blocked-names.txt",
        RuleFileKind.AllowedNames => "allowed-names.txt",
        RuleFileKind.BlockedIps => "blocked-ips.txt",
        RuleFileKind.AllowedIps => "allowed-ips.txt",
        RuleFileKind.Cloaking => "cloaking-rules.txt",
        RuleFileKind.Forwarding => "forwarding-rules.txt",
        RuleFileKind.CaptivePortals => "captive-portals.txt",
        _ => null,
    };

    /// <summary>The absolute path for a rule kind, or <see langword="null"/> for an out-of-range
    /// kind (see <see cref="LeafName"/>). Callers treat null as fail-closed.</summary>
    private string? PathFor(RuleFileKind kind)
    {
        var leaf = LeafName(kind);
        return leaf is null ? null : Path.Combine(_programDataDir, leaf);
    }

    public RuleFileSnapshot ReadRuleFile(RuleFileKind kind)
    {
        var path = PathFor(kind);
        if (path is null || !FileExists(path))
            return new RuleFileSnapshot(string.Empty, RuleFileState.Missing, null);

        var content = TryReadShared(path);
        if (content is null)
            return new RuleFileSnapshot(string.Empty, RuleFileState.Unreadable, TryGetMtime(kind));

        return new RuleFileSnapshot(content, RuleFileState.Present, TryGetMtime(kind));
    }

    public DateTime? TryGetMtime(RuleFileKind kind)
    {
        var path = PathFor(kind);
        if (path is null)
            return null;

        try { return File.Exists(path) ? File.GetLastWriteTimeUtc(path) : null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    public async Task<RuleFileWriteOutcome> WriteRuleFileAsync(RuleFileKind kind, string content, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(content);

        // The helper parses the ordinal member NAME into its closed enum (never a path
        // component); this is the string HelperClient.WriteRuleFileAsync forwards.
        var kindName = kind.ToString();

        // Step 1 — 1 MiB frame pre-check on the ACTUAL request bytes (IC-14). The transport
        // fails closed on oversize too, but that surfaces as a lost reply — this gives the
        // friendly outcome without touching the pipe. Mirrors ConfigFileService.cs:118-125.
        if (UiPaths.RuleFileTooLarge(kindName, content))
        {
            return new RuleFileWriteOutcome(
                RuleFileWriteOutcomeKind.TooLarge,
                "blocklist too large to send to the helper (limit 1 MiB per request) — split it, or reference it as an external file");
        }

        // Step 2 — the helper's unconditional (last-writer-wins, no CAS) validated write.
        // Refusal messages are surfaced verbatim (IC-10).
        var write = await _helper.WriteRuleFileAsync(kindName, content, ct).ConfigureAwait(false);
        if (write is null)
        {
            return new RuleFileWriteOutcome(
                RuleFileWriteOutcomeKind.HelperUnavailable,
                "the helper did not reply to the save — the rule file may not have been written; reload before retrying");
        }

        return write.Success
            ? new RuleFileWriteOutcome(RuleFileWriteOutcomeKind.Applied, write.Message)
            : new RuleFileWriteOutcome(RuleFileWriteOutcomeKind.Rejected, write.Message);
    }

    private static bool FileExists(string path)
    {
        try { return File.Exists(path); }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    /// <summary>A sane upper bound on a rule-file read, symmetric with the 1 MiB per-request WRITE
    /// cap (<see cref="IpcSerializer.MaxBytes"/>). We allow a generous multiple so a legitimate
    /// near-cap file still reads, while a pathologically large file (only plantable by something
    /// already past the ACL trust boundary) fails closed to Unreadable rather than buffering an
    /// unbounded string into memory — keeping the reader's "never throws" contract honest on
    /// hostile input.</summary>
    private const long MaxReadBytes = 8L * IpcSerializer.MaxBytes;

    // Share ReadWrite | Delete: the helper replaces the file (temp + Replace/Move) on write;
    // without Delete sharing a concurrent read would throw. Mirrors ResolverListReader:92-102.
    private static string? TryReadShared(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

            // Bounded read: reject a file larger than the cap before buffering it into a string, so a
            // huge file fails closed (Unreadable) instead of an unbounded allocation. Length can throw
            // for a non-seekable/odd stream — the surrounding catch keeps us fail-closed either way.
            if (stream.CanSeek && stream.Length > MaxReadBytes)
            {
                return null;
            }

            using var reader = new StreamReader(stream); // detects the BOM / decodes UTF-8
            return reader.ReadToEnd();
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }
}
