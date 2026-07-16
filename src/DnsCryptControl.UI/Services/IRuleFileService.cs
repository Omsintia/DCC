using System;
using System.Threading;
using System.Threading.Tasks;
using DnsCryptControl.Platform;

namespace DnsCryptControl.UI.Services;

/// <summary>Where one rule-file's content came from / why it's absent. Fail-closed: any
/// I/O problem becomes <see cref="Unreadable"/> rather than throwing (IC-3).</summary>
public enum RuleFileState
{
    /// <summary>The <c>.txt</c> existed and was read (its <see cref="RuleFileSnapshot.Content"/>
    /// is authoritative — possibly the empty string for an empty file).</summary>
    Present,

    /// <summary>No file on disk — the family has never been written (nothing is blocked yet).</summary>
    Missing,

    /// <summary>The file exists but could not be read (locked exclusively, ACL, IO).</summary>
    Unreadable,
}

/// <summary>One rule family's <c>.txt</c> as read off disk: its raw content (IC-1 truth),
/// why it's absent when it is, and its last-write time (the IC-13 staleness anchor).</summary>
/// <param name="Content">The file's UTF-8 text, or the empty string when not
/// <see cref="RuleFileState.Present"/>.</param>
/// <param name="State">Where the content came from / why it's absent.</param>
/// <param name="LastWriteUtc">The file's last-write time (UTC), or null when Missing/Unreadable
/// — the load-time snapshot the caller re-compares before an unconditional write (IC-13).</param>
public sealed record RuleFileSnapshot(string Content, RuleFileState State, DateTime? LastWriteUtc);

/// <summary>How a rule-file write attempt ended. A simpler map than the config path's
/// <c>ConfigSaveOutcome</c> — there is no CAS/restart/version-skew here (IC-13): the
/// <c>.txt</c> write is unconditional last-writer-wins, so the only outcomes are the pre-check
/// (<see cref="TooLarge"/>), the helper refusal (<see cref="Rejected"/>, verbatim), a lost
/// helper (<see cref="HelperUnavailable"/>), and success (<see cref="Applied"/>).</summary>
public enum RuleFileWriteOutcomeKind
{
    /// <summary>The helper accepted and atomically wrote the file.</summary>
    Applied,

    /// <summary>The helper refused the write (line-validation: per-line cap or NUL) —
    /// <see cref="RuleFileWriteOutcome.Message"/> carries its reason verbatim (IC-10).
    /// Nothing written.</summary>
    Rejected,

    /// <summary>No usable reply from the helper (down, broken pipe, untrusted owner).
    /// The write may or may not have landed; the caller reloads before retrying.</summary>
    HelperUnavailable,

    /// <summary>The serialized request would exceed the transport's 1 MiB frame cap
    /// (IC-14). Nothing sent, nothing written.</summary>
    TooLarge,
}

/// <summary>Outcome of <see cref="IRuleFileService.WriteRuleFileAsync"/>: a discriminated
/// kind plus the human-actionable message the editor shows verbatim (IC-10).</summary>
public sealed record RuleFileWriteOutcome(RuleFileWriteOutcomeKind Kind, string? Message);

/// <summary>
/// The Filtering tab's single read/write path for the six rule-family <c>.txt</c> files
/// under <c>%ProgramData%\DnsCryptControl</c> (Phase 5d). The UI process READS them directly
/// (Users have Read via the ACL); every WRITE goes through the helper's policy-gated
/// <c>WriteRuleFile</c> verb — never through this service touching the disk. Reads fail
/// closed like <see cref="ResolverListReader"/>; writes never throw (typed outcome only).
/// </summary>
public interface IRuleFileService
{
    /// <summary>Reads the rule-file for <paramref name="kind"/> ONCE with shared
    /// (ReadWrite|Delete) access so a concurrent helper write never makes the read throw.
    /// Fails closed to a typed <see cref="RuleFileSnapshot"/>: missing → Missing, locked/ACL/IO
    /// → Unreadable, never a throw.</summary>
    RuleFileSnapshot ReadRuleFile(RuleFileKind kind);

    /// <summary>The rule-file's last-write time (UTC) as read immediately before a save, or
    /// null when it does not exist / cannot be stat'd (IC-13 staleness anchor). Never throws.</summary>
    DateTime? TryGetMtime(RuleFileKind kind);

    /// <summary>Sends <paramref name="content"/> for <paramref name="kind"/> to the helper's
    /// unconditional (last-writer-wins) <c>WriteRuleFile</c> verb. Runs the 1 MiB frame
    /// pre-check FIRST (IC-14 → <see cref="RuleFileWriteOutcomeKind.TooLarge"/> without touching
    /// the pipe), then maps the helper reply into a typed outcome with verbatim messages
    /// (IC-10). Never throws.</summary>
    Task<RuleFileWriteOutcome> WriteRuleFileAsync(RuleFileKind kind, string content, CancellationToken ct);
}
