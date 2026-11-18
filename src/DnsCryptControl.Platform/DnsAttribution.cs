using System.Collections.Generic;

namespace DnsCryptControl.Platform;

/// <summary>
/// One OS-observed DNS lookup attributed to the process that made it (v1.3.0 per-app attribution).
/// Captured from the Microsoft-Windows-DNS-Client ETW provider's "query called" event, which fires
/// IN THE CALLING PROCESS's context — the only place the originating PID still exists once the
/// query reaches dnscrypt-proxy via the Windows DNS Client service (the proxy's own log always
/// says 127.0.0.1). <paramref name="ProcessName"/> is resolved AT CAPTURE (PIDs are reused, so a
/// later lookup could name the wrong process) and is null when the process had already exited.
/// Attribution is BEST-EFFORT observability data — never trust-bearing, never persisted.
/// </summary>
/// <param name="Seq">Monotonically increasing ring sequence number — the poll cursor.</param>
/// <param name="UnixTimeMs">Capture time (Unix milliseconds, UTC) used for time-window correlation.</param>
/// <param name="ProcessId">The originating process's PID from the ETW event header.</param>
/// <param name="QueryName">The looked-up name, verbatim from the event payload.</param>
/// <param name="ProcessName">The process's image name resolved at capture, or null if it had exited.</param>
public sealed record DnsAttributionRecord(
    long Seq, long UnixTimeMs, int ProcessId, string QueryName, string? ProcessName);

/// <summary>
/// Read seam over the helper's bounded IN-MEMORY per-app attribution ring (never on disk — this
/// app shreds browsing history, and the attribution stream IS browsing history). Defined as an
/// interface in Platform so the Ipc handler never references the Service assembly and is
/// unit-testable with a fake, mirroring <see cref="IConfigStore"/>.
/// </summary>
public interface IDnsAttributionSource
{
    /// <summary>Returns the records with <c>Seq &gt; afterSeq</c> (oldest → newest) plus the
    /// ring's current last sequence number, which the caller passes back next poll so each record
    /// crosses the pipe once. Calling this also TOUCHES the source — it is the demand signal that
    /// starts the ETW capture and keeps it alive; the capture stops itself once polls stop, so
    /// machine-wide DNS observation runs exactly while a consumer is actually reading.</summary>
    DnsAttributionSnapshot GetSince(long afterSeq);
}

/// <summary>
/// One <see cref="IDnsAttributionSource.GetSince"/> read: the ring's current last sequence number
/// (the caller's next-poll cursor — advanced even when every matching record was already evicted,
/// so a slow poller skips ahead instead of re-reading) and the matching records, oldest → newest.
/// </summary>
/// <param name="LastSeq">The highest sequence number the ring has ever assigned (0 when empty).</param>
/// <param name="Records">The records newer than the caller's cursor, oldest → newest.</param>
public sealed record DnsAttributionSnapshot(long LastSeq, IReadOnlyList<DnsAttributionRecord> Records);
