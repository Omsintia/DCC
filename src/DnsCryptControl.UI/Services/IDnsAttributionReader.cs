using DnsCryptControl.Ipc.Commands;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// The Query Monitor's read seam over the helper's per-app DNS attribution ring (v1.3.0). A thin
/// wrapper around <see cref="IHelperClient.GetDnsAttributionsAsync"/> so
/// <c>QueryMonitorViewModel</c> stays pipe-agnostic (IC-5) and tests fake ONE tiny surface
/// instead of the whole helper client.
/// </summary>
public interface IDnsAttributionReader
{
    /// <summary>Fetches the attribution entries newer than <paramref name="afterSeq"/> (the last
    /// batch's <c>LastSeq</c>; 0 first time). Best-effort by contract: a transport failure or an
    /// unsuccessful helper reply is <c>null</c> — the caller degrades the App column to "—"
    /// (unknown), never guesses, and never treats null as an error worth surfacing. Each poll is
    /// also the demand signal that keeps the helper's ETW capture alive, so callers must only
    /// poll while query logging is consented-on.</summary>
    Task<DnsAttributionBatch?> FetchAsync(long afterSeq, CancellationToken ct);
}
