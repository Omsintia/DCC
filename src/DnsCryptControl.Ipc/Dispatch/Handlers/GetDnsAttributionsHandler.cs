using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>GetDnsAttributions (protocol v5, v1.3.0 per-app attribution): reads the helper's
/// bounded in-memory attribution ring through <see cref="IDnsAttributionSource"/> and maps the
/// Platform records onto the wire's <see cref="DnsAttributionEntry"/> verbatim. Read-only and
/// never mutates state, so unlike the mutating verbs a missing/malformed payload is NOT a
/// failure: it simply means "no cursor" and reads from the start (<c>AfterSeq = 0</c>) — there is
/// no wrong answer to fail closed against. The read itself is the demand signal that keeps the
/// helper's ETW capture alive (see the source's contract). The handler never throws for the
/// input it is given.</summary>
public sealed class GetDnsAttributionsHandler : ICommandHandler
{
    private readonly IDnsAttributionSource _source;

    public GetDnsAttributionsHandler(IDnsAttributionSource source)
    {
        ArgumentNullException.ThrowIfNull(source);
        _source = source;
    }

    public IpcCommandType Command => IpcCommandType.GetDnsAttributions;

    public string Handle(IpcRequest request)
    {
        // Absent OR malformed payload ⇒ AfterSeq 0 (read from the start). DeserializePayload
        // already fails closed to null on malformed input, so both cases funnel to the default.
        var afterSeq = 0L;
        if (request.PayloadJson is not null
            && IpcSerializer.DeserializePayload<DnsAttributionsPayload>(request.PayloadJson) is { } payload)
        {
            afterSeq = payload.AfterSeq;
        }

        var snapshot = _source.GetSince(afterSeq);
        var entries = new DnsAttributionEntry[snapshot.Records.Count];
        for (var i = 0; i < entries.Length; i++)
        {
            var record = snapshot.Records[i];
            entries[i] = new DnsAttributionEntry(
                record.Seq, record.UnixTimeMs, record.ProcessId, record.QueryName, record.ProcessName);
        }

        return IpcSerializer.SerializePayload(
            Result<DnsAttributionBatch>.Ok(new DnsAttributionBatch(snapshot.LastSeq, entries)));
    }
}
