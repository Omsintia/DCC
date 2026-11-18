using DnsCryptControl.Ipc.Commands;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Production <see cref="IDnsAttributionReader"/>: forwards to the shared
/// <see cref="IHelperClient"/> verb wrapper, which already owns the best-effort null-on-failure
/// contract — this class adds nothing but the seam boundary (see the interface's rationale).
/// </summary>
public sealed class DnsAttributionReader : IDnsAttributionReader
{
    private readonly IHelperClient _helper;

    public DnsAttributionReader(IHelperClient helper)
    {
        ArgumentNullException.ThrowIfNull(helper);
        _helper = helper;
    }

    /// <inheritdoc/>
    public Task<DnsAttributionBatch?> FetchAsync(long afterSeq, CancellationToken ct) =>
        _helper.GetDnsAttributionsAsync(afterSeq, ct);
}
