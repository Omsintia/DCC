using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// A latency probe target. Carries a resolved <see cref="IPAddress"/> only — NEVER a hostname
/// (IC-15): a hostname would trigger a system DNS lookup, an egress outside the consented probe.
/// Rows whose stamp has no embedded IP are excluded upstream, never turned into a target.
/// </summary>
public sealed record ProbeTarget(string Name, IPAddress Address, int Port);

/// <summary>The outcome of probing one target (in-memory only — never persisted).</summary>
public sealed record ProbeResult(string Name, bool Reachable, int? LatencyMs, string? Error);

/// <summary>Measures round-trip reach to resolver endpoints (a user-consented, offline-gated act).</summary>
public interface ILatencyProber
{
    /// <summary>
    /// Probes each target, reporting results via <paramref name="progress"/> as they complete.
    /// Returns all results (one per target). When probing is gated off, every result is
    /// unreachable with an "offline" note. Honors <paramref name="ct"/> for cancellation.
    /// </summary>
    Task<IReadOnlyList<ProbeResult>> ProbeAsync(
        IReadOnlyList<ProbeTarget> targets, IProgress<ProbeResult>? progress, CancellationToken ct);
}

/// <summary>The probe gate seam: probing is only permitted when this allows it. An offline
/// switch was never implemented — production wires <see cref="AlwaysOnlineProbeGate"/>; the
/// seam exists so tests (and any future switch) can gate probing off.</summary>
public interface IProbeGate
{
    /// <summary>False when the gate forbids probing — the prober then makes zero connections.</summary>
    bool IsProbingAllowed { get; }
}

/// <summary>The production gate: probing is always allowed (there is no offline switch).</summary>
public sealed class AlwaysOnlineProbeGate : IProbeGate
{
    public bool IsProbingAllowed => true;
}
