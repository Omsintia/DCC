using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// The single sanctioned socket-using file in the app (IC-11). Measures TCP-connect time to a
/// resolver's IP endpoint as a network-reach proxy for latency. Connects by <c>IPAddress</c> only
/// (never a hostname — no DNS egress, IC-15), bounds concurrency, times out per attempt, and takes
/// the best of a few samples. Gated by <see cref="IProbeGate"/> (offline mode makes zero
/// connections). Results are in-memory only; nothing is persisted.
/// </summary>
/// <remarks>
/// Raw <see cref="Socket"/>/<see cref="TcpClient"/> are banned solution-wide via BannedSymbols;
/// this file carries the sole <c>RS0030</c> exemption. Do not copy socket usage elsewhere.
/// </remarks>
public sealed class TcpConnectProber : ILatencyProber
{
    private readonly IProbeGate _gate;
    private readonly int _concurrency;
    private readonly TimeSpan _timeout;
    private readonly int _samples;

    public TcpConnectProber(IProbeGate gate, int concurrency = 8, TimeSpan? timeout = null, int samples = 2)
    {
        _gate = gate ?? throw new ArgumentNullException(nameof(gate));
        _concurrency = Math.Max(1, concurrency);
        _timeout = timeout ?? TimeSpan.FromMilliseconds(1500);
        _samples = Math.Max(1, samples);
    }

    public async Task<IReadOnlyList<ProbeResult>> ProbeAsync(
        IReadOnlyList<ProbeTarget> targets, IProgress<ProbeResult>? progress, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(targets);

        // Offline (or any gate-off): make zero connections; report every target as gated.
        if (!_gate.IsProbingAllowed)
        {
            var gated = targets.Select(t => new ProbeResult(t.Name, false, null, "offline")).ToList();
            foreach (var r in gated) progress?.Report(r);
            return gated;
        }

        var results = new ProbeResult[targets.Count];
        using var slots = new SemaphoreSlim(_concurrency);
        var tasks = new List<Task>(targets.Count);

        for (var i = 0; i < targets.Count; i++)
        {
            var index = i;
            var target = targets[i];
            tasks.Add(Task.Run(async () =>
            {
                await slots.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    var result = await ProbeOneAsync(target, ct).ConfigureAwait(false);
                    results[index] = result;
                    progress?.Report(result);
                }
                finally { slots.Release(); }
            }, ct));
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return results;
    }

    private async Task<ProbeResult> ProbeOneAsync(ProbeTarget target, CancellationToken ct)
    {
        int? best = null;
        for (var i = 0; i < _samples; i++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                // Sanctioned socket usage — IC-11 probe confinement. The disable spans every
                // TcpClient member access (the analyzer flags them, not just the constructor).
#pragma warning disable RS0030
                using var client = new TcpClient(target.Address.AddressFamily);
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(_timeout);

                var sw = Stopwatch.StartNew();
                await client.ConnectAsync(target.Address, target.Port, timeoutCts.Token).ConfigureAwait(false); // IPAddress overload — no DNS
                sw.Stop();
#pragma warning restore RS0030

                var ms = (int)Math.Min(sw.ElapsedMilliseconds, int.MaxValue);
                if (best is null || ms < best) best = ms;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw; // real cancellation — propagate
            }
            catch (OperationCanceledException)
            {
                // per-attempt timeout — try the next sample
            }
            catch (SocketException)
            {
                // refused / unreachable — try the next sample
            }
        }

        return best is { } latency
            ? new ProbeResult(target.Name, true, latency, null)
            : new ProbeResult(target.Name, false, null, "unreachable");
    }
}
