using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using DnsCryptControl.Core.Stamps;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// B3: <see cref="TcpConnectProber"/> + <see cref="KillSwitchClassification"/>. The non-manual
/// tests make ZERO real connections (they exercise the offline gate and the pure classifier);
/// the real-socket loopback probes are <c>ManualIntegration</c>.
/// </summary>
public class TcpConnectProberTests
{
    private sealed class FakeGate : IProbeGate
    {
        public bool IsProbingAllowed { get; init; }
    }

    private static ProbeTarget Target(string name, int port) => new(name, IPAddress.Loopback, port);

    [Fact]
    public async Task ProbeAsync_whenOffline_makesZeroConnections_andReportsGated()
    {
        var prober = new TcpConnectProber(new FakeGate { IsProbingAllowed = false });
        var reported = new List<ProbeResult>();
        var progress = new Progress<ProbeResult>(r => { lock (reported) reported.Add(r); });

        var results = await prober.ProbeAsync(new[] { Target("a", 443), Target("b", 443) }, progress, CancellationToken.None);

        Assert.Equal(2, results.Count);
        Assert.All(results, r => Assert.False(r.Reachable));
        Assert.All(results, r => Assert.Equal("offline", r.Error));
    }

    [Fact]
    public async Task ProbeAsync_emptyTargets_returnsEmpty()
    {
        var prober = new TcpConnectProber(new FakeGate { IsProbingAllowed = true });
        var results = await prober.ProbeAsync(Array.Empty<ProbeTarget>(), null, CancellationToken.None);
        Assert.Empty(results);
    }

    [Theory]
    [InlineData(StampProtocol.PlainDns, 53, true, true)]     // port 53 blocked
    [InlineData(StampProtocol.DnsCrypt, 53, true, true)]     // 53 blocked regardless of proto
    [InlineData(StampProtocol.DoT, 853, true, true)]         // DoT over TCP/853 blocked
    [InlineData(StampProtocol.DoQ, 853, true, false)]        // DoQ is UDP/853 — NOT blocked
    [InlineData(StampProtocol.DoH, 443, true, false)]        // 443 not blocked
    [InlineData(StampProtocol.DnsCrypt, 443, true, false)]
    [InlineData(StampProtocol.PlainDns, 53, false, false)]   // kill switch off — never blocked
    [InlineData(StampProtocol.DoT, 853, false, false)]
    public void KillSwitchClassification_matchesTheFirewallRules(StampProtocol protocol, int port, bool ksOn, bool expectedBlocked)
    {
        Assert.Equal(expectedBlocked, KillSwitchClassification.IsBlockedByKillSwitch(protocol, port, ksOn));
    }

    // ---- real-socket loopback probes (deterministic but open real sockets) ----

    [Fact]
    [Trait("Category", "ManualIntegration")]
    public async Task ProbeAsync_loopbackListener_isReachable()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start(); // backlog accepts the SYN; no AcceptTcpClient needed
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var prober = new TcpConnectProber(new FakeGate { IsProbingAllowed = true });

            var result = Assert.Single(await prober.ProbeAsync(new[] { Target("local", port) }, null, CancellationToken.None));
            Assert.True(result.Reachable);
            Assert.NotNull(result.LatencyMs);
        }
        finally { listener.Stop(); }
    }

    [Fact]
    [Trait("Category", "ManualIntegration")]
    public async Task ProbeAsync_closedPort_isUnreachable()
    {
        // bind then release a port to get one that is (almost certainly) closed
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        var prober = new TcpConnectProber(new FakeGate { IsProbingAllowed = true }, timeout: TimeSpan.FromMilliseconds(500), samples: 1);
        var result = Assert.Single(await prober.ProbeAsync(new[] { Target("closed", port) }, null, CancellationToken.None));
        Assert.False(result.Reachable);
        Assert.Equal("unreachable", result.Error);
    }
}
