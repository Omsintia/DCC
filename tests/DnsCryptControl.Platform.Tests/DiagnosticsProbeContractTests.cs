using System;
using DnsCryptControl.Platform;
using DnsCryptControl.Platform.Diagnostics;
using Xunit;

namespace DnsCryptControl.Platform.Tests;

public class DiagnosticsProbeContractTests
{
    private sealed class StubProbe : IDiagnosticsProbe
    {
        public PlatformResult<DiagnosticsSnapshot> Run() =>
            PlatformResult<DiagnosticsSnapshot>.Ok(new DiagnosticsSnapshot(
                TakenUtc: DateTimeOffset.UnixEpoch,
                Overall: HealthState.Unknown,
                Listeners: new ListenerCheck(HealthState.Unknown, false, false, false, false, Array.Empty<string>()),
                ActiveResolve: new ActiveResolveCheck(HealthState.Unknown, "x.test", false, 0, null),
                ActiveResolveV6: new ActiveResolveCheck(HealthState.Unknown, "x.test", false, 0, null),
                AdapterDns: new AdapterDnsCheck(HealthState.Unknown, false, Array.Empty<AdapterDnsEntry>()),
                Hardening: new HardeningCheck(HealthState.Unknown, false, false, false, false, Array.Empty<string>())));

        public PlatformResult<ResolveVerification> VerifyUpstreamResolution() =>
            PlatformResult<ResolveVerification>.Ok(new ResolveVerification(false, 5000, "timeout"));
    }

    [Fact]
    public void Probe_isImplementable_andReturnsSnapshot()
    {
        IDiagnosticsProbe probe = new StubProbe();
        var r = probe.Run();
        Assert.True(r.Success);
        Assert.NotNull(r.Value);
        Assert.Equal(HealthState.Unknown, r.Value!.Overall);
    }

    [Fact]
    public void VerifyUpstreamResolution_isImplementable_andADeadRouteIsAnOkResultWithResolvedFalse()
    {
        // Contract: a dead route is a SUCCESSFUL probe run whose answer is "did not resolve"
        // (Ok + Resolved=false); a Fail result is reserved for the probe itself being unable to run.
        IDiagnosticsProbe probe = new StubProbe();
        var r = probe.VerifyUpstreamResolution();
        Assert.True(r.Success);
        Assert.NotNull(r.Value);
        Assert.False(r.Value!.Resolved);
        Assert.Equal("timeout", r.Value.Detail);
    }
}
