using System;
using System.Collections.Generic;
using System.Net;
using DnsCryptControl.Platform;
using DnsCryptControl.Platform.Diagnostics;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class WindowsDiagnosticsProbeTests
{
    private sealed class FakeInputs : IDnsProbeInputs
    {
        public ListenerObservation Listeners { get; init; } =
            new(true, true, false, false, new[] { "127.0.0.1:53" });
        public ActiveResolveObservation Resolve { get; init; } =
            new("selfcheck.test", ProxyAnswered: true, ElapsedMs: 5, Detail: "RCODE=0");
        public ActiveResolveObservation ResolveV6 { get; init; } =
            new("selfcheck.test", ProxyAnswered: true, ElapsedMs: 5, Detail: "RCODE=0");
        public IReadOnlyList<AdapterObservation> Adapters { get; init; } =
            new[] { new AdapterObservation("Ethernet", "Intel", "Up", new[] { "127.0.0.1" }, DnsAllLoopback: true) };
        public HardeningObservation Hardening { get; init; } =
            new(true, true, true, true, new[] { "ok" });

        public ListenerObservation ObserveListeners() => Listeners;
        public ActiveResolveObservation ObserveActiveResolve() => Resolve;
        public ActiveResolveObservation ObserveActiveResolveV6() => ResolveV6;
        public IReadOnlyList<AdapterObservation> ObserveAdapters() => Adapters;
        public HardeningObservation ObserveHardening() => Hardening;
    }

    [Fact]
    public void Run_composesInputs_throughEvaluator_toPass()
    {
        var snap = WindowsDiagnosticsProbe.RunWith(new FakeInputs(), DateTimeOffset.UnixEpoch);
        Assert.True(snap.Success);
        Assert.Equal(HealthState.Pass, snap.Value!.Overall);
        Assert.True(snap.Value.AdapterDns.AllLoopback);
        Assert.Equal(DateTimeOffset.UnixEpoch, snap.Value.TakenUtc);
    }

    [Fact]
    public void Run_failsOverall_whenAdapterLeaks()
    {
        var inputs = new FakeInputs
        {
            Adapters = new[] { new AdapterObservation("Wi-Fi", "Realtek", "Up", new[] { "8.8.8.8" }, DnsAllLoopback: false) },
        };
        var snap = WindowsDiagnosticsProbe.RunWith(inputs, DateTimeOffset.UnixEpoch);
        Assert.True(snap.Success);
        Assert.Equal(HealthState.Fail, snap.Value!.Overall);
        Assert.False(snap.Value.AdapterDns.AllLoopback);
    }

    [Fact]
    public void Run_failsOverall_whenProxyDidNotAnswer()
    {
        var inputs = new FakeInputs
        {
            Resolve = new ActiveResolveObservation("selfcheck.test", ProxyAnswered: false, ElapsedMs: 1500, Detail: "timeout"),
        };
        var snap = WindowsDiagnosticsProbe.RunWith(inputs, DateTimeOffset.UnixEpoch);
        Assert.Equal(HealthState.Fail, snap.Value!.Overall);
    }

    [Fact]
    public void Run_warnsOverall_whenHardeningIncomplete()
    {
        var inputs = new FakeInputs
        {
            Hardening = new HardeningObservation(SmhnrDisabled: false, ParallelAAaaaDisabled: true,
                KillSwitchRulesPresent: true, BrowserDohPoliciesPresent: true, new[] { "smhnr not set" }),
        };
        var snap = WindowsDiagnosticsProbe.RunWith(inputs, DateTimeOffset.UnixEpoch);
        Assert.Equal(HealthState.Warn, snap.Value!.Overall);
    }

    // Fault-barrier: RunWith must never propagate an observer exception to the caller.
    // Any exception thrown by one of the four ObserveXxx() methods must be caught and
    // returned as a failed PlatformResult (Success=false, ErrorKind=OperationFailed).
    [Fact]
    public void RunWith_returnsFail_whenObserverThrows()
    {
        var inputs = new ThrowingInputs();
        var result = WindowsDiagnosticsProbe.RunWith(inputs, DateTimeOffset.UnixEpoch);
        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.OperationFailed, result.Error);
    }

    private sealed class ThrowingInputs : IDnsProbeInputs
    {
        public ListenerObservation ObserveListeners() =>
            throw new UnauthorizedAccessException("registry access denied (test)");
        public ActiveResolveObservation ObserveActiveResolve() =>
            throw new UnauthorizedAccessException("should not reach here");
        public ActiveResolveObservation ObserveActiveResolveV6() =>
            throw new UnauthorizedAccessException("should not reach here");
        public IReadOnlyList<AdapterObservation> ObserveAdapters() =>
            throw new UnauthorizedAccessException("should not reach here");
        public HardeningObservation ObserveHardening() =>
            throw new UnauthorizedAccessException("should not reach here");
    }

    // IPAddress.IsLoopback edge cases (R[8]): use IsLoopback, never string equality.
    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.0.0.53", true)]            // entire 127.0.0.0/8 is loopback
    [InlineData("::1", true)]
    [InlineData("::ffff:127.0.0.1", true)]      // IPv4-mapped IPv6 loopback
    [InlineData("8.8.8.8", false)]
    [InlineData("192.168.1.1", false)]
    public void AllLoopback_usesIsLoopback_notStringEquality(string addr, bool expectedLoopback)
    {
        var ip = IPAddress.Parse(addr);
        Assert.Equal(expectedLoopback, WindowsDiagnosticsProbe.IsLoopbackDns(new[] { ip }));
    }

    [Fact]
    public void AllLoopback_isFalse_ifAnyServerNonLoopback()
    {
        var servers = new[] { IPAddress.Parse("127.0.0.1"), IPAddress.Parse("8.8.8.8") };
        Assert.False(WindowsDiagnosticsProbe.IsLoopbackDns(servers));
    }

    [Fact]
    public void AllLoopback_isFalse_whenNoServersConfigured()
    {
        // An Up adapter with zero DNS servers is not provably loopback-locked → not "all loopback".
        Assert.False(WindowsDiagnosticsProbe.IsLoopbackDns(Array.Empty<IPAddress>()));
    }

    // Evaluator path: when the observation flag ProxyAnswered=false is injected, the overall
    // health must be Fail regardless of the DNS wire bytes. This is distinct from IC-7's direct
    // LoopbackResolveProbe test below — it exercises the RunWith → DiagnosticsEvaluator path.
    [Fact]
    public void Overall_isFail_whenObservationFlags_proxyDidNotAnswer()
    {
        var obs = new ActiveResolveObservation("test.local", ProxyAnswered: false, ElapsedMs: 10, Detail: "RCODE=2");
        var inputs = new FakeInputs { Resolve = obs };
        var snap = WindowsDiagnosticsProbe.RunWith(inputs, DateTimeOffset.UnixEpoch);
        Assert.Equal(HealthState.Fail, snap.Value!.Overall);
        Assert.False(snap.Value.ActiveResolve.ProxyAnswered);
    }

    // IC-7: direct test of LoopbackResolveProbe — an RCODE=2 response with QR=1 and matching id
    // passes the header check (it IS well-formed) BUT IsValidProxyResponse must reject it
    // (SERVFAIL is not an accepted answer).
    [Fact]
    public void LoopbackResolveProbe_rcodeServfail_isNotProxyAnswered()
    {
        // A response that is structurally well-formed (QR=1, matching id, question echoed) but RCODE=2.
        ushort id = 0x0042;
        var question = SelfCheckQuestion(id);
        var buf = EchoedResponse(id, rcode: 0x02); // SERVFAIL

        // IsWellFormedResponse checks header shape + QR + id: this passes.
        Assert.True(LoopbackResolveProbe.IsWellFormedResponse(buf, id));

        // But IsValidProxyResponse must also require an accepted RCODE.
        Assert.False(LoopbackResolveProbe.IsValidProxyResponse(buf, id, question));
    }

    // Live-VM finding (Phase 5b): the self-check name is an UNDELEGATED TLD (.test), so a HEALTHY
    // encrypted pipeline answers NXDOMAIN(3) from upstream — the full loopback→proxy→upstream round
    // trip is proven, yet the original RCODE==0-only rule mapped it to ProxyAnswered=false and made
    // the green badge unreachable on a correct minimal config. IC-7 refinement: accept NOERROR(0)
    // and NXDOMAIN(3); SERVFAIL(2)/REFUSED(5)/garbage remain failures (proxy up, resolution broken).
    [Fact]
    public void LoopbackResolveProbe_rcodeNxdomain_isProxyAnswered()
    {
        ushort id = 0x0042;
        var question = SelfCheckQuestion(id);
        var buf = EchoedResponse(id, rcode: 0x03); // NXDOMAIN — the correct upstream answer for an undelegated name

        Assert.True(LoopbackResolveProbe.IsWellFormedResponse(buf, id));
        Assert.True(LoopbackResolveProbe.IsValidProxyResponse(buf, id, question));
    }

    [Fact]
    public void LoopbackResolveProbe_rcodeRefused_isNotProxyAnswered()
    {
        ushort id = 0x0042;
        var question = SelfCheckQuestion(id);
        var buf = EchoedResponse(id, rcode: 0x05); // REFUSED

        Assert.False(LoopbackResolveProbe.IsValidProxyResponse(buf, id, question));
    }

    // Exhaustive header-RCODE matrix: EXACTLY NOERROR(0) and NXDOMAIN(3) pass. The last two vectors
    // set the RA flag (byte 3 bit 7) to prove the & 0x0F mask ignores flag bits: RA+NXDOMAIN (0x83)
    // passes, RA+rcode15 (0x8F) does not. (Header RCODE is only 4 bits; extended RCODEs need an EDNS
    // OPT record and BuildAQuery sends ARCOUNT=0, so no compliant responder can reply with one.)
    [Theory]
    [InlineData(0x00, true)]  // NOERROR
    [InlineData(0x01, false)] // FORMERR
    [InlineData(0x02, false)] // SERVFAIL
    [InlineData(0x03, true)]  // NXDOMAIN (undelegated self-check name)
    [InlineData(0x04, false)] // NOTIMP
    [InlineData(0x05, false)] // REFUSED
    [InlineData(0x06, false)] // YXDOMAIN
    [InlineData(0x07, false)] // YXRRSET
    [InlineData(0x08, false)] // NXRRSET
    [InlineData(0x09, false)] // NOTAUTH
    [InlineData(0x0A, false)] // NOTZONE
    [InlineData(0x0B, false)]
    [InlineData(0x0C, false)]
    [InlineData(0x0D, false)]
    [InlineData(0x0E, false)]
    [InlineData(0x0F, false)]
    [InlineData(0x83, true)]  // RA flag + NXDOMAIN: flag bits must be masked off
    [InlineData(0x8F, false)] // RA flag + rcode 15: mask keeps the rcode, still rejected
    public void IsValidProxyResponse_accepts_exactly_noerror_and_nxdomain(int byte3, bool expected)
    {
        ushort id = 0x0042;
        var question = SelfCheckQuestion(id);
        var buf = EchoedResponse(id, byte3);

        Assert.Equal(expected, LoopbackResolveProbe.IsValidProxyResponse(buf, id, question));
    }

    // F4: the question-section echo check. A bare 12-byte header — the shape a blind spoofer or a
    // half-alive listener most cheaply produces — is structurally well-formed with a good RCODE, yet it
    // echoes NO question, so it must NOT count as a proxy answer.
    [Fact]
    public void IsValidProxyResponse_rejects_bare_header_without_question_echo()
    {
        ushort id = 0x0042;
        var question = SelfCheckQuestion(id);
        var buf = new byte[12];
        buf[0] = (byte)(id >> 8); buf[1] = (byte)(id & 0xFF);
        buf[2] = 0x80; // QR=1
        buf[3] = 0x00; // NOERROR
        // QDCOUNT stays 0, no question bytes.

        Assert.True(LoopbackResolveProbe.IsWellFormedResponse(buf, id)); // header shape alone passes
        Assert.False(LoopbackResolveProbe.IsValidProxyResponse(buf, id, question)); // but no echo -> rejected
    }

    [Fact]
    public void IsValidProxyResponse_rejects_a_wrong_name_echo()
    {
        ushort id = 0x0042;
        var question = SelfCheckQuestion(id);
        // A NOERROR response that echoes a DIFFERENT question (answer for another name).
        var buf = EchoedResponse(id, rcode: 0x00, question: DnsQueryBytes.BuildAQuery("evil.example", id)[12..]);

        Assert.False(LoopbackResolveProbe.IsValidProxyResponse(buf, id, question));
    }

    [Fact]
    public void IsValidProxyResponse_rejects_qdcount_not_one()
    {
        ushort id = 0x0042;
        var question = SelfCheckQuestion(id);
        var buf = EchoedResponse(id, rcode: 0x00);
        buf[5] = 0x02; // QDCOUNT = 2, but only one question is echoed -> reject

        Assert.False(LoopbackResolveProbe.IsValidProxyResponse(buf, id, question));
    }

    [Fact]
    public void IsValidProxyResponse_rejects_a_truncated_question_echo()
    {
        ushort id = 0x0042;
        var question = SelfCheckQuestion(id);
        var full = EchoedResponse(id, rcode: 0x00);
        var truncated = full[..(full.Length - 1)]; // drop the last question byte

        Assert.False(LoopbackResolveProbe.IsValidProxyResponse(truncated, id, question));
    }

    [Fact]
    public void IsValidProxyResponse_accepts_question_echo_with_trailing_answer()
    {
        ushort id = 0x0042;
        var question = SelfCheckQuestion(id);
        // A real NOERROR reply echoes the question then appends an answer section; the trailing bytes are fine.
        var buf = EchoedResponse(id, rcode: 0x00, answer: new byte[] { 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01 });

        Assert.True(LoopbackResolveProbe.IsValidProxyResponse(buf, id, question));
    }

    [Fact]
    public void IsValidProxyResponse_rejects_empty_expected_question()
    {
        ushort id = 0x0042;
        var buf = EchoedResponse(id, rcode: 0x00);

        // Fail closed if the caller supplies no question to match against.
        Assert.False(LoopbackResolveProbe.IsValidProxyResponse(buf, id, ReadOnlySpan<byte>.Empty));
    }

    // The self-check name the badge poll uses; an undelegated TLD (.test) so a healthy answer is NXDOMAIN.
    private const string SelfCheckName = "dnscrypt-resolver-selfcheck.test";

    // The exact question section (QNAME+QTYPE+QCLASS) the probe would send for the self-check name.
    private static byte[] SelfCheckQuestion(ushort id) => DnsQueryBytes.BuildAQuery(SelfCheckName, id)[12..];

    // Builds a response frame: 12-byte header (matching id, QR=1, QDCOUNT=1, the given RCODE) + an echoed
    // question section + an optional trailing answer, mirroring what a real dnscrypt-proxy reply looks like.
    private static byte[] EchoedResponse(ushort id, int rcode, byte[]? question = null, byte[]? answer = null)
    {
        question ??= SelfCheckQuestion(id);
        var buf = new byte[12 + question.Length + (answer?.Length ?? 0)];
        buf[0] = (byte)(id >> 8); buf[1] = (byte)(id & 0xFF);
        buf[2] = 0x80;                 // QR=1
        buf[3] = (byte)rcode;
        buf[4] = 0x00; buf[5] = 0x01;  // QDCOUNT=1
        Array.Copy(question, 0, buf, 12, question.Length);
        if (answer is not null) Array.Copy(answer, 0, buf, 12 + question.Length, answer.Length);
        return buf;
    }

    // ================= VerifyUpstreamResolution (FIX #1: the post-apply real-name route check) ==========

    /// <summary>Recording fake probe function: scripted per-call observations + a log of every
    /// (server, port, name, timeout) it was invoked with.</summary>
    private sealed class RecordingProbe
    {
        public List<(IPAddress Server, int Port, string Name, TimeSpan Timeout)> Calls { get; } = new();
        public Queue<ActiveResolveObservation> Script { get; } = new();

        public ActiveResolveObservation Invoke(IPAddress server, int port, string name, TimeSpan timeout)
        {
            Calls.Add((server, port, name, timeout));
            return Script.Dequeue();
        }

        public static ActiveResolveObservation Answered(int elapsedMs = 120, string detail = "RCODE=3, ancount=0") =>
            new("q.example.com", ProxyAnswered: true, ElapsedMs: elapsedMs, Detail: detail);

        public static ActiveResolveObservation TimedOut(int elapsedMs = 2500) =>
            new("q.example.com", ProxyAnswered: false, ElapsedMs: elapsedMs, Detail: "timeout");

        public static ActiveResolveObservation Servfail(int elapsedMs = 50) =>
            new("q.example.com", ProxyAnswered: false, ElapsedMs: elapsedMs, Detail: "RCODE=2 - rejected (bad RCODE, id/QR mismatch, or question not echoed) (30 bytes)");
    }

    [Fact]
    public void VerifyWith_firstAnswer_succeeds_withOneAttempt()
    {
        var probe = new RecordingProbe();
        probe.Script.Enqueue(RecordingProbe.Answered(elapsedMs: 87));

        var r = WindowsDiagnosticsProbe.VerifyWith(probe.Invoke, "abc12345.example.com");

        Assert.True(r.Success);
        Assert.True(r.Value!.Resolved);
        Assert.Equal(87, r.Value.ElapsedMs);
        Assert.Single(probe.Calls);
    }

    [Fact]
    public void VerifyWith_retries_thenSucceeds_onThirdAttempt()
    {
        var probe = new RecordingProbe();
        probe.Script.Enqueue(RecordingProbe.Servfail());
        probe.Script.Enqueue(RecordingProbe.Servfail());
        probe.Script.Enqueue(RecordingProbe.Answered());

        var r = WindowsDiagnosticsProbe.VerifyWith(probe.Invoke, "abc12345.example.com");

        Assert.True(r.Value!.Resolved);
        Assert.Equal(3, probe.Calls.Count);
    }

    [Fact]
    public void VerifyWith_deadRoute_twoFullTimeouts_exhaustTheBudget_resolvedFalse()
    {
        // The dead-anonymized-route shape: every attempt times out at the full 2500 ms. Two of
        // those hit the 5 s cumulative cap, so the third attempt must be skipped (total ≤ ~5 s —
        // the probe runs inside the helper's serial pipe dispatch and must never hold it long).
        var probe = new RecordingProbe();
        probe.Script.Enqueue(RecordingProbe.TimedOut());
        probe.Script.Enqueue(RecordingProbe.TimedOut());
        probe.Script.Enqueue(RecordingProbe.TimedOut()); // must NOT be consumed

        var r = WindowsDiagnosticsProbe.VerifyWith(probe.Invoke, "abc12345.example.com");

        Assert.True(r.Success);           // the probe RAN fine — the answer is "did not resolve"
        Assert.False(r.Value!.Resolved);
        Assert.Equal(5000, r.Value.ElapsedMs);
        Assert.Equal("timeout", r.Value.Detail);
        Assert.Equal(2, probe.Calls.Count);
    }

    [Fact]
    public void VerifyWith_fastFailures_getAllThreeAttempts_resolvedFalse()
    {
        var probe = new RecordingProbe();
        probe.Script.Enqueue(RecordingProbe.Servfail());
        probe.Script.Enqueue(RecordingProbe.Servfail());
        probe.Script.Enqueue(RecordingProbe.Servfail());

        var r = WindowsDiagnosticsProbe.VerifyWith(probe.Invoke, "abc12345.example.com");

        Assert.False(r.Value!.Resolved);
        Assert.Equal(3, probe.Calls.Count);
        Assert.Contains("RCODE=2", r.Value.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void VerifyWith_alwaysTargetsLoopback53_theKillSwitchSafePin()
    {
        // PIN: every attempt must go to 127.0.0.1:53 — the loopback proxy exercises the configured
        // route, and the kill switch never blocks loopback. A refactor that pointed this probe at a
        // remote resolver would be blocked by the armed kill switch and false-warn on every apply.
        var probe = new RecordingProbe();
        probe.Script.Enqueue(RecordingProbe.Servfail());
        probe.Script.Enqueue(RecordingProbe.Servfail());
        probe.Script.Enqueue(RecordingProbe.Servfail());

        WindowsDiagnosticsProbe.VerifyWith(probe.Invoke, "abc12345.example.com");

        Assert.All(probe.Calls, c =>
        {
            Assert.Equal(IPAddress.Loopback, c.Server);
            Assert.Equal(53, c.Port);
            Assert.Equal("abc12345.example.com", c.Name);
        });
    }

    [Fact]
    public void VerifyWith_probeThrow_mapsToFailResult_neverPropagates()
    {
        static ActiveResolveObservation Throwing(IPAddress s, int p, string n, TimeSpan t) =>
            throw new InvalidOperationException("socket layer exploded (test)");

        var r = WindowsDiagnosticsProbe.VerifyWith(Throwing, "abc12345.example.com");

        Assert.False(r.Success);
        Assert.Equal(PlatformErrorKind.OperationFailed, r.Error);
        Assert.Contains("socket layer exploded", r.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void VerifyName_isARandomHexLabel_underTheDelegatedExampleZone()
    {
        // The name must live under a REAL delegated zone (so block_undelegated cannot answer it
        // locally) with a fresh random label (so no cache can satisfy it without an upstream trip).
        var a = WindowsDiagnosticsProbe.VerifyName();
        var b = WindowsDiagnosticsProbe.VerifyName();

        Assert.Matches("^[0-9a-f]{8}\\.example\\.com$", a);
        Assert.Matches("^[0-9a-f]{8}\\.example\\.com$", b);
        Assert.NotEqual(a, b);
    }

    [Trait("Category", "ManualIntegration")]
    [Fact]
    public void Run_live_onRealBox_producesSnapshot()
    {
        if (!OperatingSystem.IsWindows()) return;
        // Requires a real dnscrypt-proxy listening on 127.0.0.1:53. Validates the live sockets/adapters/
        // registry path end-to-end. Not asserted in CI; the manual run inspects the snapshot.
        var probe = new WindowsDiagnosticsProbe(
            new StubKillSwitch(), new StubBrowserDoh());
        var snap = probe.Run();
        Assert.True(snap.Success);
        Assert.NotNull(snap.Value);
    }

    private sealed class StubKillSwitch : IFirewallKillSwitch
    {
        public PlatformResult SetKillSwitch(bool enable) => PlatformResult.Ok();
        public bool IsKillSwitchActive() => false;
    }

    private sealed class StubBrowserDoh : IBrowserDohPolicy
    {
        public PlatformResult SetBrowserDohPolicy(bool enable) => PlatformResult.Ok();
        public bool IsBrowserDohPolicyApplied() => false;
    }
}
