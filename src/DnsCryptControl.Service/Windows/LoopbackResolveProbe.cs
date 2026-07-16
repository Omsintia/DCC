using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace DnsCryptControl.Service.Windows;

/// <summary>Sends a hand-built A-query straight to the loopback proxy over a Connect-pinned UdpClient and
/// reports whether a well-formed answer came back. Pinning with Connect guarantees the reply came
/// from the owner of 127.0.0.1:53 (not a stray datagram) and bypasses the Windows resolver entirely.
/// IC-7 (refined by the Phase 5b live-VM finding, commit 1183c2e): ProxyAnswered is true ONLY when
/// the response is well-formed AND RCODE is NOERROR(0) or NXDOMAIN(3). The self-check name is an
/// UNDELEGATED TLD (.test): dnscrypt-proxy answers it NXDOMAIN — LOCALLY when block_undelegated=true
/// (the shipped default; the query never leaves the box, so the ~1.5s badge poll emits ZERO upstream
/// beacon) or from upstream otherwise. ProxyAnswered therefore attests PROXY-PROCESS LIVENESS on the
/// loopback listener; upstream reachability is intentionally NOT proven (negative caching would
/// satisfy it locally anyway). The badge's no-LEAK guarantee rests on AdapterDns.AllLoopback —
/// queries that die inside the proxy never egress. Requiring NOERROR made the green badge
/// unreachable on a correct minimal config. SERVFAIL(2)/REFUSED(5)/garbage remain failures
/// (proxy up, resolution path broken). Read-only; every socket/CTS is disposed via <c>using</c>
/// so a dead proxy fails fast.
/// <para>
/// TRUST BOUNDARY (finding F4, Phase 6): the reply is Connect-pinned to 127.0.0.1:53, so it can only
/// come from whatever process owns that port - and ANY process that owns it can forge a well-formed
/// answer. This probe therefore attests "something on the loopback DNS port speaks DNS and echoed our
/// exact question", NOT "that something is specifically our dnscrypt-proxy". The question-section echo
/// check added here (QDCOUNT=1 + a byte-exact copy of the QNAME/QTYPE/QCLASS we sent) raises the bar so
/// a blind/off-path spoofer that cannot observe our per-probe random id AND question can no longer pass
/// a bare 12-byte header; an on-box process squatting the port still can. That residual is inherent to a
/// liveness badge and is acceptable BECAUSE leak-safety does not rest on this badge - it rests on
/// AdapterDns.AllLoopback (every adapter's DNS is loopback) plus the opt-in kill switch (port-53 egress
/// blocked). This method is a health signal, never a security control.
/// </para></summary>
internal static class LoopbackResolveProbe
{
    /// <summary>Probe <paramref name="server"/>:<paramref name="port"/> for <paramref name="queriedName"/>,
    /// timing out after <paramref name="timeout"/>. ProxyAnswered is true iff bytes returned, the response
    /// is at least a 12-byte header, the QR bit is set, the transaction id matches, AND RCODE is
    /// NOERROR(0) or NXDOMAIN(3).</summary>
    internal static ActiveResolveObservation Probe(IPAddress server, int port, string queriedName, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentException.ThrowIfNullOrEmpty(queriedName);

        var id = (ushort)Random.Shared.Next(1, ushort.MaxValue);
        var query = DnsQueryBytes.BuildAQuery(queriedName, id);
        var sw = Stopwatch.StartNew();

        try
        {
            // IC-11 (Phase 5c): UdpClient is banned solution-wide as a probe/egress choke-point
            // bypass. This is the sole sanctioned Service use — a Connect-pinned loopback DNS probe
            // to the local proxy (127.0.0.1), no external egress. Comment-only exemption (IC-2).
            // The disable spans every UdpClient member access (the analyzer flags them too).
#pragma warning disable RS0030
            using var client = new UdpClient(server.AddressFamily);
            client.Connect(server, port);
            using var cts = new CancellationTokenSource(timeout);

            client.SendAsync(query, cts.Token).AsTask().GetAwaiter().GetResult();
            var received = client.ReceiveAsync(cts.Token).AsTask().GetAwaiter().GetResult();
#pragma warning restore RS0030
            sw.Stop();

            var buf = received.Buffer;
            // The question section we sent is query[12..] (BuildAQuery emits exactly header + one question);
            // a valid response echoes it byte-for-byte at offset 12.
            var valid = IsValidProxyResponse(buf, id, query.AsSpan(12));
            string detail;
            if (buf.Length >= 12)
            {
                var rcode = buf[3] & 0x0F;
                var ancount = (buf[6] << 8) | buf[7];
                detail = valid
                    ? $"RCODE={rcode}, ancount={ancount}"
                    : $"RCODE={rcode} - rejected (bad RCODE, id/QR mismatch, or question not echoed) ({buf.Length} bytes)";
            }
            else
            {
                detail = $"malformed response ({buf.Length} bytes)";
            }

            return new ActiveResolveObservation(queriedName, ProxyAnswered: valid,
                ElapsedMs: (int)sw.ElapsedMilliseconds, Detail: detail);
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            return new ActiveResolveObservation(queriedName, ProxyAnswered: false,
                ElapsedMs: (int)sw.ElapsedMilliseconds, Detail: "timeout");
        }
        catch (SocketException ex)
        {
            sw.Stop();
            return new ActiveResolveObservation(queriedName, ProxyAnswered: false,
                ElapsedMs: (int)sw.ElapsedMilliseconds, Detail: $"socket error {ex.SocketErrorCode}");
        }
    }

    /// <summary>A response is structurally well-formed iff it has the 12-byte header, QR=1 (it is a
    /// response), and its transaction id equals the query id. Does NOT check RCODE.
    /// Used in unit tests to verify the structural check independently.</summary>
    internal static bool IsWellFormedResponse(byte[] buf, ushort expectedId)
    {
        if (buf is null || buf.Length < 12) return false;
        var responseId = (ushort)((buf[0] << 8) | buf[1]);
        if (responseId != expectedId) return false;
        var qr = (buf[2] & 0x80) != 0; // high bit of flags byte 2
        return qr;
    }

    /// <summary>IC-7 (refined) + F4: A response is a valid proxy answer iff it is structurally well-formed
    /// (QR=1, matching id), RCODE is NOERROR(0) or NXDOMAIN(3), AND it echoes the exact question we sent
    /// (QDCOUNT=1 with the QNAME/QTYPE/QCLASS byte-for-byte at offset 12). NXDOMAIN is accepted because the
    /// self-check name is an undelegated TLD: dnscrypt-proxy's block_undelegated plugin (shipped
    /// default TRUE) synthesizes the NX locally, and an upstream answers NX when that plugin is off —
    /// either way the proxy processed and answered the query. Same acceptance class as the
    /// pre-existing synthetic-NOERROR case (blocked_query_response='hinfo'). SERVFAIL(2), REFUSED(5),
    /// etc. are NOT a passing proxy answer — the proxy responded but the resolution path is broken.
    /// The question echo (finding F4) rejects a bare 12-byte header, a wrong-name answer, or a truncated
    /// echo: a blind spoofer must now reproduce BOTH the per-probe random id AND the question. The
    /// question section is never compression-compressed, so a byte-exact compare at offset 12 is correct.
    /// Fails closed on any length/count shortfall. See the trust-boundary note on the type.</summary>
    internal static bool IsValidProxyResponse(byte[] buf, ushort expectedId, ReadOnlySpan<byte> expectedQuestion)
    {
        if (!IsWellFormedResponse(buf, expectedId)) return false;
        var rcode = buf[3] & 0x0F; // low nibble of byte 3
        if (rcode is not (0 or 3)) return false; // NOERROR | NXDOMAIN only

        // A well-formed answer to our single-question query has QDCOUNT=1 and echoes the question verbatim.
        if (expectedQuestion.Length == 0) return false;           // caller must supply the question it sent
        var qdcount = (buf[4] << 8) | buf[5];
        if (qdcount != 1) return false;
        if (buf.Length < 12 + expectedQuestion.Length) return false;
        return buf.AsSpan(12, expectedQuestion.Length).SequenceEqual(expectedQuestion);
    }
}
