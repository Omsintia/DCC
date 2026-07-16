using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using DnsCryptControl.Core.Stamps;

namespace DnsCryptControl.Fuzzing.Oracles;

/// <summary>
/// DIFFERENTIAL oracle (Phase 6b): every input in Corpus/stamp/oracle-vectors.jsonl was parsed by the EXACT
/// dnscrypt-proxy 2.1.16 stamp parser (github.com/jedisct1/go-dnsstamps, pinned in tools/oracles/go.mod)
/// via oracle.exe, and its verdict frozen. We re-parse each with our hand-ported <see cref="ServerStampParser"/>
/// and assert the SAFETY-critical invariant:
/// <para>
/// <b>whenever WE accept a stamp, the reference also accepted it AND agrees on every field that decides what
/// the app dials/trusts</b> - protocol, probe address+port, DNSCrypt pubkey, provider name, TLS cert hashes,
/// DoH/ODoH path, and the 64-bit props bitfield. A C#-accept / reference-reject-or-disagree is a fail-OPEN
/// parser drift (we would dial/trust an endpoint the reference would not) and FAILS the test.
/// </para>
/// The reverse - reference accepts, we reject - is our DOCUMENTED hardening (stricter base64url, exactly-
/// 32-byte pubkey, UTF-8/control-char rejection, canonical-IP requirement); it is counted, not failed.
/// Runs offline from the frozen vectors (no Go toolchain in CI); refresh them by re-running oracle.exe over
/// Corpus/stamp/seeds.txt (see tools/oracles/README.md).
/// </summary>
public class StampDifferentialTests
{
    private sealed record Vector(
        string In, bool Ok, string Err, int Proto, string Addr, string Pk,
        IReadOnlyList<string> Hashes, string Provider, string Path, ulong Props);

    private static List<Vector> LoadVectors()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Corpus", "stamp", "oracle-vectors.jsonl");
        var vectors = new List<Vector>();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            using var doc = JsonDocument.Parse(line);
            var r = doc.RootElement;
            var hashes = r.TryGetProperty("hashes", out var h) && h.ValueKind == JsonValueKind.Array
                ? h.EnumerateArray().Select(e => e.GetString() ?? "").ToList()
                : new List<string>();
            vectors.Add(new Vector(
                In: r.GetProperty("in").GetString() ?? "",
                Ok: r.GetProperty("ok").GetBoolean(),
                Err: r.TryGetProperty("err", out var e) ? e.GetString() ?? "" : "",
                Proto: r.GetProperty("proto").GetInt32(),
                Addr: r.GetProperty("addr").GetString() ?? "",
                Pk: r.GetProperty("pk").GetString() ?? "",
                Hashes: hashes,
                Provider: r.GetProperty("provider").GetString() ?? "",
                Path: r.GetProperty("path").GetString() ?? "",
                Props: r.GetProperty("props").GetUInt64()));
        }
        return vectors;
    }

    [Fact]
    [Trait("Category", "Fuzz")]
    public void CSharp_accept_agrees_with_the_2_1_16_reference()
    {
        var vectors = LoadVectors();
        Assert.NotEmpty(vectors); // the frozen corpus must be present + copied next to the test assembly

        var divergences = new List<string>();
        int agreed = 0, hardeningRejections = 0;

        foreach (var v in vectors)
        {
            var csOk = ServerStampParser.TryParse(v.In, out var stamp, out _);
            if (!csOk)
            {
                if (v.Ok) hardeningRejections++; // we reject what the reference accepts = documented hardening
                continue;
            }

            if (!v.Ok)
            {
                divergences.Add($"FAIL-OPEN: we accepted, 2.1.16 rejected [{v.Err}]: {v.In}");
                continue;
            }

            var mismatch = CompareFields(stamp!, v);
            if (mismatch is not null) divergences.Add($"DISAGREE [{mismatch}]: {v.In}");
            else agreed++;
        }

        Assert.True(divergences.Count == 0,
            $"{divergences.Count} unexplained stamp divergence(s) vs dnscrypt-proxy 2.1.16 " +
            $"(agreed={agreed}, hardening-rejections={hardeningRejections}):{Environment.NewLine}" +
            string.Join(Environment.NewLine, divergences));
    }

    // Returns null on agreement, else a short reason. Compares only what determines dial/trust behaviour.
    // The optional bootstrap-IP list (both parsers parse it) is intentionally NOT compared: bootstrap IPs
    // seed name resolution, they are not endpoint-authenticating, so a divergence is a resolution-seed
    // difference, not a mis-dialed/mis-trusted endpoint (see stamp.go). The accept/reject decision - the
    // dangerous axis - is still cross-checked above.
    private static string? CompareFields(ServerStamp s, Vector v)
    {
        if ((int)s.Protocol != v.Proto) return $"proto {(int)s.Protocol}!={v.Proto}";
        if (s.Props != v.Props) return $"props {s.Props}!={v.Props}";

        // Probe address: only when we produced an IP literal (hostname-only stamps carry no probe target,
        // and the reference's ServerAddrStr for those is not a dial target). The reference appends the
        // per-type default port and brackets IPv6, so reconstruct the same shape.
        if (s.AddressIp is not null)
        {
            var expected = s.AddressIp.Contains(':', StringComparison.Ordinal)
                ? $"[{s.AddressIp}]:{s.Port}"
                : $"{s.AddressIp}:{s.Port}";
            if (!string.Equals(expected, v.Addr, StringComparison.Ordinal)) return $"addr {expected}!={v.Addr}";
        }

        var pk = s.PublicKey is null ? "" : Convert.ToHexString(s.PublicKey).ToLowerInvariant();
        if (!string.Equals(pk, v.Pk, StringComparison.Ordinal)) return "pk";
        // go-dnsstamps overloads its single ProviderName field: for DNSCrypt it is the provider name, for
        // DoH/DoT/DoQ/ODoH it is the hostname. We split those into ProviderName vs Hostname (a stamp carries
        // exactly one), so the reference's Provider maps to whichever of ours is set.
        var name = s.ProviderName ?? s.Hostname ?? "";
        if (!string.Equals(name, v.Provider, StringComparison.Ordinal)) return "name";
        if (!string.Equals(s.Path ?? "", v.Path, StringComparison.Ordinal)) return "path";

        var hashes = s.Hashes.Select(h => Convert.ToHexString(h).ToLowerInvariant()).ToList();
        if (!hashes.SequenceEqual(v.Hashes, StringComparer.Ordinal)) return "hashes";
        return null;
    }
}
