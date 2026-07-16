using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using DnsCryptControl.Core.Rules;

namespace DnsCryptControl.Fuzzing.Oracles;

/// <summary>
/// DIFFERENTIAL oracle (Phase 6b): our <see cref="IpRule.Classify"/> parses blocked_ips/allowed_ips rules,
/// and it must agree with the Go stdlib (net.ParseIP / net.ParseCIDR) that dnscrypt-proxy 2.1.16 uses.
/// Corpus/ip/oracle-vectors.jsonl froze the reference verdict per token. The safety-critical direction
/// (mirroring the stamp differential) is <b>whenever WE accept a rule, the proxy must be able to parse it
/// too</b> - else the proxy silently skips our rule and the "block" never applies = fail-open. Per shape:
/// <list type="bullet">
///   <item>CIDR (contains '/'): if we accept it, net.ParseCIDR must accept it AND the canonical network
///     value must agree (a different network = we would block a different range).</item>
///   <item>Exact (no '/', no trailing '*'): if we accept it, net.ParseIP must accept it. We do NOT require
///     the canonical STRING to equal Go's - an IPv4-mapped IPv6 (::ffff:1.2.3.4) renders as the dotted-quad
///     in Go but keeps the ::ffff: form in .NET, the SAME numeric IP the proxy matches on (critbitgo is
///     numeric), so both are effective. Our rejecting a non-canonical form net.ParseIP accepts (e.g.
///     2620:00fe::fe) is documented hardening - counted, not failed.</item>
/// </list>
/// TextPrefix rules (trailing '*') are dnscrypt-proxy-specific with no net-stdlib reference and are excluded.
/// See the fuzzing design notes.
/// </summary>
public class IpDifferentialTests
{
    private sealed record IpVector(string In, bool IsIP, string IpCanon, bool IsCidr, string CidrCanon);

    private static List<IpVector> LoadVectors()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Corpus", "ip", "oracle-vectors.jsonl");
        var vectors = new List<IpVector>();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            using var doc = JsonDocument.Parse(line);
            var r = doc.RootElement;
            vectors.Add(new IpVector(
                r.GetProperty("in").GetString() ?? "",
                r.GetProperty("is_ip").GetBoolean(),
                r.GetProperty("ip_canon").GetString() ?? "",
                r.GetProperty("is_cidr").GetBoolean(),
                r.GetProperty("cidr_canon").GetString() ?? ""));
        }
        return vectors;
    }

    [Fact]
    [Trait("Category", "Fuzz")]
    public void IpRule_accept_agrees_with_net_parse()
    {
        var vectors = LoadVectors();
        Assert.NotEmpty(vectors);

        var divergences = new List<string>();
        int agreed = 0, hardeningRejections = 0;

        foreach (var v in vectors)
        {
            var accepted = IpRule.Classify(v.In, out var value, out var kind, out _, out _, out _);

            if (v.In.Contains('/', StringComparison.Ordinal))
            {
                var csCidr = accepted && kind == IpRuleKind.Cidr;
                if (csCidr)
                {
                    if (!v.IsCidr)
                        divergences.Add($"FAIL-OPEN CIDR '{v.In}': we accept, net.ParseCIDR rejects");
                    else if (!string.Equals(value, v.CidrCanon, StringComparison.Ordinal))
                        divergences.Add($"CIDR canon '{v.In}': C#='{value}' Go='{v.CidrCanon}'");
                    else agreed++;
                }
                else if (v.IsCidr) hardeningRejections++;
            }
            else if (!v.In.EndsWith('*'))
            {
                var csExact = accepted && kind == IpRuleKind.Exact;
                if (csExact)
                {
                    if (!v.IsIP) divergences.Add($"FAIL-OPEN exact '{v.In}': we accept, net.ParseIP rejects");
                    else agreed++;
                }
                else if (v.IsIP) hardeningRejections++;
            }
        }

        Assert.True(divergences.Count == 0,
            $"{divergences.Count} IP-parse divergence(s) vs Go net.ParseIP/ParseCIDR " +
            $"(agreed={agreed}, hardening-rejections={hardeningRejections}):{Environment.NewLine}" +
            string.Join(Environment.NewLine, divergences));
    }
}
