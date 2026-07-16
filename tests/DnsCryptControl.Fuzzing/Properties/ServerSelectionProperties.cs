using System.Collections.Generic;
using System.Linq;
using CsCheck;
using DnsCryptControl.Core.Sources;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz properties for <see cref="ServerSelection.Evaluate"/> - the honesty engine that decides which list
/// entries the proxy would actually register, behind the Resolvers grey-outs, the effective-pool count, and
/// the ZERO-POOL SAVE BLOCK (a config with no live server is a total DNS outage the proxy refuses to start
/// on). It has no coverage today. Over the full 10-field config space against a fixed, diverse entry set
/// (DoH / ODoH-target / relay / DoT), the invariants: (1) TOTALITY - Evaluate never throws; (2) DETERMINISM;
/// (3) the critical guard <c>IsZeroPool == (EffectiveCount == 0)</c>; (4) <c>EffectiveCount</c> equals the
/// distinct-name-deduped (last-write-wins) count of included non-relay servers; (5) IsManual consistency;
/// (6) relays are never counted as pool servers. A Go differential of updateRegisteredServers is a documented
/// follow-up (it is deeply entangled with the proxy Config/state). See
/// the fuzzing design notes.
/// </summary>
public class ServerSelectionProperties
{
    // A fixed, diverse list parsed once: a DoH server, an ODoH target, an ODoH relay, and a DoT server
    // (unsupported as an upstream). Real, parseable stamps drawn from the frozen stamp corpus.
    // doh-cf (DoH, included/family/protocol paths), odoh-crypto-sx (ODoH target, odoh toggle), odohrelay-numa
    // (relay, exempt from server_names/protocol), dot-quad9 (DoT = UnsupportedProtocol), mixed-proto (two
    // differing-protocol stamps -> Nondeterministic), no-usable (only an invalid stamp -> NoUsableStamp). The
    // require_* filter branch is NOT reached (every real stamp has props=7); that branch has golden coverage
    // in Core ServerSelectionTests, as do exact EffectiveCount values - this property fuzzes the config space
    // for totality/determinism/the zero-pool guard, not as the primary props-filter or count oracle.
    private const string ListText =
        "## doh-cf\nCloudflare DoH\nsdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5\n" +
        "## odoh-crypto-sx\nODoH target\nsdns://BQcAAAAAAAAADm9kb2guY3J5cHRvLnN4Ci9kbnMtcXVlcnk\n" +
        "## odohrelay-numa\nODoH relay\nsdns://hQcAAAAAAAAAAAASb2RvaC1yZWxheS5udW1hLnJzBi9yZWxheQ\n" +
        "## dot-quad9\nQuad9 DoT (unsupported upstream)\nsdns://AwcAAAAAAAAABzkuOS45LjkADWRucy5xdWFkOS5uZXQ\n" +
        "## mixed-proto\nMixed DoH+DoT (nondeterministic)\nsdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5\nsdns://AwcAAAAAAAAABzkuOS45LjkADWRucy5xdWFkOS5uZXQ\n" +
        "## no-usable\nOnly an invalid stamp\nsdns://not-a-valid-stamp\n";

    private static readonly IReadOnlyList<ResolverListEntry> Entries = ResolverListParser.Parse(ListText, "").Entries;

    // Candidate names for server_names / disabled_server_names: the real entry names plus a ghost that is in
    // no entry (exercises the missing-pinned path).
    private static readonly string[] Candidates =
        Entries.Select(e => e.Name).Append("nonexistent-server").ToArray();

    private static readonly Gen<IReadOnlyList<string>> SubsetGen =
        Gen.Int[0, (1 << 5) - 1].Select(mask =>
        {
            var list = new List<string>();
            for (var i = 0; i < Candidates.Length && i < 5; i++)
                if ((mask & (1 << i)) != 0) list.Add(Candidates[i]);
            return (IReadOnlyList<string>)list;
        });

    private static readonly Gen<ServerSelectionConfig> ConfigGen =
        Gen.Select(SubsetGen, SubsetGen, Gen.Int[0, 255], (serverNames, disabled, flags) =>
            new ServerSelectionConfig(
                serverNames, disabled,
                Ipv4Servers: (flags & 1) != 0,
                Ipv6Servers: (flags & 2) != 0,
                DnsCryptServers: (flags & 4) != 0,
                DohServers: (flags & 8) != 0,
                ODoHServers: (flags & 16) != 0,
                RequireDnssec: (flags & 32) != 0,
                RequireNolog: (flags & 64) != 0,
                RequireNofilter: (flags & 128) != 0));

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Evaluate_is_total_deterministic_and_zero_pool_is_exactly_no_included_server()
    {
        Assert.NotEmpty(Entries); // guard: the fixed stamps must have parsed
        ConfigGen.Sample(cfg =>
        {
            // Totality: a throw fails the property.
            var r1 = ServerSelection.Evaluate(Entries, cfg);
            var r2 = ServerSelection.Evaluate(Entries, cfg);

            // Determinism.
            if (r1.Pool.IsZeroPool != r2.Pool.IsZeroPool || r1.Pool.EffectiveCount != r2.Pool.EffectiveCount)
                return false;

            // The critical guard: zero-pool iff no server is effectively live.
            if (r1.Pool.IsZeroPool != (r1.Pool.EffectiveCount == 0)) return false;

            // EffectiveCount == distinct included non-relay names, deduped last-write-wins (a later same-name
            // entry's stamp is authoritative) - the exact anti-false-safe the pool count exists for.
            var lastByName = new Dictionary<string, ServerEvaluation>(System.StringComparer.Ordinal);
            foreach (var ev in r1.Evaluations) lastByName[ev.Entry.Name] = ev;
            var included = lastByName.Values.Count(ev => ev.IsIncludedServer);
            if (r1.Pool.EffectiveCount != included) return false;

            // A relay is never a pool server.
            if (r1.Evaluations.Any(ev => ev.IsRelay && ev.IsIncludedServer)) return false;

            // Behavioral manual-mode consequence (not a restatement of IsManual's definition): in manual mode
            // every INCLUDED non-relay server's name must be one the user pinned in server_names - otherwise
            // an unpinned server slipped into the pool.
            if (cfg.ServerNames.Count > 0
                && r1.Evaluations.Any(ev => ev.IsIncludedServer && !cfg.ServerNames.Contains(ev.Entry.Name)))
                return false;

            return true;
        }, iter: Fuzz.Iter);
    }
}
