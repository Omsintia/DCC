namespace DnsCryptControl.Core.QueryLog;

/// <summary>
/// The action dnscrypt-proxy 2.1.16 recorded for a single query, as observed live in the shipped
/// binary's TSV query log (VM spikes 501/502). The taxonomy is deliberately closed to the actions
/// seen in the wild plus <see cref="Forward"/> (a forwarding-rule match) and a catch-all
/// <see cref="Other"/> so an unseen future token is classified, never fatal.
/// </summary>
public enum QueryAction
{
    /// <summary>PASS — the query was resolved upstream (has a real <c>server</c>/<c>relay</c>).</summary>
    Pass,

    /// <summary>REJECT — blocked by a name or IP filter (locally answered; <c>server</c>/<c>relay</c> are <c>-</c>).</summary>
    Reject,

    /// <summary>CLOAK — cloaked to a local/override IP (locally answered).</summary>
    Cloak,

    /// <summary>SYNTH — a synthesized answer (e.g. <c>block_ipv6</c> for an AAAA query; locally answered).</summary>
    Synth,

    /// <summary>NXDOMAIN — the name did not exist upstream.</summary>
    NxDomain,

    /// <summary>FORWARD — matched a forwarding rule.</summary>
    Forward,

    /// <summary>Any action token not in the closed taxonomy above (never crash on an unseen action).</summary>
    Other,
}

/// <summary>
/// One parsed line from the dnscrypt-proxy 2.1.16 TSV query log. Tab-separated columns, in order:
/// <c>[YYYY-MM-DD HH:MM:SS]</c>, <c>client_ip</c>, <c>qname</c>, <c>qtype</c>, <c>ACTION</c>,
/// <c>durationMs</c> (like <c>183ms</c>), <c>server</c>, <c>relay</c>. Every string field is
/// preserved verbatim (the bracketed <see cref="Time"/> is kept as-is; use
/// <see cref="QueryLogParser.StripTimeBrackets"/> to display it without the brackets). The raw
/// duration token is normalised to an <see cref="int"/> millisecond count (a bad token → 0), and
/// the raw <c>ACTION</c> token is mapped to the closed <see cref="QueryAction"/> taxonomy.
/// </summary>
/// <param name="Time">The bracketed local timestamp as written by the proxy (e.g. <c>[2026-07-03 10:24:59]</c>), verbatim.</param>
/// <param name="Client">The client IP (verbatim).</param>
/// <param name="Name">The queried name / qname (verbatim; tabs are the column separator, so an intra-field tab cannot occur).</param>
/// <param name="Type">The DNS query type (e.g. <c>A</c>, <c>AAAA</c>, <c>PTR</c>), verbatim.</param>
/// <param name="Action">The mapped <see cref="QueryAction"/> (unknown token → <see cref="QueryAction.Other"/>).</param>
/// <param name="DurationMs">The parsed duration in milliseconds (a malformed token → <c>0</c>).</param>
/// <param name="Server">The upstream server, or <c>-</c> for a locally-answered action (verbatim).</param>
/// <param name="Relay">The anonymisation relay, or <c>-</c> when none (verbatim).</param>
public sealed record QueryLogLine(
    string Time,
    string Client,
    string Name,
    string Type,
    QueryAction Action,
    int DurationMs,
    string Server,
    string Relay);
