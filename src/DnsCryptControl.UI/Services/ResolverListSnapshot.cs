using System;
using System.Collections.Generic;
using DnsCryptControl.Core.Sources;

namespace DnsCryptControl.UI.Services;

/// <summary>The read state of one resolver/relay cache file.</summary>
public enum ResolverListState
{
    /// <summary>The proxy's cache file was present and parsed.</summary>
    Fresh,

    /// <summary>No cache file and no bundled snapshot — the lists have not been downloaded yet.</summary>
    Missing,

    /// <summary>The cache file exists but could not be read (locked, ACL, IO).</summary>
    Unreadable,

    /// <summary>The cache file was read but is not a valid list (whole-file-invalid).</summary>
    ParseFailed,

    /// <summary>Served from the bundled snapshot because no cache file was present (may be outdated).</summary>
    Bundled,
}

/// <summary>One source's list as read off disk: its parsed entries, freshness, and state.</summary>
/// <param name="SourceName">The <c>[sources.&lt;name&gt;]</c> name (e.g. <c>public-resolvers</c>).</param>
/// <param name="Prefix">The source prefix (prepended to entry names).</param>
/// <param name="State">Where the data came from / why it's absent.</param>
/// <param name="LastCheckedUtc">The cache file's last-write time (the proxy bumps it on every refresh check), or null.</param>
/// <param name="Parsed">The parse result, or null when <see cref="ResolverListState.Missing"/>/<see cref="ResolverListState.Unreadable"/>.</param>
public sealed record ResolverListSnapshot(
    string SourceName,
    string Prefix,
    ResolverListState State,
    DateTimeOffset? LastCheckedUtc,
    ResolverListParseResult? Parsed)
{
    /// <summary>The parsed entries (empty when there is no readable data).</summary>
    public IReadOnlyList<ResolverListEntry> Entries => Parsed?.Entries ?? Array.Empty<ResolverListEntry>();
}
