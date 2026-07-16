namespace DnsCryptControl.Platform;

/// <summary>
/// Reads/writes dnscrypt-proxy's config and rule files in the protected
/// %ProgramData%\DnsCryptControl\ directory. Every write is atomic (temp file + replace),
/// preceded by a backup, rolled back on failure, and confined with SafePath. Defined as
/// an interface so the WriteConfig/WriteRuleFile handlers are unit-testable with a fake.
/// </summary>
public interface IConfigStore
{
    /// <summary>Reads the current dnscrypt-proxy.toml text, or NotFound if absent.</summary>
    PlatformResult<string> ReadConfig();

    /// <summary>Backs up the previous config, then atomically writes the new TOML text.
    /// Rolls back to the backup on any failure. The caller is responsible for validating
    /// the TOML BEFORE calling this; the store does no schema validation.</summary>
    PlatformResult WriteConfig(string tomlText);

    /// <summary>BE-6 optimistic concurrency (IC-9): compares the SHA-256 of the CURRENT
    /// on-disk config file BYTES against <paramref name="expectedBaseSha256"/> (lowercase
    /// hex, caller's value lowercase-normalized, ordinal compare — the candidate text is
    /// never hashed). Match → the same backup + atomic write + rollback as
    /// <see cref="WriteConfig"/>. Mismatch or absent file →
    /// <see cref="PlatformErrorKind.Conflict"/> with a human-actionable message (IC-10).
    /// A sha that is not 64 hex chars → <see cref="PlatformErrorKind.InvalidArgument"/>;
    /// the file is untouched on every reject path.</summary>
    PlatformResult WriteConfigIfBaseMatches(string tomlText, string expectedBaseSha256);

    /// <summary>Backs up the previous rule file (if any), then atomically writes the new
    /// content to the fixed filename for <paramref name="kind"/>. Rolls back on failure.</summary>
    PlatformResult WriteRuleFile(RuleFileKind kind, string content);

    /// <summary>Writes the store's OWN bundled, minisign-signed ODoH source-list cache files
    /// (odoh-servers.md + .minisig, odoh-relays.md + .minisig) into the protected base dir,
    /// BYTE-EXACT (the signature verifies only against the exact bytes), each via the same
    /// atomic temp-write + backup + rollback as the other writes. The content is the store's
    /// own trusted, embedded copy — never caller-supplied — so an unprivileged caller cannot
    /// inject a resolver list; integrity ultimately rests on the proxy verifying the .md
    /// against the pinned minisign key. Placing a valid, fresh cache BEFORE the sources are
    /// referenced lets the proxy load ODoH from cache instead of the fatal boot-time download.
    /// Fail-closed: a missing embedded asset or any write failure returns a failed result and
    /// leaves the base dir unchanged for the remaining files.</summary>
    PlatformResult PlaceOdohSourceCaches();

    /// <summary>Places the store's OWN bundled, minisign-signed DEFAULT source-list cache
    /// (public-resolvers.md + .minisig) into the protected base dir UNLESS the existing pair
    /// VERIFIES against the pinned resolver-list key — byte-exact, via the same atomic write +
    /// backup + rollback as <see cref="PlaceOdohSourceCaches"/>. A fresher cache the proxy
    /// downloaded itself always passes verification (the proxy pins the same key), so it is never
    /// overwritten; a missing, half-missing, truncated, torn, or mismatched pair is restored whole.
    /// Seeding closes the fresh-install brick: the shipped config's only source has a URL the
    /// off-53 bootstrap can never resolve (bootstrap_resolvers is plain-DNS-only, and the shipped
    /// entries are :443), and dnscrypt-proxy treats a source with no loadable cache as FATAL — so
    /// starting the proxy without a valid cache leaves the machine on loopback DNS with a dead
    /// proxy.</summary>
    PlatformResult EnsureDefaultSourceCaches();
}
