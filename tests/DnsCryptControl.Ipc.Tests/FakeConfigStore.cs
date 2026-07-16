using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Tests;

internal sealed class FakeConfigStore : IConfigStore
{
    public string? Config { get; set; }
    public Dictionary<RuleFileKind, string> RuleFiles { get; } = new();
    public PlatformErrorKind? FailNextWrite { get; set; }

    /// <summary>Overrides the sha the fake reports for the "on-disk" config; when null it
    /// derives from <see cref="Config"/> (UTF-8 bytes) so happy-path tests just seed Config
    /// and pass <c>TestSha.Of(Config)</c>. Set it explicitly to force a Conflict.</summary>
    public string? CurrentSha256 { get; set; }

    /// <summary>Every WriteConfigIfBaseMatches call, in order — lets handler tests assert
    /// the exact text+sha received, or that the CAS write surface was never touched.</summary>
    public List<(string TomlText, string BaseSha256)> CasWrites { get; } = new();

    public PlatformResult<string> ReadConfig() =>
        Config is null
            ? PlatformResult<string>.Fail(PlatformErrorKind.NotFound, "no config")
            : PlatformResult<string>.Ok(Config);

    public PlatformResult WriteConfig(string tomlText)
    {
        if (FailNextWrite is { } kind) { FailNextWrite = null; return PlatformResult.Fail(kind, "write failed"); }
        Config = tomlText; // simulates the post-commit state; config unchanged on the fail path above
        return PlatformResult.Ok();
    }

    // In-memory mirror of FileSystemConfigStore.WriteConfigIfBaseMatches semantics.
    public PlatformResult WriteConfigIfBaseMatches(string tomlText, string expectedBaseSha256)
    {
        CasWrites.Add((tomlText, expectedBaseSha256));
        if (FailNextWrite is { } kind) { FailNextWrite = null; return PlatformResult.Fail(kind, "write failed"); }

        if (expectedBaseSha256.Length != 64 || !expectedBaseSha256.All(Uri.IsHexDigit))
            return PlatformResult.Fail(PlatformErrorKind.InvalidArgument, "expectedBaseSha256 must be a 64-character hex SHA-256");

        var current = CurrentSha256 ?? (Config is null ? null : TestSha.Of(Config));
        if (current is null)
            return PlatformResult.Fail(PlatformErrorKind.Conflict, "config file missing — reload before saving: dnscrypt-proxy.toml");
        if (!string.Equals(current, expectedBaseSha256.ToLowerInvariant(), StringComparison.Ordinal))
            return PlatformResult.Fail(PlatformErrorKind.Conflict, "config file changed on disk since it was loaded — reload before saving");

        Config = tomlText; // config unchanged on every fail path above
        return PlatformResult.Ok();
    }

    public PlatformResult WriteRuleFile(RuleFileKind kind, string content)
    {
        if (FailNextWrite is { } fk) { FailNextWrite = null; return PlatformResult.Fail(fk, "write failed"); }
        RuleFiles[kind] = content;
        return PlatformResult.Ok();
    }

    /// <summary>Records each PlaceOdohSourceCaches call; <see cref="FailNextOdohPlace"/> forces one failure.</summary>
    public int PlaceOdohCalls { get; private set; }
    public PlatformErrorKind? FailNextOdohPlace { get; set; }

    public PlatformResult PlaceOdohSourceCaches()
    {
        PlaceOdohCalls++;
        if (FailNextOdohPlace is { } kind) { FailNextOdohPlace = null; return PlatformResult.Fail(kind, "odoh cache place failed"); }
        return PlatformResult.Ok();
    }

    /// <summary>Records each EnsureDefaultSourceCaches call; <see cref="FailNextEnsureDefault"/> forces one failure.</summary>
    public int EnsureDefaultCalls { get; private set; }
    public PlatformErrorKind? FailNextEnsureDefault { get; set; }

    public PlatformResult EnsureDefaultSourceCaches()
    {
        EnsureDefaultCalls++;
        if (FailNextEnsureDefault is { } kind) { FailNextEnsureDefault = null; return PlatformResult.Fail(kind, "default cache seed failed"); }
        return PlatformResult.Ok();
    }
}
