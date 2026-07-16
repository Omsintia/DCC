using System;
using System.Collections.Generic;
using System.IO;
using DnsCryptControl.Core.Sources;
using DnsCryptControl.Core.Toml;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Reads the proxy's cached resolver/relay lists from <c>%ProgramData%\DnsCryptControl</c>,
/// discovering the sources (<c>cache_file</c> + <c>prefix</c>) from the on-disk config so list
/// names are never hardcoded. Opens with <c>FileShare.ReadWrite | FileShare.Delete</c> so a read
/// never fails just because the proxy is rewriting the cache mid-refresh. Fail-closed: any error
/// becomes a typed <see cref="ResolverListState"/>, never a throw.
/// </summary>
public sealed class ResolverListReader : IResolverListReader
{
    private readonly string _configFilePath;
    private readonly string _programDataDir;
    private readonly string _bundledSnapshotDir;

    /// <param name="configFilePath">The dnscrypt-proxy.toml to read sources from (defaults to the real path).</param>
    /// <param name="programDataDir">The directory the proxy writes caches into (defaults to <see cref="UiPaths.ProgramDataDir"/>).</param>
    /// <param name="bundledSnapshotDir">The shipped offline snapshot directory (defaults to <see cref="UiPaths.BundledSnapshotDir"/>).</param>
    public ResolverListReader(string? configFilePath = null, string? programDataDir = null, string? bundledSnapshotDir = null)
    {
        _configFilePath = configFilePath ?? UiPaths.ConfigFile;
        _programDataDir = programDataDir ?? UiPaths.ProgramDataDir;
        _bundledSnapshotDir = bundledSnapshotDir ?? UiPaths.BundledSnapshotDir;
    }

    public IReadOnlyList<ResolverListSnapshot> ReadAll()
    {
        var configText = TryReadAllText(_configFilePath);
        if (configText is null) return Array.Empty<ResolverListSnapshot>();

        var doc = TomlConfigDocument.Parse(configText);
        if (doc.HasErrors || !doc.TryGetSubTables("sources", out var sources))
            return Array.Empty<ResolverListSnapshot>();

        var snapshots = new List<ResolverListSnapshot>(sources.Count);
        foreach (var source in sources)
        {
            if (!source.TryGetString("cache_file", out var cacheFile) || string.IsNullOrEmpty(cacheFile))
                continue; // a source with no cache_file has nothing to read
            var prefix = source.TryGetString("prefix", out var p) && p is not null ? p : "";
            snapshots.Add(ReadSource(source.Name, cacheFile, prefix));
        }
        return snapshots;
    }

    private ResolverListSnapshot ReadSource(string sourceName, string cacheFileName, string prefix)
    {
        // Resolve the cache path relative to the proxy's config dir (bare filename only — CWE-22 guard).
        var cachePath = UiPaths.ResolveCacheFile(cacheFileName, _programDataDir);
        if (cachePath is not null && File.Exists(cachePath))
        {
            var text = TryReadShared(cachePath);
            if (text is null)
                return new ResolverListSnapshot(sourceName, prefix, ResolverListState.Unreadable, TryGetMtime(cachePath), null);

            var parsed = ResolverListParser.Parse(text, prefix);
            var state = parsed.WholeFileInvalid ? ResolverListState.ParseFailed : ResolverListState.Fresh;
            return new ResolverListSnapshot(sourceName, prefix, state, TryGetMtime(cachePath), parsed);
        }

        // No cache file — fall back to the bundled snapshot (F21) if one shipped.
        var bundledPath = UiPaths.ResolveCacheFile(cacheFileName, _bundledSnapshotDir);
        if (bundledPath is not null && File.Exists(bundledPath))
        {
            var text = TryReadShared(bundledPath);
            if (text is not null)
            {
                var parsed = ResolverListParser.Parse(text, prefix);
                if (!parsed.WholeFileInvalid)
                    return new ResolverListSnapshot(sourceName, prefix, ResolverListState.Bundled, TryGetMtime(bundledPath), parsed);
            }
        }

        return new ResolverListSnapshot(sourceName, prefix, ResolverListState.Missing, null, null);
    }

    private static string? TryReadAllText(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            // A pathologically large config would balloon this reader (ReadAllText grows a multi-GB
            // string) — fail closed to null so the list panel renders empty rather than OOM-ing the UI.
            if (ConfigReadGuard.IsOversized(path, out _)) return null;
            return File.ReadAllText(path);
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    // Share ReadWrite | Delete: the proxy replaces the cache file (temp + rename/delete) during a
    // refresh; without Delete sharing a concurrent read would throw.
    private static string? TryReadShared(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream); // detects the BOM / decodes UTF-8
            return reader.ReadToEnd();
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    private static DateTimeOffset? TryGetMtime(string path)
    {
        try { return File.Exists(path) ? new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero) : null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }
}
