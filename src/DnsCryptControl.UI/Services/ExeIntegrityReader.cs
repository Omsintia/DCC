using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Computes offline integrity facts (path, version, SHA-256) for the installed proxy. Pure file I/O — no
/// network, no pipe, no embedded pin. Fail-closed: a missing/locked/denied file degrades to nulls rather
/// than throwing.
///
/// <para><b>Version source:</b> dnscrypt-proxy is a Go binary with no Win32 VERSIONINFO resource, so
/// <see cref="FileVersionInfo"/> is empty. The UI also cannot run <c>&lt;exe&gt; -version</c>: the proxy is
/// ACL-protected so only SYSTEM may EXECUTE it (Users are granted Read, not ReadAndExecute), and
/// <c>Process.Start</c> returns "Access is denied" — proof the supply-chain hardening works. Instead we read
/// the installer-pinned version <c>tag</c> from the sibling <c>state\installed-binary.json</c> — the record
/// the helper's integrity gate verifies against, so it describes the installed + verified binary — on which
/// Users hold Read.</para>
/// </summary>
public sealed class ExeIntegrityReader : IExeIntegrityReader
{
    public ExeIntegrityInfo Read(string exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
        {
            return new ExeIntegrityInfo(exePath ?? string.Empty, FileVersion: null, Sha256Hex: null, Exists: false);
        }

        return new ExeIntegrityInfo(exePath, TryReadVersion(exePath), TryComputeSha256(exePath), Exists: true);
    }

    private static string? TryReadVersion(string exePath)
    {
        // PE version first (empty for the Go binary), else the installer-pinned tag (see class remarks).
        var pe = TryReadPeVersion(exePath);
        return !string.IsNullOrWhiteSpace(pe) ? pe : TryReadPinnedTag(exePath);
    }

    private static string? TryReadPeVersion(string exePath)
    {
        try
        {
            var v = FileVersionInfo.GetVersionInfo(exePath).FileVersion;
            return string.IsNullOrWhiteSpace(v) ? null : v;
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    /// <summary>Reads the installer-pinned proxy version (<c>tag</c>) from the sibling
    /// <c>state\installed-binary.json</c> (relative to the proxy exe's directory). Fail-closed to null on any
    /// absence, access denial, oversize, or corruption.</summary>
    private static string? TryReadPinnedTag(string exePath)
    {
        try
        {
            var dir = Path.GetDirectoryName(exePath);
            if (string.IsNullOrEmpty(dir)) return null;
            var recordPath = Path.Combine(dir, "state", "installed-binary.json");
            if (!File.Exists(recordPath)) return null;
            if (new FileInfo(recordPath).Length > 64 * 1024) return null; // tiny record; guard amplification
            using var doc = JsonDocument.Parse(File.ReadAllText(recordPath));
            return doc.RootElement.ValueKind == JsonValueKind.Object
                   && doc.RootElement.TryGetProperty("tag", out var tag)
                   && tag.ValueKind == JsonValueKind.String
                ? SanitizeVersion(tag.GetString())
                : null;
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
        catch (JsonException) { return null; }
    }

    /// <summary>Normalizes a version token to a safe, short string, or null. Scans lines and returns the first
    /// version-ish one (version-token chars only AND at least one digit) so a corrupt record cannot inject
    /// junk/control characters into the integrity panel.</summary>
    internal static string? SanitizeVersion(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        foreach (var candidate in raw.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var line = candidate.Length > 48 ? candidate[..48] : candidate;
            if (line.Length > 0
                && line.Any(char.IsDigit)
                && line.All(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '+' or '_' or ' '))
            {
                return line.Trim();
            }
        }
        return null;
    }

    private static string? TryComputeSha256(string exePath)
    {
        try
        {
            using var stream = File.OpenRead(exePath);
            var hash = SHA256.HashData(stream);
            return ToLowerHex(hash);
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    /// <summary>Lowercase hex (matches published dnscrypt-proxy checksums) without <c>ToLowerInvariant</c> (CA1308).</summary>
    private static string ToLowerHex(byte[] bytes) =>
        string.Concat(Array.ConvertAll(bytes, b => b.ToString("x2", CultureInfo.InvariantCulture)));
}
