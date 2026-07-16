using System;
using System.IO;

namespace DnsCryptControl.Core.Security;

/// <summary>
/// Lexical path-traversal confinement (CWE-22): canonicalizes and confines untrusted
/// relative paths to an allow-listed base directory and rejects traversal, rooted,
/// UNC, reserved-device-name, and ADS inputs. This does NOT resolve
/// symlinks/junctions/reparse points — callers performing file I/O must additionally
/// use handle-based, reparse-aware semantics to defend against link-following and TOCTOU
/// (CWE-367); that belongs in the privileged service that does the actual I/O.
/// </summary>
public static class SafePath
{
    private static readonly string[] ReservedDeviceNames =
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9",
        "LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9",
    };

    /// <summary>True if <paramref name="candidatePath"/> resolves to a location inside
    /// <paramref name="baseDir"/> (ordinal compare with a trailing separator to defeat
    /// prefix tricks like C:\base-evil).</summary>
    public static bool IsWithinBase(string baseDir, string candidatePath)
    {
        ArgumentException.ThrowIfNullOrEmpty(baseDir);
        ArgumentException.ThrowIfNullOrEmpty(candidatePath);

        var fullBase = Path.GetFullPath(baseDir);
        var withSep = fullBase.EndsWith(Path.DirectorySeparatorChar)
            ? fullBase
            : fullBase + Path.DirectorySeparatorChar;
        var fullCandidate = Path.GetFullPath(candidatePath);

        return fullCandidate.StartsWith(withSep, StringComparison.OrdinalIgnoreCase)
            || string.Equals(fullCandidate, fullBase, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Combines an untrusted *relative* name onto a trusted base directory,
    /// rejecting traversal, rooted paths, UNC, reserved device names, and ADS.</summary>
    public static string ResolveWithinBase(string baseDir, string untrustedRelativeName)
    {
        ArgumentException.ThrowIfNullOrEmpty(baseDir);
        ArgumentException.ThrowIfNullOrEmpty(untrustedRelativeName);

        if (untrustedRelativeName.Contains("..", StringComparison.Ordinal))
            throw new ArgumentException("Path traversal segment is not allowed.", nameof(untrustedRelativeName));
        if (untrustedRelativeName.Contains(':', StringComparison.Ordinal))
            throw new ArgumentException("Drive/stream specifiers are not allowed.", nameof(untrustedRelativeName));
        if (Path.IsPathRooted(untrustedRelativeName))
            throw new ArgumentException("Absolute paths are not allowed.", nameof(untrustedRelativeName));
        if (untrustedRelativeName.StartsWith("\\\\", StringComparison.Ordinal)
            || untrustedRelativeName.StartsWith("//", StringComparison.Ordinal))
            throw new ArgumentException("UNC paths are not allowed.", nameof(untrustedRelativeName));

        // Reject a reserved device name in ANY path component (not just the leaf): on Windows
        // a device name with any extension/trailing dot/space (e.g. CON, CON.txt, "CON ") still
        // resolves to the device, and an intermediate component (sub\CON\x) does too.
        foreach (var component in untrustedRelativeName.Split('\\', '/'))
        {
            if (component.Length == 0) continue;
            var deviceCandidate = component.Split('.')[0].Trim();
            if (Array.Exists(ReservedDeviceNames, n => string.Equals(n, deviceCandidate, StringComparison.OrdinalIgnoreCase)))
                throw new ArgumentException("Reserved device name is not allowed.", nameof(untrustedRelativeName));
        }

        var combined = Path.GetFullPath(Path.Combine(baseDir, untrustedRelativeName));
        if (!IsWithinBase(baseDir, combined))
            throw new ArgumentException("Resolved path escapes the base directory.", nameof(untrustedRelativeName));

        return combined;
    }
}
