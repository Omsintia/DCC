using System;
using System.IO;
using DnsCryptControl.Core.Security;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Confines an untrusted <c>log_file</c> config value to the proxy's ProgramData directory before the UI
/// tails it. The config's <c>log_file</c> is attacker-influenceable (a hostile or hand-edited config, or an
/// external write), and the Logs and Diagnostics tab reads that file's trailing bytes onto the screen;
/// without confinement a crafted value - a UNC path, a <c>\\.\</c> device, an NTFS alternate data stream, a
/// traversal, or a sensitive local file such as <c>C:\Windows\System32\config\SAM</c> - would turn the
/// read-only log tail into an ARBITRARY-FILE READER in the UNPRIVILEGED UI (finding 2026-07-08). This is a
/// purely lexical guard (CWE-22 / CWE-73): it never opens a file, it only decides which path is safe to read.
/// </summary>
public static class LogFilePathGuard
{
    /// <summary>
    /// Resolves <paramref name="logFile"/> (a config <c>log_file</c> value) to an absolute path CONFINED to
    /// <paramref name="baseDir"/> (the proxy's working / ProgramData directory), or <see langword="null"/>
    /// when it is empty, exotic (UNC / device / alternate-data-stream / traversal), or resolves outside the
    /// base. A relative name resolves against the base (the proxy's cwd); an absolute name is accepted only
    /// if it already resolves within the base. Never throws.
    /// </summary>
    public static string? ConfineToBase(string? logFile, string? baseDir)
    {
        if (string.IsNullOrEmpty(logFile) || string.IsNullOrEmpty(baseDir))
        {
            return null;
        }

        // Reject exotic shapes lexically, BEFORE any path resolution.
        if (logFile.Contains("..", StringComparison.Ordinal))
        {
            return null; // traversal segment
        }

        if (logFile.StartsWith("\\\\", StringComparison.Ordinal) || logFile.StartsWith("//", StringComparison.Ordinal))
        {
            return null; // UNC ( \\host\share ) and the Win32 device namespace ( \\.\  \\?\ )
        }

        // A ':' is legitimate ONLY as the drive-letter colon at index 1 of an absolute path; any other ':'
        // is an NTFS alternate-data-stream / drive-stream specifier. Strip a leading "X:" then reject any ':'.
        var afterDrive = logFile.Length >= 2 && logFile[1] == ':' ? logFile[2..] : logFile;
        if (afterDrive.Contains(':', StringComparison.Ordinal))
        {
            return null; // alternate data stream
        }

        string full;
        try
        {
            full = Path.IsPathRooted(logFile)
                ? Path.GetFullPath(logFile)
                : Path.GetFullPath(Path.Combine(baseDir, logFile));
        }
        catch (ArgumentException)
        {
            return null; // invalid path characters
        }
        catch (IOException)
        {
            return null; // includes PathTooLongException
        }
        catch (NotSupportedException)
        {
            return null; // malformed path (e.g. a stray colon that slipped the lexical check)
        }
        catch (System.Security.SecurityException)
        {
            return null; // denied
        }

        return SafePath.IsWithinBase(baseDir, full) ? full : null;
    }
}
