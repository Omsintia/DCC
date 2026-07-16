using System;
using System.IO;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Guards the UI's off-disk config reads against a pathologically large file. A real
/// <c>dnscrypt-proxy.toml</c> is a few KB, and the app can never SAVE one larger than the
/// 1 MiB IPC request limit, so a file far above that is corrupt — e.g. a mis-encoded
/// UTF-8↔ANSI round-trip that amplified a single character, or a log accidentally written
/// into it. Reading such a file whole with <see cref="File.ReadAllText(string)"/> /
/// <see cref="File.ReadAllBytes(string)"/> would either balloon the UI's memory (StreamReader
/// growing a multi-GB string) or throw the raw framework "file is too long" <see cref="IOException"/>
/// at ~2 GB. Every reader checks this first so it fails cleanly and cheaply instead.
/// </summary>
public static class ConfigReadGuard
{
    /// <summary>The largest config the UI will read off disk. 8 MiB is thousands of times a normal
    /// config and 8× the 1 MiB save limit — generous for any legitimate file, far below the size that
    /// would balloon a read. dnscrypt-proxy keeps its large lists (blocklists, resolver caches) in
    /// SEPARATE files, so the toml itself never legitimately approaches this.</summary>
    public const long MaxConfigBytes = 8L * 1024 * 1024;

    /// <summary>True when <paramref name="path"/> exists and its length exceeds
    /// <see cref="MaxConfigBytes"/>. Never throws: a length that can't be read fails toward
    /// "not oversized" so the caller's normal read path runs and surfaces the real I/O error.</summary>
    public static bool IsOversized(string path, out long length)
    {
        length = 0;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return false;
            length = info.Length;
            return length > MaxConfigBytes;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
        catch (ArgumentException) { return false; }
    }

    /// <summary>A user-facing, actionable message for an oversized config, quoting the size in MB.</summary>
    public static string OversizeMessage(long length)
    {
        var mb = length / (1024.0 * 1024.0);
        return $"Config file is unexpectedly large ({mb:F0} MB). dnscrypt-proxy.toml is normally a few KB — " +
               "this usually means the file is corrupt or something was written into it. Restore a known-good " +
               "config (a .bak in the backups folder) and reload.";
    }
}
