using System.Collections.Generic;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// A read-only tail reader for the proxy's own operational log (<c>dnscrypt-proxy.log</c>, design 3.2).
/// Unlike <see cref="IQueryLogReader"/> this NEVER shreds — the proxy log is operational diagnostics
/// (lower sensitivity than browsing history), so it is read read-only and left intact; disabling capture
/// is what removes it. Fail-closed like the other UI readers: a missing/unreadable file yields an empty
/// tail, never a throw.
/// </summary>
public interface ILogTailReader
{
    /// <summary>
    /// Reads up to the last <paramref name="maxLines"/> lines of the file at <paramref name="path"/>, in
    /// file order (oldest first). A missing or unreadable file, or a non-positive
    /// <paramref name="maxLines"/>, yields an empty tail. Never throws — the proxy may hold a concurrent
    /// write handle, so reads tolerate sharing.
    /// </summary>
    /// <param name="path">The absolute path of the log file to tail.</param>
    /// <param name="maxLines">The maximum number of trailing lines to return.</param>
    /// <returns>The trailing lines (oldest first; empty when unreadable/missing).</returns>
    IReadOnlyList<string> ReadTail(string path, int maxLines);
}
