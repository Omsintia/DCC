using System;
using System.IO;
using System.Text;
using DnsCryptControl.Core.QueryLog;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// The Query Monitor's read-and-shred query-log reader (Phase 5e). Each <see cref="Drain"/> opens the
/// log ONCE for <c>FileAccess.ReadWrite</c> with <c>FileShare.ReadWrite | FileShare.Delete</c> (the
/// proxy holds a concurrent write handle — the default <c>FileShare.Read</c> hits a sharing violation,
/// proven on the VM), reads every byte, parses the COMPLETE-LINE prefix (everything up to and including
/// the last newline), then truncates the same handle to length 0 so at-rest browsing history is bounded
/// to one poll interval (IC-QM4).
///
/// <para><b>Truncate-to-0 with bounded fuzz.</b> We do the read and the <c>SetLength(0)</c> on one
/// handle. A rare line the proxy split across two writes right at the read/truncate boundary — i.e. a
/// partial trailing line with no terminating newline — is dropped this tick (the parser skips it and
/// the truncate discards it). The proxy writes each log line atomically, so a straddling partial is
/// rare and, when it happens, bounded to at most one line lost per drain (≤1 poll interval of fuzz).
/// The design accepts this in exchange for a race-free, always-empties-the-file shred: an alternative
/// "preserve the tail" scheme raced a concurrent append during the copy window and could re-order or
/// double-count, which is worse for a browsing-history recorder than dropping a single straddling line.</para>
///
/// <para>Fail-closed like the other UI readers: a missing file drains <see cref="DrainedQueries.Empty"/>;
/// a transient <see cref="IOException"/> (the sharing conflict seen in the spike) is retried ONCE and
/// then, if it still fails, drains empty for this tick WITHOUT truncating (so the unread bytes are
/// retried next tick). No method ever throws.</para>
/// </summary>
public sealed class QueryLogReader : IQueryLogReader
{
    private readonly string _path;

    /// <param name="queryLogPath">The query-log path to drain (defaults to the real per-user
    /// <see cref="UiPaths.QueryLogFile"/>; tests inject a temp path).</param>
    public QueryLogReader(string? queryLogPath = null)
    {
        _path = queryLogPath ?? UiPaths.QueryLogFile;
    }

    /// <summary>A sane upper bound on a single drain, symmetric with the rule-file reader's cap and the
    /// 1 MiB per-request transport cap: at one drain per poll interval the log cannot legitimately grow
    /// this large between ticks, so a file past the bound is treated as hostile and drops the read for
    /// this tick (still truncating, so it self-heals) rather than buffering an unbounded string. The
    /// dropped burst is signalled with <see cref="DrainedQueries.HadReadError"/> so the VM can surface a
    /// "dropped a burst" indication rather than a silent gap (not a false clean drain).</summary>
    private const long MaxDrainBytes = 8L * 1024 * 1024;

    public DrainedQueries Drain()
    {
        // Retry ONCE on a transient sharing conflict (the proxy momentarily holds an exclusive-ish
        // handle mid-write); a second failure drains empty for this tick without truncating.
        var result = TryDrainOnce();
        if (result is null)
        {
            result = TryDrainOnce();
        }

        return result ?? new DrainedQueries(Array.Empty<QueryLogLine>(), HadReadError: true);
    }

    /// <summary>
    /// One read-and-shred attempt. Returns the drained lines on success (including an ordinary empty
    /// drain for a missing/empty file), or <see langword="null"/> when a transient <see cref="IOException"/>
    /// blocked the read (the caller retries once more, then reports a read error). Never throws.
    /// </summary>
    private DrainedQueries? TryDrainOnce()
    {
        try
        {
            // A missing file is an ordinary empty drain (logging may be off, or the proxy has not
            // written yet), NOT a read error — do not truncate what does not exist.
            if (!File.Exists(_path))
            {
                return DrainedQueries.Empty;
            }

            using var stream = new FileStream(
                _path,
                FileMode.Open,
                FileAccess.ReadWrite,
                FileShare.ReadWrite | FileShare.Delete);

            // Snapshot the length at open. A file past the cap (only plantable past the per-user ACL
            // boundary, or a runaway burst) is dropped for this tick but still truncated, so it
            // self-heals rather than wedging every poll on an unbounded allocation. Signal the drop with
            // HadReadError so the VM shows a "dropped a burst" indication instead of a silent gap.
            var snapshotLength = stream.Length;
            if (snapshotLength > MaxDrainBytes)
            {
                stream.SetLength(0);
                return new DrainedQueries(Array.Empty<QueryLogLine>(), HadReadError: true);
            }

            // Read the current bytes with raw I/O (NOT a StreamReader — its buffering could advance past
            // what we account for and confuse the truncate below).
            var buffer = new byte[snapshotLength];
            var read = ReadExactlyUpTo(stream, buffer);

            // Read-and-shred (IC-QM4), truncate-to-0 with bounded fuzz: parse only the complete-line
            // prefix (everything up to and including the last newline) and TRUNCATE the whole file to 0.
            // A partial trailing line with no newline (a proxy write split across the boundary — rare,
            // since the proxy writes each line atomically) is dropped this tick and discarded by the
            // truncate. This is deliberately simple + race-free: we never copy a tail down while the
            // proxy may be appending, so the shred can neither re-order nor double-count lines.
            var completePrefixLength = LastNewlineExclusiveEnd(buffer, read);
            stream.SetLength(0);

            var text = DecodeUtf8(buffer, completePrefixLength);
            var lines = QueryLogParser.ParseLines(text);
            return new DrainedQueries(lines, HadReadError: false);
        }
        catch (IOException)
        {
            // Transient sharing conflict — signal the caller to retry / report a read error. The file
            // was NOT truncated, so its bytes are retried next tick.
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            // A permissions problem is not going to clear on an immediate retry; fail closed to a
            // read-error drain for this tick without spinning.
            return new DrainedQueries(Array.Empty<QueryLogLine>(), HadReadError: true);
        }
    }

    /// <summary>Reads up to <paramref name="buffer"/>.Length bytes from the current position, returning
    /// the count actually read (a short read is tolerated — the file may have been truncated by another
    /// party between the length snapshot and the read).</summary>
    private static int ReadExactlyUpTo(FileStream stream, byte[] buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var n = stream.Read(buffer, total, buffer.Length - total);
            if (n == 0)
            {
                break; // EOF earlier than the snapshot said — someone truncated concurrently.
            }

            total += n;
        }

        return total;
    }

    /// <summary>Returns the exclusive end index of the complete-line prefix: one past the LAST
    /// <c>'\n'</c> in <c>buffer[0, count)</c>, or 0 when there is no newline at all (the whole buffer is
    /// a single partial line). The slice <c>[0, result)</c> is exactly the bytes that end in a newline —
    /// every complete line — leaving any trailing partial line out. The trailing partial is dropped by
    /// the caller's truncate (bounded-fuzz, documented on the type).</summary>
    private static int LastNewlineExclusiveEnd(byte[] buffer, int count)
    {
        for (var i = count - 1; i >= 0; i--)
        {
            if (buffer[i] == (byte)'\n')
            {
                return i + 1;
            }
        }

        return 0;
    }

    /// <summary>Decodes <paramref name="count"/> bytes of <paramref name="buffer"/> as UTF-8, stripping a
    /// leading BOM if present (the proxy writes plain UTF-8, but a BOM would otherwise become part of the
    /// first field). Never throws — invalid sequences are replaced by the decoder's fallback.</summary>
    private static string DecodeUtf8(byte[] buffer, int count)
    {
        var start = 0;
        if (count >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF)
        {
            start = 3; // skip the UTF-8 BOM
        }

        return Encoding.UTF8.GetString(buffer, start, count - start);
    }

    public void Purge()
    {
        try
        {
            // Delete sharing lets this succeed even while the proxy still holds a handle; a missing
            // file is a no-op. Idempotent and fail-closed (IC-QM5).
            if (File.Exists(_path))
            {
                File.Delete(_path);
            }
        }
        catch (IOException)
        {
            // Best-effort: a sharing conflict or a not-yet-released handle leaves the file for the next
            // Purge/Drain to reclaim; never throw on the disable path.
        }
        catch (UnauthorizedAccessException)
        {
            // Same — the disable path must never surface a throw.
        }
    }
}
