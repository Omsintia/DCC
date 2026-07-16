using System.IO;
using System.Text;
using DnsCryptControl.Core.QueryLog;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// B (Phase 5e): <see cref="QueryLogReader"/> is the Query Monitor's read-and-shred query-log reader.
/// These are real-FS temp-file tests (the shred behaviour is inseparable from actual file state):
/// each <see cref="QueryLogReader.Drain"/> reads all current bytes, parses them through
/// <see cref="QueryLogParser"/>, then TRUNCATES the on-disk file to zero (IC-QM4); a missing file
/// drains empty; a shared-write handle (how the proxy holds the file) must NOT block the read; and a
/// non-shared exclusive lock fails closed to a read-error drain without throwing. <see cref="QueryLogReader.Purge"/>
/// deletes the file (IC-QM5). Nothing here touches the real <c>%LOCALAPPDATA%</c> — a temp path is injected.
/// </summary>
public class QueryLogReaderTests
{
    /// <summary>A well-formed 8-column TSV line the Core parser accepts (mirrors the VM spike format).</summary>
    private const string PassLine =
        "[2026-07-03 10:24:59]\t127.0.0.1\texample.com\tA\tPASS\t42ms\tcloudflare\t-";

    /// <summary>A REJECT line — locally answered, so server/relay are '-'.</summary>
    private const string RejectLine =
        "[2026-07-03 10:25:00]\t127.0.0.1\tads.doubleclick.net\tA\tREJECT\t0ms\t-\t-";

    private static string NewTempPath()
    {
        var dir = Path.Combine(Path.GetTempPath(), "querylog-" + Path.GetRandomFileName());
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, "query.log");
    }

    private static void CleanupDir(string filePath)
    {
        var dir = Path.GetDirectoryName(filePath)!;
        if (Directory.Exists(dir))
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ---- Drain: read-and-shred --------------------------------------------------------

    [Fact]
    public void Drain_reads_the_lines_then_truncates_the_file_to_zero()
    {
        var path = NewTempPath();
        try
        {
            File.WriteAllText(path, PassLine + "\n" + RejectLine + "\n");

            var drained = new QueryLogReader(path).Drain();

            // Read: both lines parsed, in file order, with the mapped actions.
            Assert.False(drained.HadReadError);
            Assert.Equal(2, drained.Lines.Count);
            Assert.Equal(QueryAction.Pass, drained.Lines[0].Action);
            Assert.Equal("example.com", drained.Lines[0].Name);
            Assert.Equal(QueryAction.Reject, drained.Lines[1].Action);

            // Shred (IC-QM4): the on-disk file is now truncated to zero — at-rest history is gone.
            Assert.Equal(0, new FileInfo(path).Length);
        }
        finally { CleanupDir(path); }
    }

    [Fact]
    public void Drain_a_second_time_after_shred_returns_nothing()
    {
        var path = NewTempPath();
        try
        {
            File.WriteAllText(path, PassLine + "\n");
            var reader = new QueryLogReader(path);

            var first = reader.Drain();
            Assert.Single(first.Lines);

            // The first drain shredded the file; the second sees an empty (but present) file.
            var second = reader.Drain();
            Assert.False(second.HadReadError);
            Assert.Empty(second.Lines);
            Assert.Equal(0, new FileInfo(path).Length);
        }
        finally { CleanupDir(path); }
    }

    [Fact]
    public void Drain_missing_file_is_an_empty_drain_not_an_error()
    {
        var path = NewTempPath();
        try
        {
            File.Delete(path); // ensure it does not exist (logging off / proxy not writing yet)

            var drained = new QueryLogReader(path).Drain();

            Assert.False(drained.HadReadError); // absence is not a read error
            Assert.Empty(drained.Lines);
            Assert.False(File.Exists(path));    // the reader did not create it
        }
        finally { CleanupDir(path); }
    }

    [Fact]
    public void Drain_empty_file_is_an_empty_drain()
    {
        var path = NewTempPath();
        try
        {
            File.WriteAllText(path, string.Empty);

            var drained = new QueryLogReader(path).Drain();

            Assert.False(drained.HadReadError);
            Assert.Empty(drained.Lines);
            Assert.Equal(0, new FileInfo(path).Length);
        }
        finally { CleanupDir(path); }
    }

    [Fact]
    public void Drain_reports_complete_lines_drops_the_partial_trailing_line_and_truncates_to_zero()
    {
        // Truncate-to-0 with bounded fuzz (FIX 3): a live tail can catch the proxy mid-append — a complete
        // line + newline, then a half-written line with NO terminating newline. The reader parses only the
        // complete-line prefix (up to the last newline), then truncates the WHOLE file to 0. The partial
        // trailing line is therefore DROPPED this tick (not preserved on disk) — the accepted ≤1-line fuzz.
        var path = NewTempPath();
        try
        {
            File.WriteAllText(path, PassLine + "\n[2026-07-03 10:25:01]\t127.0.0.1\tpartial");

            var drained = new QueryLogReader(path).Drain();

            Assert.False(drained.HadReadError);
            Assert.Single(drained.Lines);                 // only the complete line is reported
            Assert.Equal("example.com", drained.Lines[0].Name);

            // The whole file (including the partial trailing line) is truncated to zero — the partial is
            // gone, NOT left on disk for the next drain.
            Assert.Equal(0, new FileInfo(path).Length);
        }
        finally { CleanupDir(path); }
    }

    [Fact]
    public void Drain_a_partial_line_after_shred_is_gone_next_drain()
    {
        // Corollary of the truncate-to-0 contract: because the partial trailing line was discarded (not
        // preserved), a second drain finds an empty file — the dropped line does NOT reappear.
        var path = NewTempPath();
        try
        {
            File.WriteAllText(path, PassLine + "\n[2026-07-03 10:25:01]\t127.0.0.1\tpartial");
            var reader = new QueryLogReader(path);

            Assert.Single(reader.Drain().Lines); // the complete line; partial dropped + truncated

            var second = reader.Drain();
            Assert.False(second.HadReadError);
            Assert.Empty(second.Lines);           // the partial did NOT survive to the next drain
            Assert.Equal(0, new FileInfo(path).Length);
        }
        finally { CleanupDir(path); }
    }

    [Fact]
    public void Drain_malformed_line_is_skipped_and_the_good_lines_survive()
    {
        // Fail-closed parsing (5d discipline): a short/malformed line is skipped, never fatal.
        var path = NewTempPath();
        try
        {
            File.WriteAllText(path, "not\ta\tvalid\tline\n" + PassLine + "\n");

            var drained = new QueryLogReader(path).Drain();

            Assert.False(drained.HadReadError);
            Assert.Single(drained.Lines);                 // the malformed line was skipped
            Assert.Equal(QueryAction.Pass, drained.Lines[0].Action);
        }
        finally { CleanupDir(path); }
    }

    [Fact]
    public void Drain_succeeds_while_the_proxy_holds_a_shared_write_handle()
    {
        // The shipped proxy holds an open APPEND handle with ReadWrite|Delete sharing (VM-proven). The
        // reader MUST open with the matching share flags — the default FileShare.Read would hit a
        // sharing violation. Hold such a handle open across the drain and assert the read still works.
        var path = NewTempPath();
        try
        {
            File.WriteAllText(path, PassLine + "\n");

            using (var proxyHandle = new FileStream(
                path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
            {
                var drained = new QueryLogReader(path).Drain();

                Assert.False(drained.HadReadError);
                Assert.Single(drained.Lines);
                Assert.Equal(0, new FileInfo(path).Length); // still shredded despite the concurrent handle
            }
        }
        finally { CleanupDir(path); }
    }

    [Fact]
    public void Drain_exclusively_locked_file_fails_closed_to_a_read_error_without_throwing()
    {
        // A non-shared exclusive lock (FileShare.None) simulates the transient sharing conflict seen in
        // the spike. The reader retries once, then drains a read-error result — never a throw — and does
        // NOT truncate (so the bytes are retried next tick).
        var path = NewTempPath();
        try
        {
            File.WriteAllText(path, PassLine + "\n");

            using (var exclusive = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                var drained = new QueryLogReader(path).Drain(); // must not throw

                Assert.True(drained.HadReadError);
                Assert.Empty(drained.Lines);
            }

            // The lock is released; the content was preserved (NOT shredded) and a later drain reads it.
            Assert.True(new FileInfo(path).Length > 0);
            var recovered = new QueryLogReader(path).Drain();
            Assert.False(recovered.HadReadError);
            Assert.Single(recovered.Lines);
        }
        finally { CleanupDir(path); }
    }

    [Fact]
    public void Drain_a_new_append_after_shred_reads_only_the_new_bytes()
    {
        // End-to-end shred cadence: drain, proxy appends more, drain again reads ONLY the new lines
        // (the first batch was shredded), confirming no double-reporting and no lost lines.
        var path = NewTempPath();
        try
        {
            File.WriteAllText(path, PassLine + "\n");
            var reader = new QueryLogReader(path);

            Assert.Single(reader.Drain().Lines);

            // Simulate the proxy appending a new line after the shred (open APPEND, matching share).
            using (var append = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
            using (var writer = new StreamWriter(append, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
            {
                writer.Write(RejectLine + "\n");
            }

            var second = reader.Drain();
            Assert.Single(second.Lines);
            Assert.Equal(QueryAction.Reject, second.Lines[0].Action); // only the NEW line
        }
        finally { CleanupDir(path); }
    }

    [Fact]
    public void Drain_oversized_file_truncates_and_signals_a_dropped_burst_not_a_silent_gap()
    {
        // FIX 5: a file past the internal MaxDrainBytes cap (8 MiB) is a hostile plant or a runaway burst.
        // The reader truncates it to self-heal but must NOT report a clean empty drain (silent data loss):
        // it sets HadReadError so the VM can surface a "dropped a burst" indication.
        var path = NewTempPath();
        try
        {
            // Write just over 8 MiB of filler so stream.Length exceeds the cap.
            using (var fs = new FileStream(path, FileMode.Create, FileAccess.Write))
            {
                var chunk = new byte[1024 * 1024];
                for (var i = 0; i < 9; i++)
                {
                    fs.Write(chunk, 0, chunk.Length); // 9 MiB > 8 MiB cap
                }
            }

            var drained = new QueryLogReader(path).Drain();

            Assert.True(drained.HadReadError);            // honest: a burst was dropped, not a silent gap
            Assert.Empty(drained.Lines);
            Assert.Equal(0, new FileInfo(path).Length);   // still truncated so it self-heals next tick
        }
        finally { CleanupDir(path); }
    }

    // ---- Purge (IC-QM5, the disable/stop path) ----------------------------------------

    [Fact]
    public void Purge_deletes_the_on_disk_file()
    {
        var path = NewTempPath();
        try
        {
            File.WriteAllText(path, PassLine + "\n");
            Assert.True(File.Exists(path));

            new QueryLogReader(path).Purge();

            Assert.False(File.Exists(path)); // shredded from disk entirely
        }
        finally { CleanupDir(path); }
    }

    [Fact]
    public void Purge_missing_file_is_a_no_op()
    {
        var path = NewTempPath();
        try
        {
            File.Delete(path);

            new QueryLogReader(path).Purge(); // idempotent, must not throw

            Assert.False(File.Exists(path));
        }
        finally { CleanupDir(path); }
    }
}
