using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// The production <see cref="ILogTailReader"/>: reads a file's trailing lines read-only, tolerating the
/// proxy's concurrent write handle (<c>FileShare.ReadWrite | FileShare.Delete</c>). Bounds the read to a
/// tail-sized byte window so a large log never buffers unboundedly, then returns the last N lines of that
/// window. Fail-closed: a missing/locked/unreadable file yields an empty tail; never throws.
/// </summary>
public sealed class LogTailReader : ILogTailReader
{
    /// <summary>The byte window read from the end of the file — enough to contain <c>maxLines</c> typical
    /// proxy-log lines without buffering an arbitrarily large file. A line straddling the window's leading
    /// edge is simply dropped (we only ever return whole trailing lines).</summary>
    private const int TailWindowBytes = 256 * 1024;

    public IReadOnlyList<string> ReadTail(string path, int maxLines)
    {
        if (string.IsNullOrEmpty(path) || maxLines <= 0)
        {
            return Array.Empty<string>();
        }

        try
        {
            if (!File.Exists(path))
            {
                return Array.Empty<string>();
            }

            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);

            var length = stream.Length;
            var windowStart = length > TailWindowBytes ? length - TailWindowBytes : 0;
            var windowLength = (int)(length - windowStart);
            if (windowLength <= 0)
            {
                return Array.Empty<string>();
            }

            stream.Position = windowStart;
            var buffer = new byte[windowLength];
            var read = ReadFully(stream, buffer);

            // A BOM only exists at true file start; when reading a mid-file window there is none to strip.
            var text = DecodeUtf8(buffer, read, stripBom: windowStart == 0);
            var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

            // Drop a trailing empty element from a newline-terminated final line, and the leading partial
            // line when we started mid-file.
            var from = 0;
            var to = lines.Length;
            if (to > 0 && lines[to - 1].Length == 0)
            {
                to--;
            }

            if (windowStart > 0 && to - from > 0)
            {
                from++; // discard the partial first line of the window
            }

            var available = to - from;
            if (available <= 0)
            {
                return Array.Empty<string>();
            }

            if (available > maxLines)
            {
                from = to - maxLines;
                available = maxLines;
            }

            var result = new List<string>(available);
            for (var i = from; i < to; i++)
            {
                result.Add(lines[i]);
            }

            return result;
        }
        catch (IOException)
        {
            return Array.Empty<string>();
        }
        catch (UnauthorizedAccessException)
        {
            return Array.Empty<string>();
        }
    }

    private static int ReadFully(FileStream stream, byte[] buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var n = stream.Read(buffer, total, buffer.Length - total);
            if (n == 0)
            {
                break;
            }

            total += n;
        }

        return total;
    }

    private static string DecodeUtf8(byte[] buffer, int count, bool stripBom)
    {
        var start = 0;
        if (stripBom && count >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF)
        {
            start = 3;
        }

        return Encoding.UTF8.GetString(buffer, start, count - start);
    }
}
