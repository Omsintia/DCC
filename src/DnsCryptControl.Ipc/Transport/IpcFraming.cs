using System.Buffers.Binary;
using System.Text;
using DnsCryptControl.Ipc.Serialization;

namespace DnsCryptControl.Ipc.Transport;

/// <summary>
/// Length-prefixed message framing over a byte stream: a 4-byte little-endian UInt32
/// length followed by that many UTF-8 bytes. The length is validated against
/// <see cref="IpcSerializer.MaxBytes"/> BEFORE any body buffer is allocated, so a hostile
/// length prefix cannot exhaust memory in the privileged helper (CWE-400). All read
/// failures (EOF, truncation, bad length) fail closed by returning null.
/// </summary>
public static class IpcFraming
{
    private const int PrefixBytes = 4;

    public static async Task WriteFrameAsync(Stream stream, string message, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(message);

        var body = Encoding.UTF8.GetBytes(message);
        if (body.Length == 0 || body.Length > IpcSerializer.MaxBytes)
            throw new ArgumentException($"Frame body must be 1..{IpcSerializer.MaxBytes} bytes.", nameof(message));

        var prefix = new byte[PrefixBytes];
        BinaryPrimitives.WriteUInt32LittleEndian(prefix, (uint)body.Length);

        await stream.WriteAsync(prefix, ct).ConfigureAwait(false);
        await stream.WriteAsync(body, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    public static async Task<string?> ReadFrameAsync(Stream stream, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var prefix = new byte[PrefixBytes];
        if (!await ReadExactlyAsync(stream, prefix, ct).ConfigureAwait(false))
            return null; // EOF / truncated prefix

        var length = BinaryPrimitives.ReadUInt32LittleEndian(prefix);
        if (length == 0 || length > IpcSerializer.MaxBytes)
            return null; // non-positive or over-cap length: reject before allocating

        var body = new byte[length];
        if (!await ReadExactlyAsync(stream, body, ct).ConfigureAwait(false))
            return null; // truncated body

        return Encoding.UTF8.GetString(body);
    }

    /// <summary>Reads exactly buffer.Length bytes; returns false on EOF before the buffer
    /// is filled (closed/truncated stream).</summary>
    private static async Task<bool> ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset), ct).ConfigureAwait(false);
            if (read == 0) return false;
            offset += read;
        }
        return true;
    }
}
