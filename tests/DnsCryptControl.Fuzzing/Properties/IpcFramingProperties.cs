using System.Buffers.Binary;
using CsCheck;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Ipc.Transport;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz properties for the IPC wire framing (<see cref="IpcFraming.ReadFrameAsync"/>) - the
/// length-prefixed frame reader that sits on the LocalSystem trust boundary. A hostile local
/// caller can push arbitrary bytes at the privileged helper, so the reader is the choke point
/// that must survive them. The invariants asserted here are:
/// (1) TOTALITY + FAIL-CLOSED - ReadFrameAsync never throws for any bytes and returns null on
///     any malformed / truncated frame;
/// (2) THE ANTI-DoS CAP (CWE-400) - a 4-byte length prefix of 0 or greater than
///     <see cref="IpcSerializer.MaxBytes"/> is rejected and yields null; because the prefix is read
///     as an UNSIGNED UInt32, the high-bit values 0x80000000..0xFFFFFFFF are all treated as
///     over-cap (never sign-flipped to a negative or a giant signed allocation);
/// (3) EXACT ROUND-TRIP - a valid body (1..MaxBytes) written by WriteFrameAsync reads back
///     byte-for-byte as its UTF-8 decoding.
/// These properties drive the async reader over an in-memory stream and block on the ValueTask
/// with GetAwaiter().GetResult() because CsCheck's Sample predicate is synchronous (test-only).
/// See the fuzzing design notes.
/// </summary>
public class IpcFramingProperties
{
    private const int PrefixBytes = 4;

    /// <summary>Interesting 4-byte prefix values: the cap boundaries and the signed/unsigned
    /// high-bit region that a naive Int32 reader would mishandle. Hoisted to satisfy CA1861.</summary>
    private static readonly uint[] BoundaryPrefixes =
    {
        0u,
        1u,
        (uint)IpcSerializer.MaxBytes,
        (uint)IpcSerializer.MaxBytes + 1u,
        0x7FFFFFFFu, // int.MaxValue: largest positive signed - still hugely over-cap
        0x80000000u, // int.MinValue if read signed: MUST be treated as ~2.1 GB over-cap, not negative
        0xFFFFFFFFu, // all ones: -1 if read signed - MUST be over-cap, never a tiny/negative alloc
    };

    // ---- Totality: any bytes at all ------------------------------------------------------------

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ReadFrame_never_throws_on_arbitrary_bytes() =>
        // Full random byte arrays: exercises the prefix read, the length gate, and the body read
        // over completely unstructured hostile input.
        Gen.Byte.Array.Sample(ReadIsFailClosed, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ReadFrame_never_throws_on_boundary_prefix_with_arbitrary_tail() =>
        // A boundary prefix followed by an arbitrary tail: probes the length gate at exactly the
        // cap edges and the unsigned high-bit region, then lets the body read run on random bytes.
        Gen.Select(Gen.Int[0, BoundaryPrefixes.Length - 1], Gen.Byte.Array,
                (idx, tail) => Frame(BoundaryPrefixes[idx], tail))
            .Sample(ReadIsFailClosed, iter: Fuzz.Iter);

    /// <summary>The prefix declares N bytes but M are provided. When the prefix is a valid in-cap
    /// length yet the stream is short (or long), the reader must still never throw. A truncated body
    /// must fail closed to null; extra trailing bytes are simply ignored (a non-null decode is fine).</summary>
    [Fact]
    [Trait("Category", "Fuzz")]
    public void ReadFrame_never_throws_on_declared_vs_provided_mismatch() =>
        Gen.Select(Gen.Int[1, 4096], Gen.Byte.Array,
                (declared, provided) => Frame((uint)declared, provided))
            .Sample(ReadIsFailClosed, iter: Fuzz.Iter);

    // ---- The anti-DoS cap (unsigned prefix) ----------------------------------------------------

    /// <summary>Any prefix of 0 or above the cap must be rejected to null regardless of what follows,
    /// and the high-bit values must be treated as over-cap (unsigned), never as a negative/giant alloc.
    /// The oracle: if the prefix is out of the 1..MaxBytes window, the read MUST return null.</summary>
    [Fact]
    [Trait("Category", "Fuzz")]
    public void ReadFrame_rejects_zero_and_overcap_prefixes_unsigned() =>
        Gen.Select(Gen.UInt, Gen.Byte.Array, (prefix, tail) => (prefix, tail))
            .Sample(t =>
            {
                using var ms = new MemoryStream(Frame(t.prefix, t.tail));
                var result = ReadFrame(ms);
                var inWindow = t.prefix >= 1 && t.prefix <= (uint)IpcSerializer.MaxBytes;
                // Out-of-window prefix (includes every 0x80000000..0xFFFFFFFF high-bit value): must be null.
                // In-window prefix with a short tail is also null; only an in-window prefix with enough
                // bytes can be non-null - so a non-null result implies the prefix was in-window.
                return inWindow || result is null;
            }, iter: Fuzz.Iter);

    // ---- Exact round-trip for valid bodies -----------------------------------------------------

    /// <summary>A body of 1..MaxBytes written by WriteFrameAsync must read back as exactly its UTF-8
    /// decoding. We build the frame from raw bytes (not a round-tripped string) so lone surrogates
    /// cannot muddy the oracle: the contract is byte-exact framing, decoded once with UTF-8.</summary>
    [Fact]
    [Trait("Category", "Fuzz")]
    public void ReadFrame_roundTrips_valid_bodies_exactly() =>
        NonEmptyBodyGen.Sample(body =>
        {
            using var ms = new MemoryStream(Frame((uint)body.Length, body));
            var result = ReadFrame(ms);
            return result == System.Text.Encoding.UTF8.GetString(body);
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void WriteFrame_then_ReadFrame_roundTrips_wellFormed_text() =>
        // A string with no lone surrogates survives UTF-8 encode/decode unchanged, so
        // WriteFrame(x) then ReadFrame must yield x exactly. Bodies over the cap are skipped
        // because WriteFrameAsync legitimately throws ArgumentException for those (asserted below).
        Gen.String.Sample(text =>
        {
            var byteLen = System.Text.Encoding.UTF8.GetByteCount(text);
            if (byteLen == 0 || byteLen > IpcSerializer.MaxBytes) return true; // out of WriteFrame's domain
            if (HasLoneSurrogate(text)) return true; // encode is lossy; not a framing contract
            using var ms = new MemoryStream();
            IpcFraming.WriteFrameAsync(ms, text, CancellationToken.None).GetAwaiter().GetResult();
            ms.Position = 0;
            return ReadFrame(ms) == text;
        }, iter: Fuzz.Iter);

    // ---- Concrete regression anchors -----------------------------------------------------------

    [Theory]
    [InlineData(0u)]           // zero length: rejected before allocating
    [InlineData(0x80000000u)]  // int.MinValue if signed: over-cap, must not sign-flip
    [InlineData(0xFFFFFFFFu)]  // -1 if signed: over-cap, must not become a tiny/negative alloc
    [InlineData((uint)IpcSerializer.MaxBytes + 1u)] // one past the cap
    public void ReadFrame_prefix_is_rejected_without_a_body(uint prefix)
    {
        var buf = new byte[PrefixBytes];
        BinaryPrimitives.WriteUInt32LittleEndian(buf, prefix);
        using var ms = new MemoryStream(buf); // prefix only, no body bytes at all
        Assert.Null(ReadFrame(ms));
    }

    [Fact]
    public void ReadFrame_prefix_at_exactly_MaxBytes_is_in_window()
    {
        // The cap is inclusive: MaxBytes is a legal length. With a full body it must decode (non-null).
        var body = new byte[IpcSerializer.MaxBytes];
        using var ms = new MemoryStream(Frame((uint)IpcSerializer.MaxBytes, body));
        Assert.NotNull(ReadFrame(ms));
    }

    [Fact]
    public void ReadFrame_empty_stream_is_null()
    {
        using var ms = new MemoryStream(Array.Empty<byte>());
        Assert.Null(ReadFrame(ms));
    }

    [Fact]
    public void ReadFrame_partial_prefix_is_null()
    {
        // Only 3 of the 4 prefix bytes present: truncated prefix -> fail closed.
        using var ms = new MemoryStream(new byte[] { 1, 0, 0 });
        Assert.Null(ReadFrame(ms));
    }

    // ---- Helpers -------------------------------------------------------------------------------

    /// <summary>Fail-closed oracle: driving ReadFrameAsync over the given bytes must not throw. The
    /// method throwing is the only failure mode (it fails the property); the returned value - null or a
    /// decoded string - is both a valid outcome for arbitrary input, so the oracle just proves totality.</summary>
    private static bool ReadIsFailClosed(byte[] bytes)
    {
        using var ms = new MemoryStream(bytes);
        // A throw propagates and fails the property; any return (null or string) is acceptable here.
        ReadFrame(ms);
        return true;
    }

    /// <summary>Synchronously drive the async reader (test-only: Sample's predicate is synchronous).</summary>
    private static string? ReadFrame(Stream stream) =>
        IpcFraming.ReadFrameAsync(stream, CancellationToken.None).GetAwaiter().GetResult();

    /// <summary>Build a raw frame: a 4-byte little-endian UInt32 prefix followed by the given body bytes.
    /// The prefix and the provided body length are decoupled on purpose so mismatches can be generated.</summary>
    private static byte[] Frame(uint prefix, byte[] body)
    {
        var buf = new byte[PrefixBytes + body.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(buf, prefix);
        Array.Copy(body, 0, buf, PrefixBytes, body.Length);
        return buf;
    }

    private static bool HasLoneSurrogate(string s)
    {
        for (var i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]))
            {
                if (i + 1 >= s.Length || !char.IsLowSurrogate(s[i + 1])) return true;
                i++; // valid pair: skip the low surrogate
            }
            else if (char.IsLowSurrogate(s[i]))
            {
                return true; // low surrogate with no preceding high surrogate
            }
        }
        return false;
    }

    /// <summary>Non-empty byte body capped at 4096 so the round-trip stays fast while still covering
    /// the small-frame region exhaustively; the MaxBytes edge is covered by an explicit anchor above.</summary>
    private static readonly Gen<byte[]> NonEmptyBodyGen =
        Gen.Select(Gen.Int[1, 4096], Gen.Byte.Array, (n, arr) => Grow(arr, n));

    /// <summary>Produce a byte array of exactly length n (repeat/truncate the generated array).</summary>
    private static byte[] Grow(byte[] src, int n)
    {
        var result = new byte[n];
        if (src.Length == 0)
            return result; // all-zero body of length n
        for (var i = 0; i < n; i++)
            result[i] = src[i % src.Length];
        return result;
    }
}
