using System.Text;
using CsCheck;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Security;
using DnsCryptControl.Ipc.Serialization;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz properties for <see cref="IpcSerializer"/> - the deserialization of attacker-controlled
/// JSON inside the LocalSystem helper (the highest-value CWE-502 / CWE-400 surface: whatever a
/// client can write to the named pipe lands here first). The headline invariants, all drawn from
/// the serializer's own contract (fail closed, never throw):
/// (1) TOTALITY + FAIL-CLOSED - DeserializeRequest / DeserializePayload never throw for ANY string
///     (malformed, too-deep, type-swapped, random unicode); a bad frame yields null/default, never
///     an exception escaping into the privileged helper.
/// (2) DEPTH LIMIT - nesting is capped at MaxDepth (16); JSON nested 17+ deep (up to 1000) must
///     return null via a caught JsonException, never a StackOverflow.
/// (3) BYTE CAP - MaxBytes (1 MiB) is enforced on BOTH the UTF-16 char length and the UTF-8 byte
///     length; a frame over the cap returns default without reaching the JSON reader.
/// (4) UNREGISTERED TYPE - only source-generated DTOs deserialize; an unregistered T yields default
///     (the NotSupportedException path), never a throw.
/// See the fuzzing design notes.
/// </summary>
public class IpcSerializerProperties
{
    // Hoisted to satisfy CA1861 (no inline constant arrays) and to seed the type-swap / hostile
    // JSON generators with literals that historically break naive parsers (NaN/Infinity are invalid
    // JSON; a lone high surrogate is an invalid escape; a BOM/trailing garbage tail must be rejected).
    private static readonly string[] HostileJsonFragments =
    {
        "{\"Command\":0,\"PayloadJson\":null}",              // well-formed envelope (baseline)
        "{\"Command\":0,\"PayloadJson\":\"x\",\"evil\":1}",  // unknown property (must be ignored)
        "{\"Command\":\"GetStatus\",\"PayloadJson\":null}",  // type-swap: string where enum-number expected
        "{\"Command\":{},\"PayloadJson\":null}",             // type-swap: object where number expected
        "{\"Command\":[],\"PayloadJson\":null}",             // type-swap: array where number expected
        "{\"Command\":0,\"PayloadJson\":123}",               // type-swap: number where string expected
        "{\"Command\":0,\"PayloadJson\":{}}",                // type-swap: object where string expected
        "{\"Command\":0,\"Command\":1,\"PayloadJson\":null}",// duplicate keys
        "{\"Command\":NaN}",                                 // NaN literal (invalid JSON)
        "{\"Command\":Infinity}",                            // Infinity literal (invalid JSON)
        "{\"Command\":-Infinity}",                           // -Infinity literal (invalid JSON)
        "\uFEFF{\"Command\":0,\"PayloadJson\":null}",       // leading BOM (U+FEFF)
        "{\"Command\":0,\"PayloadJson\":null} trailing junk",// trailing garbage after a valid value
        "{\"PayloadJson\":\"\\uD834\"}",                     // lone high surrogate escape
        "{\"PayloadJson\":\"\\uDC00\"}",                     // lone low surrogate escape
        "{\"Command\":2147483648}",                          // int overflow (2^31)
        "{\"Command\":-2147483649}",                         // int underflow (-2^31-1)
        "{\"Command\":99999999999999999999}",               // way past int64
        "}{ not json",                                       // structurally broken
        "",                                                  // empty
        "null",                                              // JSON null literal
        "[]",                                                // array root where object expected
        "\"just a string\"",                                 // string root where object expected
        "42",                                                // number root where object expected
    };

    // Registered payload DTOs whose Deserialize<T> path must also be total (they exercise the
    // typed-object readers, not just the envelope). Kept as a generator of the shape strings.
    private static readonly string[] TypedPayloadShapes =
    {
        "{\"TomlText\":\"max_clients = 1\",\"BaseSha256\":\"abc\"}",
        "{\"TomlText\":123,\"BaseSha256\":[]}",   // type-swaps inside a registered DTO
        "{\"Enable\":\"yes\"}",                    // bool expected, string given
        "{\"WithKillSwitch\":null}",
        "{\"Kind\":{},\"Content\":true}",
        "{\"TempPath\":42,\"ExpectedTag\":{}}",
    };

    [Fact]
    [Trait("Category", "Fuzz")]
    public void DeserializeRequest_never_throws_on_arbitrary_text() =>
        Gen.String.Sample(RequestNeverThrows, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void DeserializeRequest_never_throws_on_hostile_json_fragments() =>
        // Random-length prefixes/suffixes around the hostile literals push the byte-cap, the
        // trailing-garbage guard, and the reader's error paths at once.
        Gen.Select(Gen.Int[0, HostileJsonFragments.Length - 1], Gen.String,
                (i, extra) => HostileJsonFragments[i] + extra)
            .Sample(RequestNeverThrows, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void DeserializePayload_never_throws_on_arbitrary_text() =>
        // The registered WriteConfigPayload reader path must be as total as the envelope path.
        Gen.String.Sample(PayloadNeverThrows, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void DeserializePayload_never_throws_on_typed_payload_shapes() =>
        Gen.Select(Gen.Int[0, TypedPayloadShapes.Length - 1], Gen.String,
                (i, extra) => TypedPayloadShapes[i] + extra)
            .Sample(PayloadNeverThrows, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Deserialize_never_throws_on_random_utf8_bytes() =>
        // Raw bytes decoded as UTF-8 (with replacement) reach the reader as genuinely arbitrary
        // text, including invalid sequences the char-based generator would not produce.
        Gen.Byte.Array.Select(b => Encoding.UTF8.GetString(b))
            .Sample(s => RequestNeverThrows(s) && PayloadNeverThrows(s), iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Depth_limit_is_enforced_and_never_stack_overflows() =>
        // Nesting from just under the cap to pathologically deep (1000). At or below MaxDepth the
        // envelope may parse to a value (unknown nested prop ignored) or reject; above it must
        // reject via a caught JsonException. In NO case may the call throw or blow the stack.
        Gen.Int[1, 1000].Sample(DepthIsBounded, iter: Fuzz.Iter);

    /// <summary>Totality oracle for the envelope. A throw fails the property; a null return (rejected)
    /// is a valid outcome for hostile input. When it ACCEPTS, the parsed Command must be a defined enum
    /// value would be over-strict (System.Text.Json admits out-of-range enum numbers), so the real
    /// post-condition asserted is simply non-null on accept - the point is that no exception escaped.</summary>
    private static bool RequestNeverThrows(string input)
    {
        var req = IpcSerializer.DeserializeRequest(input);
        return req is null || req.PayloadJson is null || req.PayloadJson.Length >= 0;
    }

    /// <summary>Totality oracle for a registered typed payload. Same contract: never throw. Both a null
    /// return (rejected) and a non-null DTO are legitimate - note the source-gen deserializer does NOT
    /// enforce record required-ness, so a JSON object lacking TomlText/BaseSha256 yields a non-null
    /// WriteConfigPayload with null fields (validation is the handler's job, not the serializer's). The
    /// property fails ONLY if the call throws; the field reads below just prove the result is usable.</summary>
    private static bool PayloadNeverThrows(string input)
    {
        var payload = IpcSerializer.DeserializePayload<WriteConfigPayload>(input);
        return payload is null || (payload.TomlText?.Length ?? 0) >= 0 || payload.BaseSha256 is null;
    }

    /// <summary>Depth oracle: build JSON nested <paramref name="depth"/> objects deep and assert the
    /// deserialize is bounded - it returns a value or null, but never throws (in particular never a
    /// StackOverflowException, which the MaxDepth=16 guard exists to prevent).</summary>
    private static bool DepthIsBounded(int depth)
    {
        var json = NestedJson(depth);
        var req = IpcSerializer.DeserializeRequest(json);
        var payload = IpcSerializer.DeserializePayload<WriteConfigPayload>(json);
        // Beyond the documented MaxDepth (16) the guard MUST reject (return null): a deeply nested
        // frame can never be a legitimate 2-field envelope, so acceptance past the cap would mean the
        // depth guard failed open. At or below the cap either outcome is acceptable (unknown nested
        // property is skipped). The load-bearing assertion is simply that neither call threw.
        if (depth > 16)
            return req is null && payload is null;
        return req is null || req.PayloadJson is null || req.PayloadJson.Length >= 0;
    }

    /// <summary>An object nested <paramref name="depth"/> levels deep under a repeated key, with a
    /// scalar at the core: {"a":{"a": ... 0 ... }}. Depth counts each opening brace as one level.</summary>
    private static string NestedJson(int depth)
    {
        var sb = new StringBuilder(depth * 5 + 8);
        for (var i = 0; i < depth; i++)
            sb.Append("{\"a\":");
        sb.Append('0');
        sb.Append('}', depth);
        return sb.ToString();
    }

    // ---- Concrete regression anchors ----

    [Theory]
    [InlineData("}{ not json")]
    [InlineData("")]
    [InlineData("null")]
    [InlineData("\"a string root\"")]
    [InlineData("[1,2,3]")]
    [InlineData("{\"Command\":NaN}")]
    [InlineData("{\"Command\":Infinity}")]
    [InlineData("\uFEFF{\"Command\":0}")]                 // BOM prefix (U+FEFF)
    [InlineData("{\"Command\":0} garbage")]               // trailing junk
    [InlineData("{\"Command\":99999999999999999999}")]    // number past int64
    public void DeserializeRequest_malformed_returns_null(string json)
        => Assert.Null(IpcSerializer.DeserializeRequest(json));

    [Fact]
    public void DeserializeRequest_null_input_is_null()
        => Assert.Null(IpcSerializer.DeserializeRequest(null!));

    [Theory]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(64)]
    [InlineData(1000)]
    public void Depth_beyond_cap_returns_null_without_throwing(int depth)
    {
        var json = NestedJson(depth);
        // Never throws; beyond the MaxDepth=16 cap the guard rejects (null).
        var req = IpcSerializer.DeserializeRequest(json);
        if (depth > 16)
            Assert.Null(req);
    }

    [Fact]
    public void CharLength_over_MaxBytes_is_rejected_before_encoding()
    {
        // A pure-ASCII string longer than MaxBytes trips the cheap char-length guard first.
        var huge = new string('a', IpcSerializer.MaxBytes + 1);
        Assert.Null(IpcSerializer.DeserializeRequest(huge));
    }

    [Fact]
    public void Utf8ByteLength_over_MaxBytes_is_rejected_even_when_charLength_fits()
    {
        // Multi-byte chars: char length can sit under MaxBytes while UTF-8 byte length exceeds it.
        // U+00E9 (e-acute) is 2 UTF-8 bytes, so half-MaxBytes+1 chars => over the byte cap.
        var chars = (IpcSerializer.MaxBytes / 2) + 1;
        var multibyte = new string('\u00E9', chars);
        Assert.True(multibyte.Length <= IpcSerializer.MaxBytes, "char length must fit to exercise the byte-length guard");
        Assert.True(Encoding.UTF8.GetByteCount(multibyte) > IpcSerializer.MaxBytes);
        Assert.Null(IpcSerializer.DeserializeRequest(multibyte));
    }

    [Fact]
    public void UnregisteredType_returns_default_without_throwing()
    {
        // CallerIdentity is a real Ipc type but is NOT a registered [JsonSerializable] DTO, so the
        // TypeInfo<T>() lookup throws NotSupportedException, which the serializer catches -> default.
        // For an unconstrained generic value type, T? collapses to T, so default(T) (not null) is the
        // fail-closed sentinel; the load-bearing invariant is that the call did not throw.
        var result = IpcSerializer.DeserializePayload<CallerIdentity>("{\"ProcessId\":1,\"ImagePath\":\"x\"}");
        Assert.Equal(default, result);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(int.MaxValue)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Command_number_across_the_int_range_never_throws(int command)
    {
        // Command is an enum serialized as a number; System.Text.Json admits any in-range int (even
        // ones outside the defined vocabulary). The parse must never throw regardless.
        var req = IpcSerializer.DeserializeRequest($"{{\"Command\":{command},\"PayloadJson\":null}}");
        // Either accepted (undefined enum value tolerated) or rejected; the point is no throw above.
        if (req is not null)
            Assert.Equal(command, (int)req.Command);
    }
}
