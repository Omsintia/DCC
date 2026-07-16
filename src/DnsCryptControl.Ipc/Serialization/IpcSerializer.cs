using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using DnsCryptControl.Ipc.Commands;

namespace DnsCryptControl.Ipc.Serialization;

/// <summary>
/// Serialize/deserialize IPC messages using only the source-generated context.
/// Enforces a hard byte cap and a shallow MaxDepth so a malicious/huge frame cannot
/// exhaust resources in the privileged helper (CWE-400). All deserialize paths fail
/// closed (return null/default) instead of throwing.
/// </summary>
public static class IpcSerializer
{
    /// <summary>Maximum accepted frame size in bytes (covers a large TOML payload, not unbounded).</summary>
    public const int MaxBytes = 1_048_576; // 1 MiB

    // Both this pre-pass reader and IpcJsonContext [JsonSourceGenerationOptions] cap depth at 16, enforcing the limit consistently.
    private static readonly JsonReaderOptions ReaderGuard = new() { MaxDepth = 16 };

    public static string Serialize(IpcRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return JsonSerializer.Serialize(request, IpcJsonContext.Default.IpcRequest);
    }

    public static string SerializePayload<T>(T payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return JsonSerializer.Serialize(payload, TypeInfo<T>());
    }

    public static IpcRequest? DeserializeRequest(string json) =>
        Deserialize(json, IpcJsonContext.Default.IpcRequest);

    public static T? DeserializePayload<T>(string json)
    {
        JsonTypeInfo<T> typeInfo;
        try
        {
            typeInfo = TypeInfo<T>();
        }
        catch (NotSupportedException)
        {
            return default; // unregistered type: fail closed rather than throw out of the helper
        }
        catch (InvalidCastException)
        {
            return default;
        }

        return Deserialize(json, typeInfo);
    }

    private static T? Deserialize<T>(string json, JsonTypeInfo<T> typeInfo)
    {
        if (string.IsNullOrEmpty(json)) return default;

        // Cheap upper bound first: a UTF-8 byte count is always >= the UTF-16 code-unit
        // count, so an over-cap char length is already over-cap in bytes. Reject before
        // allocating the byte buffer.
        if (json.Length > MaxBytes) return default;

        byte[] utf8;
        try
        {
            utf8 = Encoding.UTF8.GetBytes(json);
        }
        catch (EncoderFallbackException)
        {
            return default;
        }

        if (utf8.Length > MaxBytes) return default;

        try
        {
            // Depth guard: reading through with MaxDepth=16 throws JsonException on too-deep input.
            var reader = new Utf8JsonReader(utf8, ReaderGuard);
            while (reader.Read()) { }

            // Reuse the SAME buffer for the actual deserialize (no second allocation of the input).
            return JsonSerializer.Deserialize(utf8, typeInfo);
        }
        catch (JsonException)
        {
            return default; // fail closed on malformed / too-deep input
        }
    }

    private static JsonTypeInfo<T> TypeInfo<T>()
    {
        var info = IpcJsonContext.Default.GetTypeInfo(typeof(T))
            ?? throw new NotSupportedException($"Type {typeof(T)} is not a registered IPC DTO.");
        return (JsonTypeInfo<T>)info;
    }
}
