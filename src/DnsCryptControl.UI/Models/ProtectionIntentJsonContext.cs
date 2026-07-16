using System.Text.Json.Serialization;

namespace DnsCryptControl.UI.Models;

/// <summary>
/// Source-gen (no reflection) context for <see cref="ProtectionIntent"/>. The naming
/// policy MUST match what <c>DnsCryptControl.Service.State.ProtectionStateStore</c>
/// actually writes on disk: camelCase, via
/// <c>JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)</c>
/// on the Service side. Verified by reading (not referencing) that file.
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ProtectionIntent))]
internal sealed partial class ProtectionIntentJsonContext : JsonSerializerContext
{
}
