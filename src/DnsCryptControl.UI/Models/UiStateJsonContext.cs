using System.Text.Json.Serialization;

namespace DnsCryptControl.UI.Models;

/// <summary>
/// Source-gen (no reflection) context for <see cref="UiState"/>, matching the reflection-free
/// JSON posture of the rest of the app (mirrors <see cref="ProtectionIntentJsonContext"/>).
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(UiState))]
internal sealed partial class UiStateJsonContext : JsonSerializerContext
{
}
