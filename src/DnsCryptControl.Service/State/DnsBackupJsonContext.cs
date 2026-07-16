using System.Text.Json.Serialization;

namespace DnsCryptControl.Service.State;

// Source-gen (no reflection): trim/AOT-safe and avoids the banned serializers. UseStringEnumConverter
// writes RegistryValueKind as a stable string. The generator walks DnsBackupState's full record/list graph.
[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UseStringEnumConverter = true)]
[JsonSerializable(typeof(DnsBackupState))]
internal sealed partial class DnsBackupJsonContext : JsonSerializerContext
{
}
