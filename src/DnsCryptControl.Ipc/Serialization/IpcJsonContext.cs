using System.Text.Json.Serialization;
using DnsCryptControl.Ipc.Commands;

namespace DnsCryptControl.Ipc.Serialization;

/// <summary>
/// Source-generated serialization context. Only the explicitly listed DTO types can
/// ever be (de)serialized — there is no reflection-based type discovery and no
/// payload-driven polymorphism, which closes the CWE-502 deserialization surface.
/// </summary>
// PropertyNameCaseInsensitive = false is intentional hardening for the trust boundary (no case-confusion).
[JsonSourceGenerationOptions(
    WriteIndented = false,
    PropertyNameCaseInsensitive = false,
    DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    MaxDepth = 16)]
// Phase 2: add a Result<T> [JsonSerializable] registration for each verb's response payload type as those are introduced.
[JsonSerializable(typeof(IpcRequest))]
[JsonSerializable(typeof(WriteConfigPayload))]
[JsonSerializable(typeof(WriteRuleFilePayload))]
[JsonSerializable(typeof(SetTogglePayload))]
[JsonSerializable(typeof(VerifyAndInstallBinaryPayload))]
[JsonSerializable(typeof(StatusResponse))]
[JsonSerializable(typeof(Result))]
[JsonSerializable(typeof(Result<StatusResponse>))]
[JsonSerializable(typeof(ServiceLifecycleResponse))]
[JsonSerializable(typeof(Result<ServiceLifecycleResponse>))]
[JsonSerializable(typeof(LeakMitigationResponse))]
[JsonSerializable(typeof(Result<LeakMitigationResponse>))]
[JsonSerializable(typeof(EnableProtectionPayload))]
[JsonSerializable(typeof(ProtectionResponse))]
[JsonSerializable(typeof(Result<ProtectionResponse>))]
[JsonSerializable(typeof(DnsCryptControl.Platform.Diagnostics.DiagnosticsSnapshot))]
[JsonSerializable(typeof(Result<DnsCryptControl.Platform.Diagnostics.DiagnosticsSnapshot>))]
// v4 (FIX #1): the VerifyResolution verb's response. BOTH registrations are required — omitting
// either is a SILENT serialize failure (source-gen only, reflection off).
[JsonSerializable(typeof(DnsCryptControl.Platform.Diagnostics.ResolveVerification))]
[JsonSerializable(typeof(Result<DnsCryptControl.Platform.Diagnostics.ResolveVerification>))]
internal sealed partial class IpcJsonContext : JsonSerializerContext
{
}
