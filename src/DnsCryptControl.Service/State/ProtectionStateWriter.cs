using System;
using System.IO;
using System.Runtime.Versioning;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Service.State;

/// <summary>Service-side <see cref="IProtectionStateWriter"/> over <see cref="ProtectionStateStore"/>.
/// Each method is an atomic field flip via <see cref="ProtectionStateStore.Update"/>; a write failure
/// (disk/ACL) is caught and surfaced as a fail-closed <see cref="PlatformResult"/> so the IPC handler
/// denies the operation rather than reporting durable protection it could not record.</summary>
[SupportedOSPlatform("windows")]
public sealed class ProtectionStateWriter : IProtectionStateWriter
{
    private readonly ProtectionStateStore _store;

    public ProtectionStateWriter(ProtectionStateStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _store = store;
    }

    /// <inheritdoc/>
    public PlatformResult EnableProtection() => Persist(s => s with { ProtectionEnabled = true });

    /// <inheritdoc/>
    public PlatformResult DisableProtection() => Persist(s => s with { ProtectionEnabled = false });

    /// <inheritdoc/>
    public PlatformResult SetKillSwitchEnabled(bool enabled) => Persist(s => s with { KillSwitchEnabled = enabled });

    /// <inheritdoc/>
    public PlatformResult SetLeakMitigationsEnabled(bool enabled) => Persist(s => s with { LeakMitigationsEnabled = enabled });

    private PlatformResult Persist(Func<ProtectionState, ProtectionState> transform)
    {
        try
        {
            _store.Update(transform);
            return PlatformResult.Ok();
        }
        catch (IOException ex)
        {
            return PlatformResult.Fail(PlatformErrorKind.OperationFailed, $"persist protection state failed: {ex.Message}");
        }
        catch (UnauthorizedAccessException ex)
        {
            return PlatformResult.Fail(PlatformErrorKind.OperationFailed, $"persist protection state failed: {ex.Message}");
        }
    }
}
