using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Tests;

/// <summary>
/// B1: standalone coverage of the single Platform→wire error-code map every handler
/// translates through. The map carries a <c>_ =&gt; OperationFailed</c> default arm, so a
/// <see cref="PlatformErrorKind"/> member without an explicit arm silently degrades to
/// <see cref="IpcErrorCode.OperationFailed"/> — the Conflict rows below exist precisely
/// to catch that degradation for the BE-6 compare-and-swap contract.
/// </summary>
public class PlatformResultMappingTests
{
    [Theory]
    [InlineData(PlatformErrorKind.None, IpcErrorCode.None)]
    [InlineData(PlatformErrorKind.NotFound, IpcErrorCode.NotFound)]
    [InlineData(PlatformErrorKind.InvalidArgument, IpcErrorCode.ValidationFailed)]
    [InlineData(PlatformErrorKind.Timeout, IpcErrorCode.OperationFailed)]
    [InlineData(PlatformErrorKind.OperationFailed, IpcErrorCode.OperationFailed)]
    [InlineData(PlatformErrorKind.Conflict, IpcErrorCode.Conflict)]
    public void EveryPlatformErrorKind_mapsToItsWireCode(PlatformErrorKind kind, IpcErrorCode expected)
    {
        Assert.Equal(expected, PlatformResultMapping.ToIpc(kind));
    }

    [Fact]
    public void Conflict_isTheOnlyKind_thatMapsToWireConflict()
    {
        // Conflict must never fall through to the OperationFailed default arm, and no
        // other kind may claim the Conflict wire code (the UI treats it as "reload").
        foreach (var kind in Enum.GetValues<PlatformErrorKind>())
        {
            var mapped = PlatformResultMapping.ToIpc(kind);
            Assert.Equal(kind == PlatformErrorKind.Conflict, mapped == IpcErrorCode.Conflict);
        }
    }
}
