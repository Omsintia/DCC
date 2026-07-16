using System.Collections.Generic;

namespace DnsCryptControl.Service.Windows;

/// <summary>The four raw, side-effecting observations RunDiagnostics needs. Extracted so the verdict
/// logic (DiagnosticsEvaluator) can be unit-tested with fakes while the live sockets/adapters/registry
/// implementation is exercised only under ManualIntegration.</summary>
internal interface IDnsProbeInputs
{
    ListenerObservation ObserveListeners();
    ActiveResolveObservation ObserveActiveResolve();     // 127.0.0.1:53
    ActiveResolveObservation ObserveActiveResolveV6();   // [::1]:53
    IReadOnlyList<AdapterObservation> ObserveAdapters();
    HardeningObservation ObserveHardening();
}
