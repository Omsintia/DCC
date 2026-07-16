using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Platform.Diagnostics;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests.Fakes;

/// <summary>
/// Fake <see cref="IHelperClient"/> whose every method is individually
/// scriptable/recordable so tests can assert exactly which verbs were called, with
/// what argument, and in the presence of artificial delay (for the in-flight-lock
/// test). Promoted out of <c>DashboardViewModelTests</c> (D1) because the
/// Configuration-module tests need scripted <c>WriteConfigAsync</c>/<c>RestartProxyAsync</c>/
/// <c>GetStatusAsync</c> too.
/// </summary>
internal sealed class FakeHelperClient : IHelperClient
{
    public List<bool> EnableCalls { get; } = new();
    public int DisableCalls { get; private set; }
    public int GetStatusCalls { get; private set; }
    public int RunDiagnosticsCalls { get; private set; }
    public int RestartProxyCalls { get; private set; }

    /// <summary>Per-call argument record: E3's double-save test asserts the exact
    /// (text, sha) pair each save carried.</summary>
    public List<(string TomlText, string BaseSha256)> WriteConfigCalls { get; } = new();

    /// <summary>Per-call (kind, content) record so the Phase 5d Filtering tests can assert
    /// the exact rule-file writes and their ordering.</summary>
    public List<(string Kind, string Content)> WriteRuleFileCalls { get; } = new();

    /// <summary>Phase 5f: uninstall-proxy call count.</summary>
    public int UninstallProxyServiceCalls { get; private set; }

    /// <summary>Phase 5f: each SetBrowserDohPolicy enable-flag, in call order.</summary>
    public List<bool> SetBrowserDohCalls { get; } = new();

    /// <summary>Ordered log of teardown-relevant calls ("Disable"/"Uninstall"/"SetBrowserDoh") so a
    /// reset test can assert Disable precedes Uninstall (the fail-closed teardown ordering).</summary>
    public List<string> CallOrder { get; } = new();

    public Func<CancellationToken, Task<Result<StatusResponse>?>>? GetStatusHandler { get; set; }
    public Func<bool, CancellationToken, Task<Result<ProtectionResponse>?>>? EnableHandler { get; set; }
    public Func<CancellationToken, Task<Result<ProtectionResponse>?>>? DisableHandler { get; set; }
    public Func<CancellationToken, Task<Result<DiagnosticsSnapshot>?>>? RunDiagnosticsHandler { get; set; }
    public Func<CancellationToken, Task<Result<ServiceLifecycleResponse>?>>? RestartProxyHandler { get; set; }
    public Func<string, string, CancellationToken, Task<Result?>>? WriteConfigHandler { get; set; }
    public Func<string, string, CancellationToken, Task<Result?>>? WriteRuleFileHandler { get; set; }
    public Func<CancellationToken, Task<Result?>>? UninstallProxyServiceHandler { get; set; }
    public Func<bool, CancellationToken, Task<Result?>>? SetBrowserDohHandler { get; set; }

    public Task<Result<StatusResponse>?> GetStatusAsync(CancellationToken ct)
    {
        GetStatusCalls++;
        return GetStatusHandler?.Invoke(ct)
            ?? Task.FromResult<Result<StatusResponse>?>(
                Result<StatusResponse>.Ok(new StatusResponse(true, "resolver", false, false, IpcProtocol.Version, "1.0.0")));
    }

    public Task<Result<ProtectionResponse>?> EnableProtectionAsync(bool withKillSwitch, CancellationToken ct)
    {
        EnableCalls.Add(withKillSwitch);
        return EnableHandler?.Invoke(withKillSwitch, ct)
            ?? Task.FromResult<Result<ProtectionResponse>?>(
                Result<ProtectionResponse>.Ok(new ProtectionResponse(true, withKillSwitch, true, false, null)));
    }

    public Task<Result<ProtectionResponse>?> DisableProtectionAsync(CancellationToken ct)
    {
        DisableCalls++;
        CallOrder.Add("Disable");
        return DisableHandler?.Invoke(ct)
            ?? Task.FromResult<Result<ProtectionResponse>?>(
                Result<ProtectionResponse>.Ok(new ProtectionResponse(false, false, false, false, null)));
    }

    public Task<Result<DiagnosticsSnapshot>?> RunDiagnosticsAsync(CancellationToken ct)
    {
        RunDiagnosticsCalls++;
        return RunDiagnosticsHandler?.Invoke(ct)
            ?? Task.FromResult<Result<DiagnosticsSnapshot>?>(Result<DiagnosticsSnapshot>.Ok(MakeSnapshot()));
    }

    /// <summary>v4 (FIX #1): post-apply resolve-verification call count + scriptable handler. The
    /// unscripted default is a RESOLVED route (so pre-existing save tests keep their no-warning
    /// behavior); a dead-route test scripts <c>Ok(new ResolveVerification(false, ...))</c> and an
    /// unavailable-check test scripts a failed Result or a null reply.</summary>
    public int VerifyResolutionCalls { get; private set; }
    public Func<CancellationToken, Task<Result<ResolveVerification>?>>? VerifyResolutionHandler { get; set; }

    public Task<Result<ResolveVerification>?> VerifyResolutionAsync(CancellationToken ct)
    {
        VerifyResolutionCalls++;
        return VerifyResolutionHandler?.Invoke(ct)
            ?? Task.FromResult<Result<ResolveVerification>?>(
                Result<ResolveVerification>.Ok(new ResolveVerification(true, 120, "RCODE=3, ancount=0")));
    }

    public Task<Result<ServiceLifecycleResponse>?> RestartProxyAsync(CancellationToken ct)
    {
        RestartProxyCalls++;
        return RestartProxyHandler?.Invoke(ct)
            ?? Task.FromResult<Result<ServiceLifecycleResponse>?>(
                Result<ServiceLifecycleResponse>.Ok(new ServiceLifecycleResponse("Running")));
    }

    public Task<Result?> WriteConfigAsync(string tomlText, string baseSha256, CancellationToken ct)
    {
        WriteConfigCalls.Add((tomlText, baseSha256));
        return WriteConfigHandler?.Invoke(tomlText, baseSha256, ct)
            ?? Task.FromResult<Result?>(Result.Ok());
    }

    public Task<Result?> WriteRuleFileAsync(string kind, string content, CancellationToken ct)
    {
        WriteRuleFileCalls.Add((kind, content));
        return WriteRuleFileHandler?.Invoke(kind, content, ct)
            ?? Task.FromResult<Result?>(Result.Ok());
    }

    public Task<Result?> FlushDnsCacheAsync(CancellationToken ct) =>
        Task.FromResult<Result?>(Result.Ok());

    public Task<Result?> UninstallProxyServiceAsync(CancellationToken ct)
    {
        UninstallProxyServiceCalls++;
        CallOrder.Add("Uninstall");
        return UninstallProxyServiceHandler?.Invoke(ct) ?? Task.FromResult<Result?>(Result.Ok());
    }

    public Task<Result?> SetBrowserDohPolicyAsync(bool enable, CancellationToken ct)
    {
        SetBrowserDohCalls.Add(enable);
        CallOrder.Add("SetBrowserDoh");
        return SetBrowserDohHandler?.Invoke(enable, ct) ?? Task.FromResult<Result?>(Result.Ok());
    }

    /// <summary>Post-5j ODoH fix: place-cache call count + a scriptable handler (null reply / failure
    /// exercises the "don't add sources unless the cache landed" guard). Recorded in
    /// <see cref="CallOrder"/> so a test can assert PlaceOdohCache precedes the source WriteConfig.</summary>
    public int PlaceOdohCacheCalls { get; private set; }
    public Func<CancellationToken, Task<Result?>>? PlaceOdohCacheHandler { get; set; }

    public Task<Result?> PlaceOdohCacheAsync(CancellationToken ct)
    {
        PlaceOdohCacheCalls++;
        CallOrder.Add("PlaceOdohCache");
        return PlaceOdohCacheHandler?.Invoke(ct) ?? Task.FromResult<Result?>(Result.Ok());
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    /// <summary>Builds a diagnostics snapshot whose overall health follows the two
    /// knobs — the default (all pass) is what the fake's unscripted
    /// <see cref="RunDiagnosticsAsync"/> returns.</summary>
    public static DiagnosticsSnapshot MakeSnapshot(bool allLoopback = true, bool proxyAnswered = true, bool browserDoh = true)
    {
        var listeners = new ListenerCheck(HealthState.Pass, true, true, true, true, Array.Empty<string>());
        var activeResolve = new ActiveResolveCheck(
            proxyAnswered ? HealthState.Pass : HealthState.Fail, "example.com", proxyAnswered, 5, null);
        var activeResolveV6 = new ActiveResolveCheck(HealthState.Pass, "example.com", true, 5, null);
        var adapters = new AdapterDnsCheck(
            allLoopback ? HealthState.Pass : HealthState.Fail,
            allLoopback,
            new[] { new AdapterDnsEntry("Ethernet", "Ethernet adapter", "Up", new[] { "127.0.0.1" }, allLoopback) });
        var hardening = new HardeningCheck(HealthState.Pass, true, true, true, browserDoh, Array.Empty<string>());
        var overall = allLoopback && proxyAnswered ? HealthState.Pass : HealthState.Fail;
        return new DiagnosticsSnapshot(DateTimeOffset.UtcNow, overall, listeners, activeResolve, activeResolveV6, adapters, hardening);
    }
}
