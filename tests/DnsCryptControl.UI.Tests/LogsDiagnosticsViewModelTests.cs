using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.Tests.Fakes;
using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// Phase 5e Group C: <see cref="LogsDiagnosticsViewModel"/> — the operational Logs &amp; Diagnostics tab
/// (design 3.1/3.2). Proves:
/// <list type="bullet">
///   <item><b>Health projection (3.1):</b> the snapshot mirrors the SAME read-only <see cref="StatusResponse"/>
///     + off-disk protection intent the Dashboard consumes; a helper fault degrades to
///     "unreachable/unknown" instead of throwing.</item>
///   <item><b>Proxy-log capture (3.2):</b> enabling sets <c>log_file</c>/<c>log_level</c> via the existing
///     config Save path and reflects the "captured" state + tail; disabling unsets it; off = "not captured".</item>
///   <item><b>CopyDiagnostics EXCLUDES query data (IC-QM6):</b> the health text bundle contains the health
///     fields and NONE of the query-stream fields (domains/clients/actions).</item>
/// </list>
///
/// <para>Pure-POCO/IC-5: no WPF types, a <c>SynchronousDispatcher</c>, injected fakes — deterministic, no sleeps.</para>
/// </summary>
public class LogsDiagnosticsViewModelTests
{
    private static readonly string Sha = new('a', 64);

    // ------------------------------------------------------------------ fixtures

    private sealed class SynchronousDispatcher : IUiDispatcher
    {
        public void Post(Action action) => action();
    }

    private sealed class FakeStateReader : IProtectionStateReader
    {
        public ProtectionIntent Intent { get; set; } = new(false, false, false);

        public ProtectionIntent Read() => Intent;
    }

    private sealed class FakeConfigFileService : IConfigFileService
    {
        public Queue<ConfigLoadResult> LoadQueue { get; } = new();
        public ConfigLoadResult NextLoad { get; set; } = ConfigLoadResult.Ok(string.Empty, Sha);
        public List<(string Text, string BaseSha256)> SaveCalls { get; } = new();
        public Func<string, string, CancellationToken, Task<ConfigSaveOutcome>>? SaveHandler { get; set; }

        public ConfigLoadResult Load() => LoadQueue.Count > 0 ? LoadQueue.Dequeue() : NextLoad;

        public Task<ConfigSaveOutcome> SaveAndApplyAsync(string candidateText, string baseSha256, CancellationToken ct)
        {
            SaveCalls.Add((candidateText, baseSha256));
            return SaveHandler?.Invoke(candidateText, baseSha256, ct)
                ?? Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));
        }
    }

    private sealed class FakeLogTailReader : ILogTailReader
    {
        public IReadOnlyList<string> Tail { get; set; } = Array.Empty<string>();
        public List<(string Path, int MaxLines)> Calls { get; } = new();

        public IReadOnlyList<string> ReadTail(string path, int maxLines)
        {
            Calls.Add((path, maxLines));
            return Tail;
        }
    }

    private sealed class FakeResolverReader : IActiveResolverReader
    {
        public string? Name { get; set; }

        public string? ReadPrimaryName() => Name;
    }

    private sealed class Harness
    {
        public FakeHelperClient Helper { get; } = new();
        public FakeStateReader State { get; } = new();
        public FakeResolverReader Resolver { get; } = new();
        public FakeConfigFileService Config { get; } = new();
        public FakeLogTailReader LogTail { get; } = new();
        public LogsDiagnosticsViewModel Vm { get; }

        public Harness()
        {
            // The proxy-log confinement base matches the test log_file (C:\pd\...) so the capture-tail
            // tests exercise the real ReadTail path; the arbitrary-file-read guard itself is fuzzed +
            // regression-tested against LogFilePathGuard directly (finding 2026-07-08).
            Vm = new LogsDiagnosticsViewModel(Helper, State, Resolver, Config, LogTail, new SynchronousDispatcher(), @"C:\pd");
        }
    }

    // ------------------------------------------------------------------ health projection (3.1)

    [Fact]
    public async Task refresh_projects_status_and_protection_intent()
    {
        var h = new Harness();
        h.State.Intent = new ProtectionIntent(ProtectionEnabled: true, KillSwitchEnabled: true, LeakMitigationsEnabled: false);
        h.Resolver.Name = "cloudflare"; // ActiveResolver reads from the resolver reader (like the Dashboard)
        h.Helper.GetStatusHandler = _ => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(
                ProxyRunning: true, ActiveResolver: "status-side-ignored", KillSwitchEnabled: true,
                LeakMitigationsEnabled: false, ProtocolVersion: IpcProtocol.Version, HelperBuild: "1.2.3")));

        await h.Vm.RefreshAsync(CancellationToken.None);

        Assert.True(h.Vm.HelperReachable);
        Assert.True(h.Vm.ProxyRunning);
        Assert.True(h.Vm.ProtectionEnabled);
        Assert.True(h.Vm.KillSwitchEnabled);
        Assert.False(h.Vm.LeakMitigationsEnabled);
        Assert.Equal("cloudflare", h.Vm.ActiveResolver);
        Assert.Equal("1.2.3", h.Vm.HelperBuild);
        Assert.False(h.Vm.HelperVersionMismatch);
        Assert.NotNull(h.Vm.LastRefreshedUtc);
    }

    [Fact]
    public async Task active_resolver_comes_from_the_reader_not_the_status_matching_the_dashboard()
    {
        // Regression for VM finding 5e-VM-1: the Logs health showed "(none)" (the helper's
        // StatusResponse.ActiveResolver came back empty) while the Dashboard showed the real resolver,
        // because the two read the active resolver from DIFFERENT sources. Both must use
        // IActiveResolverReader so the views never disagree (checklist §1.2 "health matches the Dashboard").
        var h = new Harness();
        h.Resolver.Name = "a-and-a";
        h.Helper.GetStatusHandler = _ => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(
                ProxyRunning: true, ActiveResolver: "", KillSwitchEnabled: true,
                LeakMitigationsEnabled: true, ProtocolVersion: IpcProtocol.Version, HelperBuild: "1.0.0.0")));

        await h.Vm.RefreshAsync(CancellationToken.None);

        Assert.Equal("a-and-a", h.Vm.ActiveResolver);
        Assert.Contains("Active resolver: a-and-a", h.Vm.BuildDiagnosticsText());
    }

    [Fact]
    public async Task refresh_with_unreachable_helper_degrades_and_never_throws()
    {
        var h = new Harness();
        h.State.Intent = new ProtectionIntent(true, false, false);
        h.Helper.GetStatusHandler = _ => Task.FromResult<Result<StatusResponse>?>(null); // lost reply

        await h.Vm.RefreshAsync(CancellationToken.None);

        Assert.False(h.Vm.HelperReachable);
        Assert.False(h.Vm.ProxyRunning);
        // Off-disk intent is still authoritative even when the helper is down.
        Assert.True(h.Vm.ProtectionEnabled);
        Assert.Empty(h.Vm.HelperBuild);
    }

    [Fact]
    public async Task refresh_flags_a_protocol_version_mismatch()
    {
        var h = new Harness();
        h.Helper.GetStatusHandler = _ => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(
                true, "r", false, false, ProtocolVersion: IpcProtocol.Version + 1, HelperBuild: "x")));

        await h.Vm.RefreshAsync(CancellationToken.None);

        Assert.True(h.Vm.HelperReachable);
        Assert.True(h.Vm.HelperVersionMismatch);
    }

    // ------------------------------------------------------------------ proxy-log capture (3.2)

    [Fact]
    public async Task capture_off_by_default_shows_not_captured_banner()
    {
        var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok("listen_addresses = ['127.0.0.1:53']\n", Sha);

        await h.Vm.RefreshAsync(CancellationToken.None);

        Assert.False(h.Vm.ProxyLogCaptured);
        Assert.NotNull(h.Vm.NotCapturedBanner);
        Assert.Null(h.Vm.ProxyLogPath);
        Assert.Empty(h.Vm.ProxyLogTail);
    }

    [Fact]
    public async Task enable_capture_writes_log_file_and_reflects_captured_state_with_tail()
    {
        var h = new Harness();
        // Refresh sees no capture; enable's RMW re-reads a bare config; the post-write reload sees the key.
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok(string.Empty, Sha));   // RefreshAsync capture-state read
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok(string.Empty, Sha));   // PrepareCaptureWrite read
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("log_file = 'C:\\\\pd\\\\dnscrypt-proxy.log'\n", Sha)); // post-write reload
        h.LogTail.Tail = new[] { "[NOTICE] dnscrypt-proxy started", "[NOTICE] dns64 not enabled" };

        await h.Vm.RefreshAsync(CancellationToken.None);
        Assert.False(h.Vm.ProxyLogCaptured);

        await h.Vm.EnableProxyLogCaptureAsync(CancellationToken.None);

        var saved = Assert.Single(h.Config.SaveCalls);
        Assert.Contains("log_file", saved.Text);
        Assert.Contains("log_level", saved.Text);
        Assert.True(h.Vm.ProxyLogCaptured);
        Assert.Null(h.Vm.NotCapturedBanner);
        Assert.Equal(2, h.Vm.ProxyLogTail.Count);
        Assert.Equal("[NOTICE] dnscrypt-proxy started", h.Vm.ProxyLogTail[0]);
    }

    [Fact]
    public async Task disable_capture_unsets_log_file()
    {
        var h = new Harness();
        // Refresh sees capture ON.
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("log_file = 'C:\\\\pd\\\\dnscrypt-proxy.log'\n", Sha));
        await h.Vm.RefreshAsync(CancellationToken.None);
        Assert.True(h.Vm.ProxyLogCaptured);

        // Disable's RMW re-reads the config that HAS the key, then the post-write reload sees it gone.
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("log_file = 'C:\\\\pd\\\\dnscrypt-proxy.log'\n", Sha));
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok(string.Empty, Sha));
        await h.Vm.DisableProxyLogCaptureAsync(CancellationToken.None);

        var saved = Assert.Single(h.Config.SaveCalls);
        Assert.DoesNotContain("log_file", saved.Text);
        Assert.False(h.Vm.ProxyLogCaptured);
        Assert.NotNull(h.Vm.NotCapturedBanner);
    }

    [Fact]
    public async Task enable_capture_rejected_by_helper_surfaces_error_and_stays_off()
    {
        var h = new Harness();
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok(string.Empty, Sha)); // refresh
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok(string.Empty, Sha)); // prepare
        h.Config.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Rejected, "helper refused"));

        await h.Vm.RefreshAsync(CancellationToken.None);
        await h.Vm.EnableProxyLogCaptureAsync(CancellationToken.None);

        Assert.False(h.Vm.ProxyLogCaptured);
        Assert.Contains("helper refused", h.Vm.ConfigError);
    }

    // ------------------------------------------------------------------ CopyDiagnostics excludes query data (IC-QM6)

    [Fact]
    public async Task diagnostics_text_contains_health_and_no_query_data()
    {
        var h = new Harness();
        h.State.Intent = new ProtectionIntent(true, true, true);
        h.Helper.GetStatusHandler = _ => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(
                true, "cloudflare", true, true, IpcProtocol.Version, "1.2.3")));
        await h.Vm.RefreshAsync(CancellationToken.None);

        var text = h.Vm.BuildDiagnosticsText();

        // Health fields ARE present.
        Assert.Contains("Protection enabled: yes", text);
        Assert.Contains("Kill switch enabled: yes", text);
        Assert.Contains("Proxy running: yes", text);
        Assert.Contains("1.2.3", text);

        // The load-bearing IC-QM6 assertion: NO query-stream fields leaked in. We fed a query-shaped
        // domain nowhere, so assert the bundle carries none of the query column concepts.
        Assert.DoesNotContain("REJECT", text, StringComparison.Ordinal);
        Assert.DoesNotContain("CLOAK", text, StringComparison.Ordinal);
        Assert.DoesNotContain("qname", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("query.log", text, StringComparison.OrdinalIgnoreCase);
        // And it says so explicitly.
        Assert.Contains("excludes all", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void diagnostics_text_before_any_refresh_never_throws()
    {
        var h = new Harness();

        var text = h.Vm.BuildDiagnosticsText();

        Assert.Contains("Helper reachable: no", text);
    }
}
