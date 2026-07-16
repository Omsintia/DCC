using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.ViewModels;
using DnsCryptControl.UI.Tests.Fakes;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// E1: (1) the UI-side mirror pin of <see cref="IpcProtocol.Version"/> (the mechanical Phase-5c
/// no-diff gate that once lived here is retired - the wire-version-pin comment below records the
/// history); (2) an end-to-end adversarial pass through the REAL stack (real ResolverListReader
/// to real Core parser to real ResolversViewModel) proving a hostile list name can never be
/// written into config.
/// </summary>
public class Phase5cGateTests
{
    private const string DohCloudflare = "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5";
    private const string Sha = "0000000000000000000000000000000000000000000000000000000000000000";

    // ---- wire-version pin ----
    // HISTORY: the Phase-5c gate asserted the mechanical IC-2 invariant - Phase 5c made NO behavioral
    // change to Ipc/Service/Platform, the sole permitted touch being the one comment-only RS0030
    // pragma in LoopbackResolveProbe.cs.
    // The Phase-5c "no privileged-tree diff" mechanical gate that lived here was RETIRED post-5j: the
    // ODoH fix deliberately added the PlaceOdohCache verb (helper places bundled signed ODoH caches so
    // the proxy never does the boot-time download it treats as FATAL). The verb-vocabulary + protocol
    // pins in the Ipc.Tests project (IpcMessagesTests / IpcProtocolTests / FrozenWireDiffGateTests) are
    // the living guard against ACCIDENTAL wire drift; this UI-side pin just mirrors the version.

    [Fact]
    public void IpcProtocolVersion_isAt4()
    {
        // v3 → v4: the v1.2.0 FIX #1 VerifyResolution verb (post-apply real-name resolve check).
        Assert.Equal(4, IpcProtocol.Version);
    }

    // ---- end-to-end adversarial: hostile list name cannot be written into config ----

    [Fact]
    public async Task hostileListName_fromTheRealReader_isRendered_butCannotBePickedIntoConfig()
    {
        var dir = Path.Combine(Path.GetTempPath(), "e2e-" + Path.GetRandomFileName());
        Directory.CreateDirectory(dir);
        try
        {
            var config = "[sources]\n[sources.'public-resolvers']\ncache_file = 'public-resolvers.md'\n";
            File.WriteAllText(Path.Combine(dir, "dnscrypt-proxy.toml"), config);
            File.WriteAllText(Path.Combine(dir, "public-resolvers.md"),
                "## bad\"name\n\nhostile entry\n" + DohCloudflare + "\n" +
                "## cloudflare\n\nclean entry\n" + DohCloudflare + "\n");

            // Real reader + real Core parser; only the pipe-facing seams are faked.
            var reader = new ResolverListReader(Path.Combine(dir, "dnscrypt-proxy.toml"), dir, bundledSnapshotDir: null);
            var vm = new ResolversViewModel(
                new StubConfigFile(config),
                reader,
                new FakeHelperClient
                {
                    GetStatusHandler = _ => Task.FromResult<Result<StatusResponse>?>(
                        Result<StatusResponse>.Ok(new StatusResponse(true, "r", false, false, IpcProtocol.Version, "1.0"))),
                },
                new StubUiStateStore(),
                new InlineDispatcher(),
                new StubProber(),
                new StubGate());

            await vm.LoadAsync(CancellationToken.None);

            // Both entries render...
            Assert.Equal(2, vm.Rows.Count);
            var hostile = vm.Rows.Single(r => r.Name == "bad\"name");
            var clean = vm.Rows.Single(r => r.Name == "cloudflare");

            // ...but the hostile name fails the IC-7 allowlist end-to-end and can't be picked into config.
            Assert.False(hostile.IsSelectable);
            Assert.True(clean.IsSelectable);

            vm.UseOnlyThisServer(hostile);
            Assert.False(vm.IsDirty);                 // refused — nothing staged
            Assert.NotNull(vm.SaveBlockedReason);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }

    // ---- minimal seams (the pipe-facing dependencies only) ----

    private sealed class StubConfigFile : IConfigFileService
    {
        private readonly string _text;
        public StubConfigFile(string text) => _text = text;
        public ConfigLoadResult Load() => ConfigLoadResult.Ok(_text, Sha);
        public Task<ConfigSaveOutcome> SaveAndApplyAsync(string candidateText, string baseSha256, CancellationToken ct)
            => throw new NotSupportedException("save is not exercised by this gate test");
    }

    private sealed class StubUiStateStore : IUiStateStore
    {
        public DnsCryptControl.UI.Models.UiState Load() => new();
        public void Save(DnsCryptControl.UI.Models.UiState state) { }
    }

    private sealed class InlineDispatcher : IUiDispatcher
    {
        public void Post(Action action) => action();
    }

    private sealed class StubProber : ILatencyProber
    {
        public Task<System.Collections.Generic.IReadOnlyList<ProbeResult>> ProbeAsync(
            System.Collections.Generic.IReadOnlyList<ProbeTarget> targets, IProgress<ProbeResult>? progress, CancellationToken ct)
            => Task.FromResult<System.Collections.Generic.IReadOnlyList<ProbeResult>>(Array.Empty<ProbeResult>());
    }

    private sealed class StubGate : IProbeGate
    {
        public bool IsProbingAllowed => true;
    }

}
