using DnsCryptControl.Core.Rules;
using DnsCryptControl.Core.Toml;
using DnsCryptControl.Platform;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.ViewModels;
using static DnsCryptControl.UI.ViewModels.FilteringViewModel;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// E1(d) — cross-family END-TO-END gate for the Filtering tab, one lens per assembly-line seam the
/// unit tests each cover in isolation, now proven together across ALL SIX families:
/// <list type="bullet">
///   <item><b>Ordered enable-and-wire with a no-hijack neighbour (IC-12):</b> in ONE fixture, enabling
///     an "ours" family writes its <c>.txt</c> BEFORE the <c>*_file</c> WriteConfig, while a sibling
///     family wired to a custom EXTERNAL path is never written and its key never staged.</item>
///   <item><b>TooLarge surfaced (IC-14):</b> a family Save whose body exceeds the 1 MiB frame yields
///     the TooLarge outcome and a per-family error, and the pipe is never touched.</item>
///   <item><b>Round-trip fixed point across every family (IC-4):</b> a combined fixture of realistic
///     per-family content holds <c>parse → serialize → parse</c> as a fixed point through each family's
///     codec — the model never lossily regenerates a user's file.</item>
/// </list>
///
/// <para>Uses the same fakes as <see cref="FilteringViewModelTests"/> (a synchronous dispatcher, a
/// never-firing editor debounce, a sequencer recording the interleave of the two write paths) so the
/// orchestration is deterministic with zero sleeps (IC-5).</para>
/// </summary>
public class FilteringCrossFamilyE2ETests
{
    private static readonly string Sha = new('a', 64);
    private static readonly TimeSpan NeverDebounce = Timeout.InfiniteTimeSpan;

    // ------------------------------------------------------------------ fakes (mirror FilteringViewModelTests)

    private sealed class SynchronousDispatcher : IUiDispatcher
    {
        public void Post(Action action) => action();
    }

    private sealed class Sequencer
    {
        public const int WriteRuleFile = 1;
        public const int WriteConfig = 2;
        public List<int> Order { get; } = new();
        public void Record(int step) => Order.Add(step);
    }

    private sealed class FakeConfigFileService : IConfigFileService
    {
        private readonly Sequencer _seq;
        public FakeConfigFileService(Sequencer seq) => _seq = seq;

        public ConfigLoadResult NextLoad { get; set; } = ConfigLoadResult.Fail("unscripted Load");
        public Queue<ConfigLoadResult> LoadQueue { get; } = new();
        public List<(string Text, string BaseSha256)> SaveCalls { get; } = new();

        public ConfigLoadResult Load() => LoadQueue.Count > 0 ? LoadQueue.Dequeue() : NextLoad;

        public Task<ConfigSaveOutcome> SaveAndApplyAsync(string candidateText, string baseSha256, CancellationToken ct)
        {
            SaveCalls.Add((candidateText, baseSha256));
            _seq.Record(Sequencer.WriteConfig);
            return Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));
        }
    }

    private sealed class FakeRuleFileService : IRuleFileService
    {
        private readonly Sequencer _seq;
        public FakeRuleFileService(Sequencer seq) => _seq = seq;

        public Dictionary<RuleFileKind, RuleFileSnapshot> Reads { get; } = new();
        public Dictionary<RuleFileKind, DateTime?> Mtimes { get; } = new();
        public List<(RuleFileKind Kind, string Content)> WriteCalls { get; } = new();
        public Func<RuleFileKind, string, Task<RuleFileWriteOutcome>>? WriteHandler { get; set; }

        public RuleFileSnapshot ReadRuleFile(RuleFileKind kind) =>
            Reads.TryGetValue(kind, out var snap) ? snap : new RuleFileSnapshot(string.Empty, RuleFileState.Missing, null);

        public DateTime? TryGetMtime(RuleFileKind kind) => Mtimes.TryGetValue(kind, out var m) ? m : null;

        public Task<RuleFileWriteOutcome> WriteRuleFileAsync(RuleFileKind kind, string content, CancellationToken ct)
        {
            WriteCalls.Add((kind, content));
            _seq.Record(Sequencer.WriteRuleFile);
            return WriteHandler?.Invoke(kind, content)
                ?? Task.FromResult(new RuleFileWriteOutcome(RuleFileWriteOutcomeKind.Applied, "saved"));
        }
    }

    private static IRuleFamilyCodec[] AllCodecs() => new IRuleFamilyCodec[]
    {
        new NameRuleFamilyCodec(RuleFileKind.BlockedNames),
        new NameRuleFamilyCodec(RuleFileKind.AllowedNames),
        new IpRuleFamilyCodec(RuleFileKind.BlockedIps),
        new IpRuleFamilyCodec(RuleFileKind.AllowedIps),
        new CloakRuleFamilyCodec(),
        new ForwardRuleFamilyCodec(),
    };

    private sealed class Harness : IDisposable
    {
        public Sequencer Seq { get; } = new();
        public FakeConfigFileService Config { get; }
        public FakeRuleFileService Rules { get; }
        public FilteringViewModel Vm { get; }

        public Harness()
        {
            Config = new FakeConfigFileService(Seq);
            Rules = new FakeRuleFileService(Seq);
            Vm = new FilteringViewModel(Config, Rules, AllCodecs(), new SynchronousDispatcher(), NeverDebounce);
        }

        public void Dispose() => Vm.Dispose();
    }

    private static string CanonicalPath(string leaf) => Path.Combine(UiPaths.ProgramDataDir, leaf);

    // ---------------------------------------------------- (1) ordered enable-and-wire beside a no-hijack sibling

    [Fact]
    public async Task enable_writes_txt_before_wiring_while_an_external_sibling_is_left_untouched()
    {
        using var h = new Harness();

        // allowed_names is wired to a CUSTOM external file the user manages; blocked_names is unwired
        // ("ours" to wire). Both loaded in one config.
        const string external = @"C:\Users\me\my-allowlist.txt";
        h.Config.NextLoad = ConfigLoadResult.Ok(
            $"[allowed_names]\nallowed_names_file = '{external}'\n", Sha);
        h.Rules.Reads[RuleFileKind.AllowedNames] =
            new RuleFileSnapshot("SHOULD NEVER BE READ OR WRITTEN", RuleFileState.Present, DateTime.UtcNow);

        await h.Vm.LoadAsync(CancellationToken.None);

        // The external sibling is read-only with a banner naming the external path.
        Assert.Contains(external, h.Vm.ExternalPathBanners[RuleFamily.AllowedNames]);

        var blocked = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames);
        blocked.Load("ads.example.com\n*.tracker.example\n");

        await h.Vm.EnableFamilyAsync(RuleFamily.BlockedNames, CancellationToken.None);

        // Only the ours-family .txt was written; the external sibling's file was never touched.
        var write = Assert.Single(h.Rules.WriteCalls);
        Assert.Equal(RuleFileKind.BlockedNames, write.Kind);
        Assert.DoesNotContain(h.Rules.WriteCalls, w => w.Kind == RuleFileKind.AllowedNames);
        Assert.True(h.Vm.IsDirty); // only the blocked_names *_file op is staged

        // Save the config: the WriteConfig fires and the recorded order proves the .txt write came
        // FIRST (the proxy is never wired to a missing file), and the external key was NOT restaged.
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok($"[allowed_names]\nallowed_names_file = '{external}'\n", Sha));
        await h.Vm.SaveConfigAsync(CancellationToken.None);

        Assert.Equal(new[] { Sequencer.WriteRuleFile, Sequencer.WriteConfig }, h.Seq.Order);

        var savedText = h.Config.SaveCalls.Single().Text;
        var doc = TomlConfigDocument.Parse(savedText);
        // The ours-family key was wired to our canonical path...
        Assert.True(doc.TryGetString("blocked_names.blocked_names_file", out var wired));
        Assert.Equal(CanonicalPath("blocked-names.txt"), wired);
        // ...and the external sibling's key is UNCHANGED (never hijacked).
        Assert.True(doc.TryGetString("allowed_names.allowed_names_file", out var untouched));
        Assert.Equal(external, untouched);
    }

    // ---------------------------------------------------- (2) TooLarge surfaced on a family Save

    [Fact]
    public async Task family_save_surfaces_TooLarge_without_wiring_or_touching_config()
    {
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok(string.Empty, Sha);
        await h.Vm.LoadAsync(CancellationToken.None);

        // The service reports TooLarge (the 1 MiB frame pre-check); the family Save must surface it.
        h.Rules.WriteHandler = (_, _) => Task.FromResult(
            new RuleFileWriteOutcome(
                RuleFileWriteOutcomeKind.TooLarge,
                "blocklist too large to send to the helper (limit 1 MiB per request) — split it, or reference it as an external file"));

        var blocked = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames);
        blocked.Load("ads.example.com\n");

        await h.Vm.SaveFamilyFileAsync(RuleFamily.BlockedNames, CancellationToken.None);

        Assert.Contains("too large", h.Vm.FamilyErrors[RuleFamily.BlockedNames]);
        Assert.False(h.Vm.FamilyNotices.ContainsKey(RuleFamily.BlockedNames)); // no success notice
        Assert.Empty(h.Config.SaveCalls); // a family Save never rides the config path
        Assert.False(h.Vm.IsDirty); // SaveFamilyFile does not stage the *_file key
    }

    // ---------------------------------------------------- (3) round-trip fixed point across all six families

    /// <summary>Realistic canonical-ish per-family content the codecs understand. The assertion below
    /// does NOT hard-code the canonical bytes (that is the Core round-trip tests' job) — it proves the
    /// IC-4 fixed-point PROPERTY: once serialized, re-parsing and re-serializing is byte-identical, and
    /// the content parsed into REAL rules (not everything degraded to Unparsed).</summary>
    private static readonly Dictionary<RuleFileKind, string> CombinedFixture = new()
    {
        [RuleFileKind.BlockedNames] =
            "# blocked names\nads.example.com\n*.tracker.example\n=exact.example\n\nmalware.example.org\n",
        [RuleFileKind.AllowedNames] =
            "# allowlist\nallowed.example.com\n*.cdn.example\n",
        [RuleFileKind.BlockedIps] =
            "# blocked ips\n10.0.0.0/8\n192.168.1.1\n",
        [RuleFileKind.AllowedIps] =
            "# allowed ips\n127.0.0.1\n::1\n",
        [RuleFileKind.Cloaking] =
            "# cloaking\nlocalhost 127.0.0.1\nexample.com 93.184.216.34\n",
        [RuleFileKind.Forwarding] =
            "# forwarding (order is load-bearing)\nexample.com 9.9.9.9\n*.internal.example 10.0.0.53,10.0.0.54\n",
    };

    [Theory]
    [InlineData(RuleFileKind.BlockedNames)]
    [InlineData(RuleFileKind.AllowedNames)]
    [InlineData(RuleFileKind.BlockedIps)]
    [InlineData(RuleFileKind.AllowedIps)]
    [InlineData(RuleFileKind.Cloaking)]
    [InlineData(RuleFileKind.Forwarding)]
    public void combined_fixture_holds_the_parse_serialize_parse_fixed_point_per_family(RuleFileKind kind)
    {
        var codec = AllCodecs().Single(c => c.Kind == kind);
        var input = CombinedFixture[kind];

        var first = codec.Parse(input);
        var second = codec.Parse(first.CanonicalText);

        // IC-4: the second serialization equals the first — parse∘serialize is idempotent (a fixed point).
        Assert.Equal(first.CanonicalText, second.CanonicalText);

        // The rows and findings survive the round-trip identically (structure is stable, not just bytes).
        Assert.Equal(first.Rows.Count, second.Rows.Count);
        for (var i = 0; i < first.Rows.Count; i++)
        {
            Assert.Equal(first.Rows[i].Kind, second.Rows[i].Kind);
            Assert.Equal(first.Rows[i].Text, second.Rows[i].Text);
        }

        // The fixture must actually parse into UNDERSTOOD rules for this family — otherwise the fixed
        // point would be trivially satisfied by everything degrading to Unparsed (the faked-seam trap).
        Assert.Contains(first.Rows, r => r.Kind == RuleRowKind.Rule);
        // And comments are preserved (never dropped), proving verbatim-preservation not lossy regen.
        Assert.Contains(first.Rows, r => r.Kind == RuleRowKind.Comment);
        // No fixture line degraded to an Error-lint (the content is all legal for its family).
        Assert.DoesNotContain(first.Findings, f => f.Severity == RuleLintSeverity.Error);
    }

    [Fact]
    public async Task combined_fixture_loads_across_all_six_editors_and_each_reports_its_rules()
    {
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok(string.Empty, Sha);
        await h.Vm.LoadAsync(CancellationToken.None);

        // Drive every editor with its fixture (as a user would after loading their real files) and
        // confirm each one parses cleanly with understood rules — the whole tab is coherent at once.
        foreach (var editor in h.Vm.Editors)
        {
            editor.Load(CombinedFixture[editor.Kind]);
            Assert.True(editor.IsValid, $"{editor.Kind} fixture should be lint-clean");
            Assert.Contains(editor.Rows, r => r.Kind == RuleRowKind.Rule);
        }

        // The per-family summaries (content-derived, IC-16) each report a non-zero rule count.
        foreach (RuleFamily family in Enum.GetValues<RuleFamily>())
        {
            Assert.DoesNotContain("0 rules", h.Vm.FamilySummaries[family]);
        }
    }
}
