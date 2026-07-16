using System.Collections.Concurrent;
using DnsCryptControl.Core.Rules;
using DnsCryptControl.Core.Toml;
using DnsCryptControl.Platform;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.ViewModels;
using static DnsCryptControl.UI.ViewModels.FilteringViewModel;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// C2: <see cref="FilteringViewModel"/> — the Filtering tab's orchestration spike. Proves the four
/// load-bearing coordination behaviours the design flags as the only NEW logic (plan §5.2):
/// <list type="bullet">
///   <item><b>Ordered enable-and-wire (IC-12):</b> the family <c>.txt</c> WriteRuleFile is sent BEFORE
///     the <c>*_file</c> WriteConfig, verified with a recording fake that captures call order across
///     the two services — the proxy is never wired to a missing file.</item>
///   <item><b>No-hijack (IC-12):</b> a <c>*_file</c> key already pointing at a custom external path is
///     never overwritten, our <c>.txt</c> is never written over theirs, and the family goes read-only
///     with an honesty banner.</item>
///   <item><b>Staleness (IC-13):</b> a <c>.txt</c> that changed on disk since load surfaces a warning
///     before the unconditional (no-CAS) write.</item>
///   <item><b>Toggle staging + IC-9 divergence:</b> block_*/reject_ttl/cloak_* stage as Bool/Long ops
///     that ride the fresh read-modify-write; a staged key that changed on disk aborts with a Conflict
///     banner and the staged set preserved; TooLarge is surfaced.</item>
/// </list>
///
/// <para>Pure-POCO/IC-5: no WPF types, every post-await observable write through the injected
/// <see cref="IUiDispatcher"/>, and all timing deterministic (a never-firing editor debounce so no
/// background re-parse can race the orchestration assertions) — zero wall-clock sleeps.</para>
/// </summary>
public class FilteringViewModelTests
{
    private static readonly string Sha = new('a', 64);
    private static readonly string Sha2 = new('b', 64);

    /// <summary>The editor debounce never fires, so the only parse is the synchronous one at Load; no
    /// background publication can race an orchestration assertion.</summary>
    private static readonly TimeSpan NeverDebounce = Timeout.InfiniteTimeSpan;

    // ------------------------------------------------------------------ fixtures

    private sealed class SynchronousDispatcher : IUiDispatcher
    {
        public void Post(Action action) => action();
    }

    private sealed class FakeConfigFileService : IConfigFileService
    {
        public ConfigLoadResult NextLoad { get; set; } = ConfigLoadResult.Fail("unscripted Load");
        public Queue<ConfigLoadResult> LoadQueue { get; } = new();
        public List<(string Text, string BaseSha256)> SaveCalls { get; } = new();
        public Func<string, string, CancellationToken, Task<ConfigSaveOutcome>>? SaveHandler { get; set; }
        private readonly Sequencer _seq;

        public FakeConfigFileService(Sequencer seq) => _seq = seq;

        public ConfigLoadResult Load() => LoadQueue.Count > 0 ? LoadQueue.Dequeue() : NextLoad;

        public Task<ConfigSaveOutcome> SaveAndApplyAsync(string candidateText, string baseSha256, CancellationToken ct)
        {
            SaveCalls.Add((candidateText, baseSha256));
            _seq.Record(Sequencer.WriteConfig);
            return SaveHandler?.Invoke(candidateText, baseSha256, ct)
                ?? Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));
        }
    }

    /// <summary>Fake rule-file service: reads come from an in-memory table; writes are recorded and
    /// their order (across BOTH services) captured via the shared <see cref="Sequencer"/>.</summary>
    private sealed class FakeRuleFileService : IRuleFileService
    {
        private readonly Sequencer _seq;
        public Dictionary<RuleFileKind, RuleFileSnapshot> Reads { get; } = new();
        public Dictionary<RuleFileKind, DateTime?> Mtimes { get; } = new();
        public List<(RuleFileKind Kind, string Content)> WriteCalls { get; } = new();
        public Func<RuleFileKind, string, Task<RuleFileWriteOutcome>>? WriteHandler { get; set; }

        public FakeRuleFileService(Sequencer seq) => _seq = seq;

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

    /// <summary>Records the interleaving of the two write paths so the ordered enable-and-wire test can
    /// assert the <c>.txt</c> WriteRuleFile precedes the <c>*_file</c> WriteConfig.</summary>
    private sealed class Sequencer
    {
        public const int WriteRuleFile = 1;
        public const int WriteConfig = 2;
        public List<int> Order { get; } = new();
        public void Record(int step) => Order.Add(step);
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

    private static string CanonicalPath(string leaf) =>
        Path.Combine(UiPaths.ProgramDataDir, leaf);

    // ------------------------------------------------------------------ load

    [Fact]
    public async Task load_reads_toggles_and_family_files()
    {
        using var h = new Harness();
        // No blocked_names_file key present → the family is ours to wire; our .txt is read.
        h.Config.NextLoad = ConfigLoadResult.Ok("block_ipv6 = true\nreject_ttl = 30\n", Sha);
        h.Rules.Reads[RuleFileKind.BlockedNames] =
            new RuleFileSnapshot("ads.example.com\n", RuleFileState.Present, DateTime.UtcNow);

        await h.Vm.LoadAsync(CancellationToken.None);

        Assert.False(h.Vm.LoadFailed);
        Assert.Equal(true, h.Vm.ToggleValues["block_ipv6"]);
        Assert.Equal(30L, h.Vm.ToggleValues["reject_ttl"]);
        var blocked = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames);
        Assert.Equal("ads.example.com\n", blocked.RawText);
    }

    [Fact]
    public async Task load_failure_surfaces_and_never_throws()
    {
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Fail("Config file not found: X");

        await h.Vm.LoadAsync(CancellationToken.None);

        Assert.True(h.Vm.LoadFailed);
        Assert.Contains("not found", h.Vm.LoadError);
    }

    // ------------------------------------------------------------- enable-and-wire (IC-12)

    [Fact]
    public async Task enable_writes_txt_BEFORE_wiring_the_config_key()
    {
        using var h = new Harness();
        // Loaded config has no blocked_names_file key → the family is ours to wire.
        h.Config.NextLoad = ConfigLoadResult.Ok(string.Empty, Sha);
        await h.Vm.LoadAsync(CancellationToken.None);

        var blocked = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames);
        blocked.Load("ads.example.com");

        await h.Vm.EnableFamilyAsync(RuleFamily.BlockedNames, CancellationToken.None);

        // (1) the .txt write happened; the config key is only STAGED (WriteConfig deferred to Save).
        Assert.Single(h.Rules.WriteCalls);
        Assert.Equal(RuleFileKind.BlockedNames, h.Rules.WriteCalls[0].Kind);
        Assert.Equal("ads.example.com", h.Rules.WriteCalls[0].Content);
        Assert.True(h.Vm.IsDirty); // the *_file op is staged

        // (2) now Save the config — the WriteConfig fires, and the recorded order proves the .txt
        // write preceded it (the proxy is never wired to a missing file).
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok(string.Empty, Sha)); // fresh RMW load
        await h.Vm.SaveConfigAsync(CancellationToken.None);

        Assert.Equal(new[] { Sequencer.WriteRuleFile, Sequencer.WriteConfig }, h.Seq.Order);
        // The staged *_file value is our canonical path, written into the TOML.
        var saved = h.Config.SaveCalls.Single().Text;
        Assert.Contains(CanonicalPath("blocked-names.txt").Replace("\\", "\\\\"), saved);
    }

    [Fact]
    public async Task enable_does_NOT_stage_the_key_when_the_txt_write_is_rejected()
    {
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok(string.Empty, Sha);
        await h.Vm.LoadAsync(CancellationToken.None);

        h.Rules.WriteHandler = (_, _) => Task.FromResult(
            new RuleFileWriteOutcome(RuleFileWriteOutcomeKind.Rejected, "A rule line exceeds the 4096-character cap."));

        await h.Vm.EnableFamilyAsync(RuleFamily.BlockedNames, CancellationToken.None);

        // The .txt write was attempted and rejected → NOTHING staged (no half-wired config key).
        Assert.Single(h.Rules.WriteCalls);
        Assert.False(h.Vm.IsDirty);
        Assert.Contains("4096", h.Vm.FamilyErrors[RuleFamily.BlockedNames]);
    }

    [Fact]
    public async Task enable_REFUSES_to_write_an_invalid_rule_file()
    {
        // 5d-VM-2 (HIGH, found on the VM): EnableFamilyAsync must mirror SaveFamilyFileAsync's IsValid gate.
        // Before the fix, "Save" refused an Error-lint body but "Enable & wire" WROTE it — for a cloaking /
        // forwarding startup-breaker that meant the proxy failed to start on the next apply.
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok(string.Empty, Sha);
        await h.Vm.LoadAsync(CancellationToken.None);

        // A non-canonical CIDR is a fail-open Error lint (the proxy silently drops it) → the editor is invalid.
        var ips = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedIps);
        ips.Load("192.0.2.0/24\n010.0.0.0/8");
        Assert.False(ips.IsValid); // precondition: the FATAL-lint state

        await h.Vm.EnableFamilyAsync(RuleFamily.BlockedIps, CancellationToken.None);

        // The gate refuses: no .txt write, no staged key, a per-family error banner instead.
        Assert.Empty(h.Rules.WriteCalls);
        Assert.False(h.Vm.IsDirty);
        Assert.Contains("invalid", h.Vm.FamilyErrors[RuleFamily.BlockedIps]);
    }

    [Fact]
    public async Task enable_success_clears_a_prior_family_error()
    {
        // 5d-VM-3 (LOW, found on the VM): a successful Enable must clear a prior per-family error so a stale
        // "Could not save" banner does not linger (Save cleared it via ApplyTxtOutcome; Enable did not).
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok(string.Empty, Sha);
        await h.Vm.LoadAsync(CancellationToken.None);

        h.Rules.WriteHandler = (_, _) => Task.FromResult(
            new RuleFileWriteOutcome(RuleFileWriteOutcomeKind.Rejected, "helper said no"));
        await h.Vm.EnableFamilyAsync(RuleFamily.BlockedNames, CancellationToken.None);
        Assert.True(h.Vm.FamilyErrors.ContainsKey(RuleFamily.BlockedNames)); // a prior error is showing

        h.Rules.WriteHandler = (_, _) => Task.FromResult(
            new RuleFileWriteOutcome(RuleFileWriteOutcomeKind.Applied, "saved"));
        h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames).Load("good.example");
        await h.Vm.EnableFamilyAsync(RuleFamily.BlockedNames, CancellationToken.None);
        Assert.False(h.Vm.FamilyErrors.ContainsKey(RuleFamily.BlockedNames)); // cleared on success
    }

    // ------------------------------------------------------------- no-hijack (IC-12)

    [Fact]
    public async Task external_path_is_never_hijacked_family_read_only()
    {
        using var h = new Harness();
        // The user manages their own blocked-names file elsewhere.
        const string external = @"C:\Users\me\my-blocklist.txt";
        h.Config.NextLoad = ConfigLoadResult.Ok(
            $"[blocked_names]\nblocked_names_file = '{external}'\n", Sha);
        h.Rules.Reads[RuleFileKind.BlockedNames] =
            new RuleFileSnapshot("SHOULD NEVER BE READ", RuleFileState.Present, DateTime.UtcNow);

        await h.Vm.LoadAsync(CancellationToken.None);

        // The family is read-only with an honesty banner naming the external path.
        Assert.Contains(external, h.Vm.ExternalPathBanners[RuleFamily.BlockedNames]);
        // We did NOT read our canonical .txt over theirs (the editor is empty, not their content).
        var blocked = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames);
        Assert.Equal(string.Empty, blocked.RawText);

        // Enabling is a no-op: neither the .txt nor the key is touched.
        await h.Vm.EnableFamilyAsync(RuleFamily.BlockedNames, CancellationToken.None);
        Assert.Empty(h.Rules.WriteCalls);
        Assert.False(h.Vm.IsDirty);
    }

    [Fact]
    public async Task canonical_path_is_ours_not_external()
    {
        using var h = new Harness();
        // The key already points at OUR canonical path → not external; the family is ours. A TOML
        // single-quoted LITERAL string takes the path verbatim (no escape processing), so the parsed
        // value equals the raw canonical path exactly.
        var canonical = CanonicalPath("blocked-names.txt");
        h.Config.NextLoad = ConfigLoadResult.Ok(
            $"[blocked_names]\nblocked_names_file = '{canonical}'\n", Sha);
        h.Rules.Reads[RuleFileKind.BlockedNames] =
            new RuleFileSnapshot("ours.example.com\n", RuleFileState.Present, DateTime.UtcNow);

        await h.Vm.LoadAsync(CancellationToken.None);

        Assert.False(h.Vm.ExternalPathBanners.ContainsKey(RuleFamily.BlockedNames));
        var blocked = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames);
        Assert.Equal("ours.example.com\n", blocked.RawText); // our file WAS read
    }

    // ------------------------------------------------------------- A5: @schedule cross-validation

    [Fact]
    public async Task undefined_schedule_reference_surfaces_a_warning_on_the_names_family()
    {
        // A5: a blocked_names rule referencing a schedule not present in [schedules] makes the proxy
        // silently DROP the rule (blocks nothing). The Filtering tab must surface a Warning.
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok("[schedules.work]\nmon = ['09:00-17:00']\n", Sha);
        h.Rules.Reads[RuleFileKind.BlockedNames] =
            new RuleFileSnapshot("ads.example @nights\n", RuleFileState.Present, DateTime.UtcNow);

        await h.Vm.LoadAsync(CancellationToken.None);

        var blocked = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames);
        Assert.Contains(blocked.Findings,
            f => f.Severity == RuleLintSeverity.Warning && f.LineNumber == 1
                 && f.Message.Contains("nights", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task defined_schedule_reference_is_clean_no_warning()
    {
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok("[schedules.work]\nmon = ['09:00-17:00']\n", Sha);
        h.Rules.Reads[RuleFileKind.BlockedNames] =
            new RuleFileSnapshot("ads.example @work\n", RuleFileState.Present, DateTime.UtcNow);

        await h.Vm.LoadAsync(CancellationToken.None);

        var blocked = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames);
        Assert.DoesNotContain(blocked.Findings, f => f.Message.Contains("schedule", StringComparison.OrdinalIgnoreCase));
    }

    // ------------------------------------------------------------- staleness (IC-13)

    [Fact]
    public async Task save_family_file_warns_when_txt_changed_on_disk_since_load()
    {
        using var h = new Harness();
        var loadTime = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        h.Config.NextLoad = ConfigLoadResult.Ok(string.Empty, Sha);
        h.Rules.Reads[RuleFileKind.BlockedNames] =
            new RuleFileSnapshot("old\n", RuleFileState.Present, loadTime);
        h.Rules.Mtimes[RuleFileKind.BlockedNames] = loadTime;

        await h.Vm.LoadAsync(CancellationToken.None);

        // The file changed on disk since load.
        h.Rules.Mtimes[RuleFileKind.BlockedNames] = loadTime.AddMinutes(5);

        var blocked = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames);
        blocked.Load("new.example.com");
        await h.Vm.SaveFamilyFileAsync(RuleFamily.BlockedNames, CancellationToken.None);

        // The write still happened (unconditional, no-CAS) but the staleness was surfaced.
        Assert.Single(h.Rules.WriteCalls);
        Assert.Contains("changed on disk", h.Vm.StalenessWarnings[RuleFamily.BlockedNames]);
    }

    [Fact]
    public async Task enable_then_save_does_not_falsely_flag_staleness_missingAtLoad()
    {
        // Review Medium: EnableFamilyAsync re-anchored LoadedMtimeUtc to the PRE-write mtime (null for
        // a missing-at-load file), while the write advances the on-disk mtime to M2. The very next
        // Save then saw M2 != null and spuriously flagged "changed on disk" with no external writer.
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok(string.Empty, Sha);
        // Missing at load (the dominant enable-to-wire-a-new-file path): no Reads entry, no Mtime.

        // The helper write "creates" the file: advance the fake mtime to M2 when WriteRuleFile runs.
        var m2 = new DateTime(2026, 2, 2, 0, 0, 0, DateTimeKind.Utc);
        h.Rules.WriteHandler = (kind, _) =>
        {
            h.Rules.Mtimes[kind] = m2;
            return Task.FromResult(new RuleFileWriteOutcome(RuleFileWriteOutcomeKind.Applied, "saved"));
        };

        await h.Vm.LoadAsync(CancellationToken.None);

        var blocked = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames);
        blocked.Load("ads.example.com");
        await h.Vm.EnableFamilyAsync(RuleFamily.BlockedNames, CancellationToken.None);

        // The Enable re-anchored the load-time mtime to M2 (what the write produced), so a subsequent
        // Save must NOT be flagged stale.
        blocked.Load("ads.example.com\nmore.example.com");
        await h.Vm.SaveFamilyFileAsync(RuleFamily.BlockedNames, CancellationToken.None);

        Assert.False(h.Vm.StalenessWarnings.ContainsKey(RuleFamily.BlockedNames));
    }

    [Fact]
    public async Task enable_then_save_does_not_falsely_flag_staleness_presentAtLoad()
    {
        using var h = new Harness();
        var loadTime = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        h.Config.NextLoad = ConfigLoadResult.Ok(string.Empty, Sha);
        h.Rules.Reads[RuleFileKind.BlockedNames] =
            new RuleFileSnapshot("old\n", RuleFileState.Present, loadTime);
        h.Rules.Mtimes[RuleFileKind.BlockedNames] = loadTime;

        var m2 = loadTime.AddMinutes(10);
        h.Rules.WriteHandler = (kind, _) =>
        {
            h.Rules.Mtimes[kind] = m2; // the write bumps mtime M1 -> M2
            return Task.FromResult(new RuleFileWriteOutcome(RuleFileWriteOutcomeKind.Applied, "saved"));
        };

        await h.Vm.LoadAsync(CancellationToken.None);

        var blocked = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames);
        await h.Vm.EnableFamilyAsync(RuleFamily.BlockedNames, CancellationToken.None);

        // Enable did not itself flag staleness (M1 == M1 pre-write), and it re-anchored to M2.
        Assert.False(h.Vm.StalenessWarnings.ContainsKey(RuleFamily.BlockedNames));

        blocked.Load("new.example.com");
        await h.Vm.SaveFamilyFileAsync(RuleFamily.BlockedNames, CancellationToken.None);

        // The subsequent Save must NOT be flagged stale (M2 == M2, no external writer).
        Assert.False(h.Vm.StalenessWarnings.ContainsKey(RuleFamily.BlockedNames));
    }

    [Fact]
    public async Task save_family_file_helper_throw_fails_closed_to_error_notThrow()
    {
        // Carried C2: the helper-write path relied on the transport returning null rather than
        // throwing. If WriteRuleFileAsync throws, the VM must degrade to a per-family error surface,
        // not let the throw escape.
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok(string.Empty, Sha);
        h.Rules.Reads[RuleFileKind.BlockedNames] =
            new RuleFileSnapshot("old\n", RuleFileState.Present, DateTime.UtcNow);
        h.Rules.WriteHandler = (_, _) => throw new InvalidOperationException("pipe blew up");

        await h.Vm.LoadAsync(CancellationToken.None);
        var blocked = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames);
        blocked.Load("ads.example.com");

        await h.Vm.SaveFamilyFileAsync(RuleFamily.BlockedNames, CancellationToken.None); // must not throw

        Assert.False(h.Vm.IsBusy);
        Assert.True(h.Vm.FamilyErrors.ContainsKey(RuleFamily.BlockedNames));
    }

    // ------------------------------------------------------------- toggle staging + IC-9

    [Fact]
    public async Task staging_a_toggle_marks_dirty_and_projects_effective_value()
    {
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok("reject_ttl = 10\n", Sha);
        await h.Vm.LoadAsync(CancellationToken.None);

        Assert.Equal(10L, h.Vm.ToggleValues["reject_ttl"]);
        Assert.False(h.Vm.IsDirty);

        h.Vm.StageToggleLong("reject_ttl", 60);
        h.Vm.StageToggleBool("block_ipv6", true);

        Assert.True(h.Vm.IsDirty);
        Assert.Equal(60L, h.Vm.ToggleValues["reject_ttl"]);
        Assert.Equal(true, h.Vm.ToggleValues["block_ipv6"]);
    }

    [Fact]
    public async Task staging_notifies_CanSaveConfig_so_the_saveApply_button_enables()
    {
        // VM-run regression (2026-07-03): FilteringView binds the "Save & apply" button's IsEnabled to
        // CanSaveConfig (a computed getter over IsDirty/IsBusy). Without
        // [NotifyPropertyChangedFor(nameof(CanSaveConfig))] on _isDirty/_isBusy, staging flips IsDirty
        // (the config Revert, bound directly to IsDirty, DID enable live) but CanSaveConfig never raised
        // PropertyChanged — so the button stayed stuck DISABLED and the config-key wiring + every toggle
        // could NEVER be committed through the UI (enable-and-wire dead end-to-end). The old staging
        // tests missed it because they asserted the getter VALUE, not the NOTIFICATION.
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok("reject_ttl = 10\n", Sha);
        await h.Vm.LoadAsync(CancellationToken.None);
        Assert.False(h.Vm.CanSaveConfig);

        var raised = new List<string?>();
        h.Vm.PropertyChanged += (_, e) => raised.Add(e.PropertyName);

        h.Vm.StageToggleBool("block_ipv6", true);

        Assert.True(h.Vm.CanSaveConfig);
        Assert.Contains(nameof(h.Vm.CanSaveConfig), raised);
    }

    [Fact]
    public async Task save_config_writes_staged_toggles_into_fresh_doc()
    {
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok("reject_ttl = 10\n", Sha);
        await h.Vm.LoadAsync(CancellationToken.None);
        h.Vm.StageToggleLong("reject_ttl", 60);
        h.Vm.StageToggleBool("block_ipv6", true);

        // Fresh RMW load returns the same on-disk content (no divergence).
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("reject_ttl = 10\n", Sha));
        await h.Vm.SaveConfigAsync(CancellationToken.None);

        var saved = h.Config.SaveCalls.Single();
        Assert.Equal(Sha, saved.BaseSha256); // the FRESH sha is the CAS base (IC-9)
        var doc = TomlConfigDocument.Parse(saved.Text);
        Assert.True(doc.TryGetLong("reject_ttl", out var ttl));
        Assert.Equal(60L, ttl);
        Assert.True(doc.TryGetBool("block_ipv6", out var v6) && v6);
        Assert.False(h.Vm.IsDirty); // Applied clears the staged set
    }

    [Fact]
    public async Task save_config_aborts_with_conflict_when_a_staged_key_diverged_on_disk()
    {
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok("reject_ttl = 10\n", Sha);
        await h.Vm.LoadAsync(CancellationToken.None);
        h.Vm.StageToggleLong("reject_ttl", 60);

        // The fresh RMW load shows reject_ttl was changed to 99 on disk since we staged over 10.
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("reject_ttl = 99\n", Sha2));
        await h.Vm.SaveConfigAsync(CancellationToken.None);

        Assert.Empty(h.Config.SaveCalls); // aborted BEFORE any write
        Assert.Contains("reject_ttl", h.Vm.ConflictMessage);
        Assert.True(h.Vm.IsDirty); // the staged set is PRESERVED
    }

    [Fact]
    public async Task save_config_surfaces_TooLarge_from_the_outcome_map()
    {
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok("reject_ttl = 10\n", Sha);
        await h.Vm.LoadAsync(CancellationToken.None);
        h.Vm.StageToggleLong("reject_ttl", 60);

        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("reject_ttl = 10\n", Sha));
        h.Config.SaveHandler = (_, _, _) => Task.FromResult(
            new ConfigSaveOutcome(ConfigSaveOutcomeKind.TooLarge, "config is too large to send to the helper (limit 1 MiB per request)"));

        await h.Vm.SaveConfigAsync(CancellationToken.None);

        Assert.Contains("too large", h.Vm.SaveError);
        Assert.True(h.Vm.IsDirty); // a non-Applied outcome keeps the staged set
    }

    // ------------------------------------------------------------- C3: content-derived honesty
    //
    // The invariant under test (mirror AnonymizedDnsViewModel:78-113): displayed state derives from
    // the family's CONTENT, never the toggle/wiring. A family wired to a .txt is only "active" (claims
    // protection) when that .txt actually holds ≥1 rule; a wired-but-empty family shows an honesty
    // banner ("nothing is blocked yet") and does NOT count toward the "K families active" headline.

    /// <summary>Wires a family's *_file key to our canonical path in raw TOML (so it loads as "ours",
    /// non-external, and the editor reads its content). A TOML single-quoted LITERAL string takes the
    /// path verbatim (no escape processing), so the parsed value equals the raw canonical path exactly
    /// — the backslashes are NOT doubled (mirror the C2 canonical_path_is_ours_not_external fixture).</summary>
    private static string WiredConfig(string section, string key, string leaf) =>
        $"[{section}]\n{key} = '{CanonicalPath(leaf)}'\n";

    [Fact]
    public async Task wired_but_empty_family_shows_honesty_banner_not_a_protection_claim()
    {
        using var h = new Harness();
        // blocked_names_file points at OUR canonical path → wired (not external), but the .txt is empty.
        h.Config.NextLoad = ConfigLoadResult.Ok(
            WiredConfig("blocked_names", "blocked_names_file", "blocked-names.txt"), Sha);
        h.Rules.Reads[RuleFileKind.BlockedNames] =
            new RuleFileSnapshot(string.Empty, RuleFileState.Present, DateTime.UtcNow);

        await h.Vm.LoadAsync(CancellationToken.None);

        // Enabled/wired but no content → the honesty banner is shown; it never claims blocking.
        Assert.True(h.Vm.EmptyButWiredBanners.ContainsKey(RuleFamily.BlockedNames));
        Assert.Contains("nothing is blocked yet", h.Vm.EmptyButWiredBanners[RuleFamily.BlockedNames]);
        // The family is NOT counted active (0 families active).
        Assert.Contains("0 of 6", h.Vm.ActiveFamiliesHeadline);
    }

    [Fact]
    public async Task wired_family_with_rules_shows_the_count_and_no_empty_banner()
    {
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok(
            WiredConfig("blocked_names", "blocked_names_file", "blocked-names.txt"), Sha);
        h.Rules.Reads[RuleFileKind.BlockedNames] =
            new RuleFileSnapshot("ads.example.com\ntracker.example.net\n# a comment\n", RuleFileState.Present, DateTime.UtcNow);

        await h.Vm.LoadAsync(CancellationToken.None);

        // Content present → no honesty banner; the per-family summary counts rules & comments.
        Assert.False(h.Vm.EmptyButWiredBanners.ContainsKey(RuleFamily.BlockedNames));
        Assert.Contains("2 rules", h.Vm.FamilySummaries[RuleFamily.BlockedNames]);
        Assert.Contains("1 comment", h.Vm.FamilySummaries[RuleFamily.BlockedNames]);
        // One family wired-and-populated → one active.
        Assert.Contains("1 of 6", h.Vm.ActiveFamiliesHeadline);
    }

    [Fact]
    public async Task not_wired_family_is_neither_active_nor_banner_flagged()
    {
        using var h = new Harness();
        // No *_file key anywhere → not wired; even a .txt with content on disk does not count.
        h.Config.NextLoad = ConfigLoadResult.Ok(string.Empty, Sha);
        h.Rules.Reads[RuleFileKind.BlockedNames] =
            new RuleFileSnapshot("ads.example.com\n", RuleFileState.Present, DateTime.UtcNow);

        await h.Vm.LoadAsync(CancellationToken.None);

        // Not wired → not "enabled but empty" (the honesty banner is only for the wired-but-empty case).
        Assert.False(h.Vm.EmptyButWiredBanners.ContainsKey(RuleFamily.BlockedNames));
        Assert.Contains("0 of 6", h.Vm.ActiveFamiliesHeadline);
    }

    [Fact]
    public async Task summary_and_headline_derive_from_CONTENT_not_the_wiring_toggle()
    {
        using var h = new Harness();
        // Wired to our path, empty on disk → banner shown, 0 active.
        h.Config.NextLoad = ConfigLoadResult.Ok(
            WiredConfig("blocked_names", "blocked_names_file", "blocked-names.txt"), Sha);
        h.Rules.Reads[RuleFileKind.BlockedNames] =
            new RuleFileSnapshot(string.Empty, RuleFileState.Present, DateTime.UtcNow);
        await h.Vm.LoadAsync(CancellationToken.None);

        Assert.True(h.Vm.EmptyButWiredBanners.ContainsKey(RuleFamily.BlockedNames));
        Assert.Contains("0 of 6", h.Vm.ActiveFamiliesHeadline);

        // Now the user types rules into the editor — WITHOUT touching the wiring/toggle. The derived
        // state must follow the CONTENT: banner clears, count appears, headline increments.
        var blocked = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames);
        blocked.Load("ads.example.com\nmalware.example.org\n");

        Assert.False(h.Vm.EmptyButWiredBanners.ContainsKey(RuleFamily.BlockedNames));
        Assert.Contains("2 rules", h.Vm.FamilySummaries[RuleFamily.BlockedNames]);
        Assert.Contains("1 of 6", h.Vm.ActiveFamiliesHeadline);
    }

    [Fact]
    public async Task invalid_lines_are_counted_in_the_family_summary()
    {
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok(string.Empty, Sha);
        await h.Vm.LoadAsync(CancellationToken.None);

        // A degenerate cloak pattern '*' is a FATAL (Error) lint (A3). The summary surfaces the count
        // from CONTENT regardless of wiring — the family need not be wired for the count to be honest.
        var cloaking = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.Cloaking);
        cloaking.Load("* 1.2.3.4\n");

        Assert.False(cloaking.IsValid);
        Assert.Contains("invalid", h.Vm.FamilySummaries[RuleFamily.Cloaking]);
    }

    [Fact]
    public async Task an_externally_managed_family_reports_the_external_banner_and_is_not_active()
    {
        using var h = new Harness();
        const string external = @"C:\Users\me\my-blocklist.txt";
        h.Config.NextLoad = ConfigLoadResult.Ok(
            $"[blocked_names]\nblocked_names_file = '{external}'\n", Sha);
        h.Rules.Reads[RuleFileKind.BlockedNames] =
            new RuleFileSnapshot("SHOULD NEVER BE READ", RuleFileState.Present, DateTime.UtcNow);

        await h.Vm.LoadAsync(CancellationToken.None);

        // The external-path banner (from C2) is surfaced; C3 must NOT ALSO show the empty-but-wired
        // honesty banner (the editor is read-only, so "nothing is blocked yet" would be misleading),
        // and an external family is not counted active (its content is unknown to us).
        Assert.True(h.Vm.ExternalPathBanners.ContainsKey(RuleFamily.BlockedNames));
        Assert.False(h.Vm.EmptyButWiredBanners.ContainsKey(RuleFamily.BlockedNames));
        Assert.Contains("0 of 6", h.Vm.ActiveFamiliesHeadline);
    }

    [Fact]
    public async Task staging_an_enable_wire_op_flips_derived_state_from_content()
    {
        using var h = new Harness();
        // Not wired at load; the editor has content the user typed.
        h.Config.NextLoad = ConfigLoadResult.Ok(string.Empty, Sha);
        await h.Vm.LoadAsync(CancellationToken.None);

        var blocked = h.Vm.Editors.Single(e => e.Kind == RuleFileKind.BlockedNames);
        blocked.Load("ads.example.com\n");

        // Not wired yet → not active even though it has content.
        Assert.Contains("0 of 6", h.Vm.ActiveFamiliesHeadline);

        // Enable-and-wire stages the *_file op → now wired AND populated → active.
        await h.Vm.EnableFamilyAsync(RuleFamily.BlockedNames, CancellationToken.None);

        Assert.Contains("1 of 6", h.Vm.ActiveFamiliesHeadline);
        Assert.False(h.Vm.EmptyButWiredBanners.ContainsKey(RuleFamily.BlockedNames));
    }
}
