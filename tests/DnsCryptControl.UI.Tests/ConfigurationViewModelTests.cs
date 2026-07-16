using System.Collections.Concurrent;
using DnsCryptControl.Core.Schema;
using DnsCryptControl.Core.Validation;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// E1: <see cref="ConfigurationViewModel"/> core — load the on-disk config through
/// <see cref="IConfigFileService.Load"/>, project the REAL 118-entry
/// <see cref="ConfigCatalog"/> into curated sections (A4 <c>Group</c>), mark
/// raw-only entries (P5b-E3: <c>Table</c>-typed OR under a dynamic section), and keep
/// BOTH editor views projections of ONE <c>TomlConfigDocument</c> (IC-1). Pure-POCO
/// tests: no WPF types, every post-await observable write through the injected
/// <see cref="IUiDispatcher"/> (IC-5).
///
/// <para>E2: the debounced off-thread validation pipeline — every structured or raw
/// edit restarts one debounce session; on fire the candidate raw text is parsed +
/// schema-validated (<c>ConfigValidator</c>) + OPSEC-evaluated (<c>OpsecConfigRules</c>)
/// off the UI thread and the results are PUBLISHED through the dispatcher. All timing
/// is deterministic: a short injected debounce interval, an injectable awaitable
/// validation gate for sequencing, and NO wall-clock sleeps anywhere.</para>
///
/// <para>E3: Save &amp; apply / Revert commands + outcome states. Per the plan's
/// "pick ONE and note it": these tests drive saves through the FAKED
/// <see cref="IConfigFileService"/> (the VM's own seam) — the real
/// <c>ConfigFileService</c> orchestration over the shared <c>FakeHelperClient</c> is
/// already covered outcome-by-outcome in <c>ConfigFileServiceTests</c> (D2).</para>
/// </summary>
public class ConfigurationViewModelTests
{
    // Deliberately hostile to model round-tripping (mirrors the A2 fixtures): a
    // full-line comment, an inline trailing comment on the line the structured
    // toggle mutates, a float, an array, and a [table] section.
    private const string SampleToml =
        "# managed by DnsCryptControl\n" +
        "require_dnssec = false # sync with resolver capabilities\n" +
        "cache_size = 4096\n" +
        "timeout_load_reduction = 0.75\n" +
        "server_names = ['cloudflare', 'quad9-dnscrypt-ip4-filter-pri']\n" +
        "\n" +
        "[anonymized_dns]\n" +
        "skip_incompatible = false\n";

    // OPSEC-clean AND schema-clean: netprobe_timeout 0 + ignore_system_dns true satisfy
    // both KillSwitchCritical rules; bootstrap/listen/netprobe_address absent = safe.
    private const string SafeToml =
        "netprobe_timeout = 0\n" +
        "ignore_system_dns = true\n" +
        "cache_size = 4096\n";

    // Parses fine as TOML but fails SCHEMA validation: a Bool key with a String value
    // (Error) plus an unknown key (Warning) — the panel must carry the FULL list, not
    // just the wire's first error.
    private const string SchemaErrorToml =
        "netprobe_timeout = 0\n" +
        "ignore_system_dns = true\n" +
        "require_dnssec = \"yes\"\n" +
        "x_unknown = 1\n";

    // Schema-clean but OPSEC-unsafe: netprobe_timeout 60 raises the KillSwitchCritical
    // NetprobeTimeoutNotZero concern (a concern is NOT a schema error — IsValid stays true).
    private const string UnsafeNetprobeToml =
        "netprobe_timeout = 60\n" +
        "ignore_system_dns = true\n";

    /// <summary>E2 tests: short enough to fire promptly; every wait is an awaited
    /// signal (post/gate arrival), never a sleep, so the exact length is latency-only.</summary>
    private static readonly TimeSpan TestDebounce = TimeSpan.FromMilliseconds(10);

    /// <summary>E1 tests: a debounce that NEVER fires (infinite), so mid-window
    /// assertions on <see cref="RawParseState.Pending"/> etc. can never race a
    /// background publication.</summary>
    private static readonly TimeSpan NeverDebounce = Timeout.InfiniteTimeSpan;

    private static readonly string Sha = new('a', 64);

    private sealed class SynchronousDispatcher : IUiDispatcher, IDisposable
    {
        private readonly SemaphoreSlim _posts = new(0);
        private int _postCount;

        public void Dispose() => _posts.Dispose();

        public int PostCount => Volatile.Read(ref _postCount);

        public void Post(Action action)
        {
            Interlocked.Increment(ref _postCount);
            action();
            _posts.Release(); // release AFTER the action so awaited state is visible
        }

        /// <summary>Zeroes the count and drains pending signals (call after LoadAsync so tests count only
        /// the posts THEY provoke). 6d: the debounce tests now await the actual validation run task
        /// (<see cref="ConfigurationViewModel.PendingValidation"/>) instead of racing a wall-clock post
        /// wait, so the old WaitForPostAsync hang-guard was removed - awaiting the task is starvation-proof.</summary>
        public void Reset()
        {
            while (_posts.Wait(0))
            {
            }

            Interlocked.Exchange(ref _postCount, 0);
        }
    }

    /// <summary>Queues posted actions instead of running them, so a test can prove a
    /// mutation happens INSIDE the posted action (IC-5) — state must be unchanged after
    /// the Post call and changed only once the queued action is run.</summary>
    private sealed class QueueingDispatcher : IUiDispatcher, IDisposable
    {
        private readonly ConcurrentQueue<Action> _pending = new();
        private readonly SemaphoreSlim _arrived = new(0);

        public void Dispose() => _arrived.Dispose();

        public void Post(Action action)
        {
            _pending.Enqueue(action);
            _arrived.Release();
        }

        public async Task WaitForQueuedPostAsync()
        {
            Assert.True(
                await _arrived.WaitAsync(TimeSpan.FromSeconds(10)),
                "timed out waiting for a post to be queued");
        }

        public void RunNext()
        {
            Assert.True(_pending.TryDequeue(out var action), "no queued post to run");
            action!();
        }
    }

    /// <summary>
    /// The E2 gate seam (plan pre-flight fix): a <see cref="TaskCompletionSource"/>-backed
    /// awaitable gate that HOLDS every validation run where it starts, so tests can
    /// interleave edits between a run's start and its publication attempt.
    /// The TCS is deliberately created WITHOUT <c>RunContinuationsAsynchronously</c>:
    /// <see cref="TaskCompletionSource.SetResult()"/> then executes the released run's
    /// continuation — parse, validate, publish-or-drop — INLINE on the releasing test
    /// thread (the run awaits with no sync context), so when a Release call returns the
    /// run has provably finished and "was never published" is a deterministic assertion,
    /// not a race. No wall-clock sleeps anywhere.
    /// </summary>
    private sealed class ManualGate : IDisposable
    {
        private readonly ConcurrentQueue<TaskCompletionSource> _held = new();
        private readonly SemaphoreSlim _arrivals = new(0);

        public void Dispose() => _arrivals.Dispose();

        public Task GateAsync(CancellationToken ct)
        {
            var tcs = new TaskCompletionSource();
            _held.Enqueue(tcs);
            _arrivals.Release();
            return tcs.Task;
        }

        /// <summary>Awaits the next validation run reaching the gate (i.e. it is past
        /// its cancellable debounce delay) and returns its release handle.</summary>
        public async Task<TaskCompletionSource> NextArrivalAsync()
        {
            Assert.True(
                await _arrivals.WaitAsync(TimeSpan.FromSeconds(10)),
                "timed out waiting for a validation run to reach the gate");
            Assert.True(_held.TryDequeue(out var tcs));
            return tcs!;
        }
    }

    private sealed class FakeStateReader : IProtectionStateReader
    {
        public ProtectionIntent Intent { get; set; } = new(false, false, false);

        public ProtectionIntent Read() => Intent;
    }

    private sealed class FakeConfigFileService : IConfigFileService
    {
        public ConfigLoadResult NextLoad { get; set; } = ConfigLoadResult.Fail("unscripted Load");
        public int LoadCalls { get; private set; }

        /// <summary>Per-call argument record (E3): the double-save test asserts the
        /// exact (text, sha) pair each dispatched save carried.</summary>
        public List<(string Text, string BaseSha256)> SaveCalls { get; } = new();

        public Func<string, string, CancellationToken, Task<ConfigSaveOutcome>>? SaveHandler { get; set; }

        public ConfigLoadResult Load()
        {
            LoadCalls++;
            return NextLoad;
        }

        // Unscripted saves still throw: E1/E2 tests never save, so a stray call there
        // is a test bug; E3 tests script the outcome explicitly.
        public Task<ConfigSaveOutcome> SaveAndApplyAsync(string candidateText, string baseSha256, CancellationToken ct)
        {
            SaveCalls.Add((candidateText, baseSha256));
            return SaveHandler?.Invoke(candidateText, baseSha256, ct)
                ?? throw new NotSupportedException("SaveAndApplyAsync was not scripted for this test.");
        }
    }

    private static async Task<(ConfigurationViewModel Vm, FakeConfigFileService File, SynchronousDispatcher Dispatcher)> LoadedAsync(
        string toml,
        TimeSpan? debounce = null,
        Func<CancellationToken, Task>? validationGate = null,
        bool protectionEnabled = false)
    {
        var file = new FakeConfigFileService { NextLoad = ConfigLoadResult.Ok(toml, Sha) };
        var dispatcher = new SynchronousDispatcher();
        var state = new FakeStateReader { Intent = new ProtectionIntent(protectionEnabled, false, false) };
        var vm = new ConfigurationViewModel(file, state, dispatcher, debounce ?? NeverDebounce, validationGate);
        await vm.LoadAsync(CancellationToken.None);

        // A load seeds a PRISTINE validation run through the normal debounce (P5b-U1).
        // With a firing debounce and no gate, that run would publish at an arbitrary
        // moment after this helper returns — drain its publication HERE so every test
        // observes only the posts it provokes itself. Gate tests hold the pristine run
        // at their gate and release + drain it themselves; a NeverDebounce session
        // never fires, so there is nothing to drain.
        if (validationGate is null && debounce is { } interval && interval != NeverDebounce)
        {
            dispatcher.Reset();
            await vm.PendingValidation;
        }

        return (vm, file, dispatcher);
    }

    private static SettingEntryViewModel Entry(ConfigurationViewModel vm, string keyPath) =>
        vm.Sections.SelectMany(s => s.Entries).Single(e => e.KeyPath == keyPath);

    // ------------------------------------------------------------- cycle 1: load

    [Fact]
    public async Task load_populates_sections_and_entries_from_the_real_catalog()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        // Every catalog entry appears exactly once, grouped on the A4 Group field in
        // catalog (first-occurrence) order — the mockup's curated nav, not 2 buckets.
        Assert.Equal(ConfigCatalog.All.Count, vm.Sections.Sum(s => s.Entries.Count));
        Assert.True(vm.Sections.Count >= 10);
        Assert.Equal("General", vm.Sections[0].Name);

        var serverSelection = vm.Sections.Single(s => s.Name == "Server selection");
        Assert.Contains(serverSelection.Entries, e => e.KeyPath == "require_dnssec");
    }

    [Fact]
    public async Task load_reads_typed_current_values_and_marks_presence()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        var dnssec = Entry(vm, "require_dnssec");
        Assert.True(dnssec.IsSet);
        Assert.Equal(false, dnssec.Value);

        var cacheSize = Entry(vm, "cache_size");
        Assert.True(cacheSize.IsSet);
        Assert.Equal(4096L, cacheSize.Value);

        // Float entries read through TryGetDouble (the A2 reader added for exactly this).
        var loadReduction = Entry(vm, "timeout_load_reduction");
        Assert.True(loadReduction.IsSet);
        Assert.Equal(0.75, loadReduction.Value);

        var serverNames = Entry(vm, "server_names");
        Assert.True(serverNames.IsSet);
        var names = Assert.IsAssignableFrom<IReadOnlyList<string>>(serverNames.Value);
        Assert.Equal(new[] { "cloudflare", "quad9-dnscrypt-ip4-filter-pri" }, names);

        // A catalogued key absent from the file: present in the section, but unset.
        var timeout = Entry(vm, "timeout");
        Assert.False(timeout.IsSet);
        Assert.Null(timeout.Value);
    }

    [Fact]
    public async Task entries_carry_the_catalog_metadata()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        var dnssec = Entry(vm, "require_dnssec");
        Assert.Equal(SettingValueType.Bool, dnssec.ValueType);
        Assert.False(string.IsNullOrEmpty(dnssec.Doc));
        Assert.False(dnssec.Deprecated);

        var cacheSize = Entry(vm, "cache_size");
        Assert.Equal("4096", cacheSize.DefaultDisplay);

        var legacyUrl = Entry(vm, "sources.url");
        Assert.True(legacyUrl.Deprecated);
        Assert.Equal("sources.urls", legacyUrl.ReplacedBy);
    }

    /// <summary>P5b-E3: raw-only when <c>Type == Table</c> OR the entry lives under a
    /// dynamic section (<c>sources</c>/<c>schedules</c>/<c>static</c>, whose real-file
    /// paths are user-named and cannot be structurally addressed by catalog path).</summary>
    [Fact]
    public async Task raw_only_entries_are_table_typed_or_under_dynamic_sections()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        Assert.True(Entry(vm, "schedules").IsRawOnly);         // dynamic section, Table
        Assert.True(Entry(vm, "static").IsRawOnly);            // dynamic section, Table
        Assert.True(Entry(vm, "sources.urls").IsRawOnly);      // dynamic section, typed leaf
        Assert.True(Entry(vm, "anonymized_dns.routes").IsRawOnly); // Table type (5c gets UI)

        Assert.False(Entry(vm, "require_dnssec").IsRawOnly);
        Assert.False(Entry(vm, "anonymized_dns.skip_incompatible").IsRawOnly);
    }

    [Fact]
    public async Task load_sets_base_sha_raw_text_and_a_clean_state()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        Assert.Equal(Sha, vm.BaseSha256);
        Assert.Equal(SampleToml, vm.RawText);
        Assert.False(vm.IsDirty);
        Assert.False(vm.LoadFailed);
        Assert.Null(vm.LoadError);
        Assert.True(vm.IsStructuredEditable);
        Assert.Equal(RawParseState.Clean, vm.RawParseState);
    }

    [Fact]
    public async Task load_failure_is_a_distinct_state_with_the_editor_disabled()
    {
        var file = new FakeConfigFileService { NextLoad = ConfigLoadResult.Fail("Config file not found: X") };
        var vm = new ConfigurationViewModel(file, new FakeStateReader(), new SynchronousDispatcher(), NeverDebounce);

        await vm.LoadAsync(CancellationToken.None);

        Assert.True(vm.LoadFailed);
        Assert.Equal("Config file not found: X", vm.LoadError);
        Assert.False(vm.IsStructuredEditable);
        Assert.Empty(vm.Sections);
        Assert.Null(vm.BaseSha256);
        Assert.False(vm.IsDirty);
    }

    [Fact]
    public async Task successful_reload_clears_a_previous_load_failure()
    {
        var file = new FakeConfigFileService { NextLoad = ConfigLoadResult.Fail("locked") };
        var vm = new ConfigurationViewModel(file, new FakeStateReader(), new SynchronousDispatcher(), NeverDebounce);
        await vm.LoadAsync(CancellationToken.None);
        Assert.True(vm.LoadFailed);

        file.NextLoad = ConfigLoadResult.Ok(SampleToml, Sha);
        await vm.LoadAsync(CancellationToken.None);

        Assert.False(vm.LoadFailed);
        Assert.Null(vm.LoadError);
        Assert.True(vm.IsStructuredEditable);
        Assert.Equal(ConfigCatalog.All.Count, vm.Sections.Sum(s => s.Entries.Count));
    }

    /// <summary>A file that LOADS but does not PARSE is not a load failure — the raw
    /// editor must show the text so the user can fix it; only the structured pane is
    /// disabled (the doc-with-errors cannot be read or mutated).</summary>
    [Fact]
    public async Task load_of_unparseable_toml_keeps_raw_text_but_disables_the_structured_pane()
    {
        const string broken = "cache = [unclosed\n";
        var (vm, _, _) = await LoadedAsync(broken);

        Assert.False(vm.LoadFailed);
        Assert.Equal(broken, vm.RawText);
        Assert.Equal(Sha, vm.BaseSha256);
        Assert.False(vm.IsStructuredEditable);
        Assert.Equal(RawParseState.Failed, vm.RawParseState);
    }

    [Fact]
    public async Task observable_writes_after_the_load_await_go_through_the_dispatcher()
    {
        var (_, _, dispatcher) = await LoadedAsync(SampleToml);

        Assert.True(dispatcher.PostCount > 0);
    }

    // -------------------------------------------- cycle 2: doc-as-truth sync (IC-1)

    /// <summary>IC-1: a structured edit is a SURGICAL syntax-tree mutation and the raw
    /// text IS <c>doc.ToText()</c> afterwards — byte-identical outside the value token,
    /// comments intact. Never a model re-serialization.</summary>
    [Fact]
    public async Task structured_edit_updates_raw_text_preserving_comments_and_sets_dirty()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);
        var dnssec = Entry(vm, "require_dnssec");

        vm.ApplyEdit(dnssec, true);

        Assert.Equal(SampleToml.Replace(
            "require_dnssec = false # sync with resolver capabilities",
            "require_dnssec = true # sync with resolver capabilities",
            StringComparison.Ordinal), vm.RawText);
        Assert.True(vm.IsDirty);
        Assert.Equal(true, dnssec.Value);
        Assert.True(dnssec.IsSet);
    }

    /// <summary>"Reset to default" = remove the key (the proxy's own default takes
    /// over); the whole <c>key = value</c> line leaves the raw text. The removed key is
    /// a MID-document one on purpose: per the A2-pinned trivia semantics a full-line
    /// comment above a pair belongs to the PREVIOUS line, so removing a first-in-file
    /// key would legitimately take the document-leading comment with it.</summary>
    [Fact]
    public async Task structured_reset_to_default_removes_the_key()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);
        var cacheSize = Entry(vm, "cache_size");

        vm.ApplyEdit(cacheSize, null);

        Assert.DoesNotContain("cache_size", vm.RawText, StringComparison.Ordinal);
        Assert.Contains("# managed by DnsCryptControl", vm.RawText, StringComparison.Ordinal);
        Assert.Contains("require_dnssec = false # sync with resolver capabilities", vm.RawText, StringComparison.Ordinal);
        Assert.False(cacheSize.IsSet);
        Assert.Null(cacheSize.Value);
        Assert.True(vm.IsDirty);
    }

    [Fact]
    public async Task structured_edit_on_a_raw_only_entry_is_refused()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);
        var schedules = Entry(vm, "schedules");

        Assert.Throws<InvalidOperationException>(() => vm.ApplyEdit(schedules, true));
        Assert.False(vm.IsDirty);
    }

    [Fact]
    public async Task structured_edit_with_a_type_mismatched_value_is_refused()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);
        var dnssec = Entry(vm, "require_dnssec");

        Assert.Throws<ArgumentException>(() => vm.ApplyEdit(dnssec, "yes"));
        Assert.Equal(SampleToml, vm.RawText); // nothing mutated
        Assert.False(vm.IsDirty);
    }

    [Fact]
    public async Task user_raw_edit_sets_dirty_and_marks_the_parse_pending()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        vm.RawText = SampleToml.Replace("cache_size = 4096", "cache_size = 8192", StringComparison.Ordinal);

        Assert.True(vm.IsDirty);
        Assert.Equal(RawParseState.Pending, vm.RawParseState);
    }

    /// <summary>The counterpart guard: when the VM ITSELF regenerates the raw text from
    /// a structured edit, that is not a user raw edit — the parse state must stay Clean
    /// (the doc IS the text), not flip to Pending and trigger a pointless re-parse.</summary>
    [Fact]
    public async Task structured_raw_text_regeneration_does_not_mark_the_parse_pending()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        vm.ApplyEdit(Entry(vm, "require_dnssec"), true);

        Assert.Equal(RawParseState.Clean, vm.RawParseState);
        Assert.True(vm.IsStructuredEditable);
    }

    /// <summary>IC-1/P5b-E2: a parse-clean raw edit REPLACES the document and the
    /// structured values refresh from it; subsequent structured edits mutate the NEW
    /// document (both changes must coexist in the regenerated text).</summary>
    [Fact]
    public async Task reparse_of_clean_raw_text_replaces_the_document_and_refreshes_entries()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        vm.RawText = SampleToml.Replace("cache_size = 4096", "cache_size = 8192", StringComparison.Ordinal);
        vm.ReparseRawText();

        Assert.Equal(RawParseState.Clean, vm.RawParseState);
        Assert.True(vm.IsStructuredEditable);
        Assert.Equal(8192L, Entry(vm, "cache_size").Value);

        // A follow-up structured edit must land on the REPLACED doc: both changes coexist.
        vm.ApplyEdit(Entry(vm, "require_dnssec"), true);
        Assert.Contains("cache_size = 8192", vm.RawText, StringComparison.Ordinal);
        Assert.Contains("require_dnssec = true", vm.RawText, StringComparison.Ordinal);
    }

    /// <summary>IC-1 review fix: a structured edit issued while a user raw edit is still
    /// <see cref="RawParseState.Pending"/> (E2's debounce has not fired yet) must NOT
    /// mutate the stale document — that would regenerate <c>RawText</c> from it and
    /// silently DISCARD the user's typed change. ApplyEdit re-parses synchronously
    /// first, so both edits coexist in the one document.</summary>
    [Fact]
    public async Task structured_edit_during_a_pending_raw_edit_reparses_first_so_both_changes_coexist()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        // User raw edit with NO explicit reparse — exactly the debounce window.
        vm.RawText = SampleToml.Replace("cache_size = 4096", "cache_size = 8192", StringComparison.Ordinal);
        Assert.Equal(RawParseState.Pending, vm.RawParseState);

        vm.ApplyEdit(Entry(vm, "require_dnssec"), true);

        Assert.Contains("cache_size = 8192", vm.RawText, StringComparison.Ordinal);
        Assert.Contains("require_dnssec = true", vm.RawText, StringComparison.Ordinal);
        Assert.Equal(8192L, Entry(vm, "cache_size").Value); // entries refreshed off the reparsed doc
        Assert.Equal(RawParseState.Clean, vm.RawParseState); // the text is a clean doc projection again
        Assert.True(vm.IsDirty);
    }

    /// <summary>The counterpart: pending raw text that does NOT parse must refuse the
    /// structured edit (same "fix the raw TOML" refusal as an already-Failed state) and
    /// leave the user's raw text untouched — never overwrite it from the stale doc.</summary>
    [Fact]
    public async Task structured_edit_during_an_unparseable_pending_raw_edit_is_refused_and_raw_text_survives()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        const string brokenEdit = "cache = [unclosed\n";
        vm.RawText = brokenEdit;
        Assert.Equal(RawParseState.Pending, vm.RawParseState);

        Assert.Throws<InvalidOperationException>(() => vm.ApplyEdit(Entry(vm, "require_dnssec"), true));

        Assert.Equal(brokenEdit, vm.RawText); // the user's raw edit is NOT overwritten
        Assert.Equal(RawParseState.Failed, vm.RawParseState); // the attempted reparse recorded the failure
        Assert.False(vm.IsStructuredEditable);
    }

    /// <summary>P5b-E2: parse errors grey the structured pane out ("fix the raw TOML")
    /// — the last-good document is kept for DISPLAY only and structured edits are
    /// refused until a clean re-parse.</summary>
    [Fact]
    public async Task reparse_of_broken_raw_text_disables_structured_editing_and_keeps_last_good_values()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        vm.RawText = "cache = [unclosed\n";
        vm.ReparseRawText();

        Assert.Equal(RawParseState.Failed, vm.RawParseState);
        Assert.False(vm.IsStructuredEditable);
        Assert.True(vm.IsDirty);

        // Last-good display values survive; edits against them are refused.
        var dnssec = Entry(vm, "require_dnssec");
        Assert.Equal(false, dnssec.Value);
        Assert.Throws<InvalidOperationException>(() => vm.ApplyEdit(dnssec, true));
    }

    [Fact]
    public async Task fixing_broken_raw_text_and_reparsing_reenables_structured_editing()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);
        vm.RawText = "cache = [unclosed\n";
        vm.ReparseRawText();
        Assert.False(vm.IsStructuredEditable);

        vm.RawText = SampleToml;
        vm.ReparseRawText();

        Assert.True(vm.IsStructuredEditable);
        Assert.Equal(RawParseState.Clean, vm.RawParseState);
        Assert.Equal(false, Entry(vm, "require_dnssec").Value);
    }

    // ------------------------------------------------- cycle 3: FilterText search (§8.3)

    [Fact]
    public async Task before_any_filter_every_section_and_entry_is_visible()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        Assert.Equal(vm.Sections.Count, vm.VisibleSections.Count);
        Assert.Equal(ConfigCatalog.All.Count, vm.VisibleSections.Sum(s => s.VisibleEntries.Count));
    }

    [Fact]
    public async Task filter_narrows_entries_across_sections_and_hides_empty_sections()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        vm.FilterText = "dnssec";

        Assert.True(vm.VisibleSections.Count < vm.Sections.Count);
        var serverSelection = vm.VisibleSections.Single(s => s.Name == "Server selection");
        Assert.Contains(serverSelection.VisibleEntries, e => e.KeyPath == "require_dnssec");

        // Every surviving entry actually matches — no section shows unmatched leftovers.
        Assert.All(
            vm.VisibleSections.SelectMany(s => s.VisibleEntries),
            e => Assert.True(
                e.KeyPath.Contains("dnssec", StringComparison.OrdinalIgnoreCase)
                || e.Doc.Contains("dnssec", StringComparison.OrdinalIgnoreCase)));

        vm.FilterText = "zzz_no_such_setting_anywhere";
        Assert.Empty(vm.VisibleSections);
    }

    /// <summary>Case-insensitive, and the match runs over the Doc text too:
    /// "OBLIVIOUS" only appears in odoh_servers' documentation, never in a key path.</summary>
    [Fact]
    public async Task filter_is_case_insensitive_and_searches_doc_text_too()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        vm.FilterText = "OBLIVIOUS";

        var visible = vm.VisibleSections.SelectMany(s => s.VisibleEntries).ToList();
        Assert.Contains(visible, e => e.KeyPath == "odoh_servers");
        Assert.All(visible, e => Assert.DoesNotContain("oblivious", e.KeyPath, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task clearing_the_filter_restores_every_section_and_entry()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);
        vm.FilterText = "dnssec";
        Assert.True(vm.VisibleSections.Count < vm.Sections.Count);

        vm.FilterText = string.Empty;

        Assert.Equal(vm.Sections.Count, vm.VisibleSections.Count);
        Assert.Equal(ConfigCatalog.All.Count, vm.VisibleSections.Sum(s => s.VisibleEntries.Count));
    }

    // ------------------- cycle: 5g-3/5g-6 plain-language Friendly + section descriptions

    [Fact]
    public void entry_copies_friendly_from_the_descriptor_and_null_stays_null()
    {
        var withFriendly = new SettingEntryViewModel(new SettingDescriptor(
            "k", string.Empty, SettingValueType.Bool, "false", "doc", "General", Friendly: "plain words"));
        Assert.Equal("plain words", withFriendly.Friendly);

        var withoutFriendly = new SettingEntryViewModel(new SettingDescriptor(
            "k", string.Empty, SettingValueType.Bool, "false", "doc", "General"));
        Assert.Null(withoutFriendly.Friendly);
    }

    // ------------------- 5j: unset-bool honesty (the lb_estimator report)

    [Fact]
    public async Task bool_entry_unset_shows_the_effective_default_not_a_misleading_off()
    {
        // lb_estimator: catalog default true, absent from this config → EffectiveBool must be true (on),
        // not a misleading "off" shown under "Default: true". (The user's lb_estimator report.)
        var (vm, _, _) = await LoadedAsync("server_names = ['cloudflare']\n");
        var entry = Entry(vm, "lb_estimator");

        Assert.False(entry.IsSet);        // absent → drives the "(default)" marker
        Assert.True(entry.DefaultBool);
        Assert.True(entry.EffectiveBool); // the fix: rendered off before
    }

    [Fact]
    public async Task bool_entry_explicit_value_wins_over_the_default()
    {
        var (vm, _, _) = await LoadedAsync("lb_estimator = false\n");
        var entry = Entry(vm, "lb_estimator");

        Assert.True(entry.IsSet);
        Assert.False(entry.EffectiveBool); // an explicit false overrides the true default
    }

    [Fact]
    public async Task bool_entry_unset_default_false_stays_off_honestly()
    {
        var (vm, _, _) = await LoadedAsync("server_names = ['cloudflare']\n");
        var entry = Entry(vm, "odoh_servers");

        Assert.False(entry.IsSet);
        Assert.False(entry.EffectiveBool); // unset + default false → off is the honest effective value
    }

    /// <summary>§8.3 + 5g-6: the search also runs over the plain-language Friendly text
    /// (null-safe — most entries have none until WP4), so users can find
    /// <c>local_doh.listen_addresses</c> by words that appear only in its Friendly line.</summary>
    [Fact]
    public async Task filter_searches_friendly_text_and_still_matches_keypath_and_doc()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        vm.FilterText = "accepts connections";

        var visible = vm.VisibleSections.SelectMany(s => s.VisibleEntries).ToList();
        var entry = visible.Single(e => e.KeyPath == "local_doh.listen_addresses");

        // The phrase lives ONLY in the Friendly text — proves Friendly was searched.
        Assert.DoesNotContain("accepts connections", entry.KeyPath, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("accepts connections", entry.Doc, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("accepts connections", entry.Friendly!, StringComparison.OrdinalIgnoreCase);

        // KeyPath and Doc matching are untouched.
        vm.FilterText = "require_dnssec";
        Assert.Contains(
            vm.VisibleSections.SelectMany(s => s.VisibleEntries),
            e => e.KeyPath == "require_dnssec");
        vm.FilterText = "OBLIVIOUS";
        Assert.Contains(
            vm.VisibleSections.SelectMany(s => s.VisibleEntries),
            e => e.KeyPath == "odoh_servers");
    }

    /// <summary>5g-3: the Local DoH group carries a section-level explainer (truthful:
    /// catalog-only keys, contrasts with the Dashboard's Browser-DoH switch).</summary>
    [Fact]
    public async Task local_doh_section_carries_a_description()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        var localDoh = vm.Sections.Single(s => s.Name == "Local DoH");
        Assert.False(string.IsNullOrWhiteSpace(localDoh.Description));
        Assert.Contains("Dashboard", localDoh.Description!, StringComparison.Ordinal);
    }

    /// <summary>5g WP4: EVERY group present in the catalog resolves to a non-null
    /// section Description — no section's explainer caption may collapse. Hard-locks
    /// the rule: a future catalog group without an authored explainer fails here.</summary>
    [Fact]
    public async Task every_catalog_group_section_carries_a_description()
    {
        var (vm, _, _) = await LoadedAsync(SampleToml);

        var groups = ConfigCatalog.All.Select(d => d.Group).Distinct(StringComparer.Ordinal);
        foreach (var group in groups)
        {
            var section = vm.Sections.Single(s => s.Name == group);
            Assert.False(
                string.IsNullOrWhiteSpace(section.Description),
                $"group '{group}' has no section Description");
        }
    }

    // -------------------------------- E2 cycle 1: debounced off-thread validation

    /// <summary>The panel's richness is LOCAL validation (the wire only carries the
    /// first error): the full issue list — Errors AND Warnings — publishes after the
    /// debounce, and any Error-severity issue invalidates (E3's Save gate consumes
    /// <c>IsValid</c>; the Save command itself arrives in E3).</summary>
    [Fact]
    public async Task raw_edit_with_a_schema_error_publishes_the_full_issue_list_and_invalidates()
    {
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce);
        dispatcher.Reset();

        vm.RawText = SchemaErrorToml;
        await vm.PendingValidation;

        Assert.False(vm.IsValid);
        Assert.Contains(vm.ValidationIssues, i =>
            i.KeyPath == "require_dnssec" && i.Severity == ValidationSeverity.Error);
        Assert.Contains(vm.ValidationIssues, i =>
            i.KeyPath == "x_unknown" && i.Severity == ValidationSeverity.Warning);
    }

    /// <summary>An OPSEC concern is a WARNING surface, not a schema error: the concern
    /// list populates while <c>IsValid</c> stays true (P5b-U1 — the editor always warns;
    /// blocking is a separate, protection-gated mirror).</summary>
    [Fact]
    public async Task raw_edit_with_an_opsec_violation_publishes_concerns_but_stays_schema_valid()
    {
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce);
        dispatcher.Reset();

        vm.RawText = UnsafeNetprobeToml;
        await vm.PendingValidation;

        Assert.Contains(vm.OpsecConcerns, c =>
            c.RuleId == OpsecConfigRules.NetprobeTimeoutNotZeroRuleId
            && c.Severity == OpsecConcernSeverity.KillSwitchCritical);
        Assert.True(vm.IsValid);
        Assert.Empty(vm.ValidationIssues);
    }

    /// <summary>"Every edit (structured or raw) restarts the debounce" — the structured
    /// path must feed the same pipeline.</summary>
    [Fact]
    public async Task structured_edit_restarts_the_debounced_validation_too()
    {
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce);
        dispatcher.Reset();

        vm.ApplyEdit(Entry(vm, "netprobe_timeout"), 60L);
        await vm.PendingValidation;

        Assert.Contains(vm.OpsecConcerns, c =>
            c.RuleId == OpsecConfigRules.NetprobeTimeoutNotZeroRuleId);
        Assert.True(vm.IsValid);
    }

    /// <summary>E1 marked a user raw edit <see cref="RawParseState.Pending"/> and left
    /// the re-parse to "E2's debounce" — this is that hand-off: a parse-clean candidate
    /// REPLACES the shared doc (structured values refresh) when the run publishes.</summary>
    [Fact]
    public async Task debounced_validation_resolves_a_pending_clean_raw_edit()
    {
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce);
        dispatcher.Reset();

        vm.RawText = SafeToml.Replace("cache_size = 4096", "cache_size = 8192", StringComparison.Ordinal);
        Assert.Equal(RawParseState.Pending, vm.RawParseState);

        await vm.PendingValidation;

        Assert.Equal(RawParseState.Clean, vm.RawParseState);
        Assert.True(vm.IsStructuredEditable);
        Assert.Equal(8192L, Entry(vm, "cache_size").Value);
        Assert.True(vm.IsValid);
    }

    /// <summary>The counterpart: an unparseable candidate transitions Pending → Failed
    /// (structured pane greys out), the syntax errors land in the issue list, and the
    /// fail-closed OPSEC "unparseable" concern surfaces.</summary>
    [Fact]
    public async Task debounced_validation_marks_an_unparseable_raw_edit_failed()
    {
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce);
        dispatcher.Reset();

        vm.RawText = "cache = [unclosed\n";
        await vm.PendingValidation;

        Assert.Equal(RawParseState.Failed, vm.RawParseState);
        Assert.False(vm.IsStructuredEditable);
        Assert.False(vm.IsValid);
        Assert.Contains(vm.ValidationIssues, i =>
            i.KeyPath == "(syntax)" && i.Severity == ValidationSeverity.Error);
        Assert.Contains(vm.OpsecConcerns, c =>
            c.RuleId == OpsecConfigRules.UnparseableConfigRuleId);
    }

    /// <summary>Load seeds a truthful baseline (parse-clean = valid, no findings yet)
    /// AND — finding 1 — kicks off a pristine validation run of the loaded text; a
    /// reload clears stale results from a previous edit session (IC-7's Revert routes
    /// through LoadAsync) and its own pristine run re-affirms the clean baseline.</summary>
    [Fact]
    public async Task load_seeds_a_valid_baseline_and_a_reload_clears_stale_validation_results()
    {
        var (vm, file, dispatcher) = await LoadedAsync(SafeToml, TestDebounce);
        Assert.True(vm.IsValid);
        Assert.Empty(vm.ValidationIssues);
        Assert.Empty(vm.OpsecConcerns);

        dispatcher.Reset();
        vm.RawText = SchemaErrorToml;
        await vm.PendingValidation;
        Assert.False(vm.IsValid);
        Assert.NotEmpty(vm.ValidationIssues);

        file.NextLoad = ConfigLoadResult.Ok(SafeToml, Sha);
        await vm.LoadAsync(CancellationToken.None);

        Assert.True(vm.IsValid);
        Assert.Empty(vm.ValidationIssues);
        Assert.Empty(vm.OpsecConcerns);

        // Finding 1: the reload seeds a pristine validation run over the fresh text —
        // await ITS publication and assert it re-affirms the clean baseline without
        // ever dirtying the editor (validation publication never sets IsDirty).
        dispatcher.Reset();
        await vm.PendingValidation;
        Assert.True(vm.IsValid);
        Assert.Empty(vm.ValidationIssues);
        Assert.Empty(vm.OpsecConcerns);
        Assert.False(vm.IsDirty);
    }

    [Fact]
    public async Task load_of_unparseable_toml_is_not_valid()
    {
        var (vm, _, _) = await LoadedAsync("cache = [unclosed\n", TestDebounce);

        Assert.False(vm.IsValid);
    }

    /// <summary>Finding 1 (the P5b-U1 pristine-load gap): a PRISTINE load of an
    /// OPSEC-unsafe file must publish its concerns with ZERO edits — never a Valid
    /// badge with no warnings until the first keystroke. The load itself seeds a
    /// validation run over the loaded text through the normal debounce, and that
    /// pristine publication never dirties the editor (<c>LoadedAsync</c> drains it
    /// before returning, so these assertions are deterministic).</summary>
    [Fact]
    public async Task pristine_load_of_an_opsec_unsafe_file_publishes_concerns_with_zero_edits()
    {
        var (vm, _, _) = await LoadedAsync(UnsafeNetprobeToml, TestDebounce);

        Assert.Contains(vm.OpsecConcerns, c =>
            c.RuleId == OpsecConfigRules.NetprobeTimeoutNotZeroRuleId
            && c.Severity == OpsecConcernSeverity.KillSwitchCritical);
        Assert.True(vm.IsValid);           // schema-clean: a concern warns, never invalidates
        Assert.False(vm.IsDirty);          // the pristine publication never dirties
        Assert.Equal(RawParseState.Clean, vm.RawParseState);
        Assert.Null(vm.SaveBlockedReason); // protection is OFF here — warn only (P5b-U1)
    }

    /// <summary>IC-5: the publication itself must go through the dispatcher — with a
    /// QUEUEING dispatcher the computed results must not be visible until the queued
    /// post actually runs. The gate sequences the pristine-load run (P5b-U1) and the
    /// edit's run deterministically — no run can post at an arbitrary moment.</summary>
    [Fact]
    public async Task validation_results_publish_only_inside_the_dispatched_post()
    {
        using var gate = new ManualGate();
        var file = new FakeConfigFileService { NextLoad = ConfigLoadResult.Ok(SafeToml, Sha) };
        var dispatcher = new QueueingDispatcher();
        var vm = new ConfigurationViewModel(file, new FakeStateReader(), dispatcher, TestDebounce, gate.GateAsync);
        await vm.LoadAsync(CancellationToken.None);
        await dispatcher.WaitForQueuedPostAsync();
        dispatcher.RunNext(); // the load publication — it also seeds the pristine validation run
        Assert.Equal(SafeToml, vm.RawText);

        (await gate.NextArrivalAsync()).SetResult(); // the pristine run: computes + posts inline
        await dispatcher.WaitForQueuedPostAsync();
        dispatcher.RunNext(); // its baseline publication (SafeToml is clean — harmless)
        Assert.True(vm.IsValid);

        vm.RawText = SchemaErrorToml;
        (await gate.NextArrivalAsync()).SetResult(); // the edit's run: computes + posts inline
        await dispatcher.WaitForQueuedPostAsync();

        // The run has computed and POSTED, but the post has not run: still the baseline.
        Assert.True(vm.IsValid);
        Assert.Empty(vm.ValidationIssues);

        dispatcher.RunNext();

        Assert.False(vm.IsValid);
        Assert.NotEmpty(vm.ValidationIssues);
    }

    // ------------------- E2 cycle 2: stale-session drop (deterministic, gate seam)

    /// <summary>The plan's stale-drop scenario verbatim: hold validation #1 at the gate,
    /// issue edit #2 (new session token), release #1 → #1's results are NEVER published;
    /// #2's are. The ManualGate runs a released run to completion inline, so both the
    /// negative and the positive assertion are deterministic.</summary>
    [Fact]
    public async Task stale_validation_results_are_dropped_never_published()
    {
        using var gate = new ManualGate();
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce, gate.GateAsync);
        (await gate.NextArrivalAsync()).SetResult(); // the pristine-load run: release + publish inline
        dispatcher.Reset();

        vm.RawText = SchemaErrorToml;                // edit #1
        var run1 = await gate.NextArrivalAsync();    // #1 held at the gate, past its delay

        vm.RawText = UnsafeNetprobeToml;             // edit #2 — #1's session is now stale

        run1.SetResult();                            // release #1: runs to completion inline

        Assert.Equal(0, dispatcher.PostCount);       // #1 published NOTHING
        Assert.Empty(vm.ValidationIssues);           // #1's schema errors never landed
        Assert.True(vm.IsValid);                     // still the load baseline
        Assert.Equal(RawParseState.Pending, vm.RawParseState); // #1 must not resolve #2's pending text

        var run2 = await gate.NextArrivalAsync();
        run2.SetResult();                            // release #2: publishes inline

        Assert.Equal(1, dispatcher.PostCount);
        Assert.Contains(vm.OpsecConcerns, c =>
            c.RuleId == OpsecConfigRules.NetprobeTimeoutNotZeroRuleId);
        Assert.Empty(vm.ValidationIssues);           // #2 is schema-clean
        Assert.True(vm.IsValid);
        Assert.Equal(RawParseState.Clean, vm.RawParseState);
    }

    /// <summary>Rapid successive edits collapse to EXACTLY one publication — the last
    /// text's. Every superseded run is released and runs to completion (inline) before
    /// the assertion, so "exactly one" is proven, not sampled.</summary>
    [Fact]
    public async Task rapid_successive_edits_publish_exactly_once_for_the_last_text()
    {
        using var gate = new ManualGate();
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce, gate.GateAsync);
        (await gate.NextArrivalAsync()).SetResult(); // the pristine-load run: release + publish inline
        dispatcher.Reset();

        vm.RawText = SchemaErrorToml;                              // edit A
        var runA = await gate.NextArrivalAsync();
        vm.RawText = SchemaErrorToml + "y_unknown = 2\n";          // edit B
        var runB = await gate.NextArrivalAsync();
        vm.RawText = UnsafeNetprobeToml;                           // edit C (last)
        var runC = await gate.NextArrivalAsync();

        runA.SetResult();
        runB.SetResult();
        Assert.Equal(0, dispatcher.PostCount); // superseded runs never publish

        runC.SetResult();

        Assert.Equal(1, dispatcher.PostCount); // exactly one publication — the last text's
        Assert.True(vm.IsValid);
        Assert.Empty(vm.ValidationIssues);
        Assert.Contains(vm.OpsecConcerns, c =>
            c.RuleId == OpsecConfigRules.NetprobeTimeoutNotZeroRuleId);
    }

    /// <summary>A reload (IC-7 Revert / E3's Conflict-Reload) discards unsaved edits —
    /// INCLUDING their in-flight validation session: a run held past its delay when the
    /// reload lands must never publish the discarded edit's findings over the fresh
    /// baseline.</summary>
    [Fact]
    public async Task reload_discards_a_pending_validation_session()
    {
        using var gate = new ManualGate();
        var (vm, file, dispatcher) = await LoadedAsync(SafeToml, TestDebounce, gate.GateAsync);
        (await gate.NextArrivalAsync()).SetResult(); // the pristine-load run: release + publish inline
        dispatcher.Reset();

        vm.RawText = SchemaErrorToml;               // an edit whose session is in flight
        var run1 = await gate.NextArrivalAsync();

        file.NextLoad = ConfigLoadResult.Ok(SafeToml, Sha);
        await vm.LoadAsync(CancellationToken.None); // Revert: discards the edit
        dispatcher.Reset();

        run1.SetResult();                            // the orphaned run finishes inline

        Assert.Equal(0, dispatcher.PostCount);       // …and published nothing
        Assert.True(vm.IsValid);
        Assert.Empty(vm.ValidationIssues);
        Assert.Empty(vm.OpsecConcerns);
        Assert.False(vm.IsDirty);
        Assert.Equal(RawParseState.Clean, vm.RawParseState);
    }

    // -------------- E2 cycle 3: client-side OPSEC save-block mirror (P5b-U1, F24)

    private const string GuardReasonSuffix =
        "disable protection to save an off-spec config, or fix the flagged keys";

    /// <summary>P5b-U1 while protection is ON: a KillSwitchCritical concern sets
    /// <c>SaveBlockedReason</c> — the Save-disabling banner, worded per the plan. UX
    /// mirror ONLY: the helper-side write policy enforces regardless (IC-3/IC-4).</summary>
    [Fact]
    public async Task protection_on_with_a_killswitch_critical_concern_blocks_save_with_the_guard_reason()
    {
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce, protectionEnabled: true);
        Assert.Null(vm.SaveBlockedReason); // load baseline: nothing blocked yet
        dispatcher.Reset();

        vm.RawText = UnsafeNetprobeToml;
        await vm.PendingValidation;

        Assert.NotNull(vm.SaveBlockedReason);
        Assert.StartsWith("OPSEC guard: ", vm.SaveBlockedReason, StringComparison.Ordinal);
        Assert.Contains("netprobe_timeout", vm.SaveBlockedReason, StringComparison.Ordinal);
        Assert.EndsWith(GuardReasonSuffix, vm.SaveBlockedReason, StringComparison.Ordinal);
        Assert.True(vm.IsValid); // blocked is not INVALID — the schema is fine
    }

    /// <summary>ProtectionCritical concerns block a protected save too (they break the
    /// loopback re-point even though the kill switch itself survives).</summary>
    [Fact]
    public async Task protection_on_with_a_protection_critical_concern_blocks_save()
    {
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce, protectionEnabled: true);
        dispatcher.Reset();

        vm.RawText = SafeToml + "listen_addresses = ['0.0.0.0:5353']\n";
        await vm.PendingValidation;

        Assert.NotNull(vm.SaveBlockedReason);
        Assert.Contains("listen_addresses", vm.SaveBlockedReason, StringComparison.Ordinal);
    }

    /// <summary>The same unsafe text with protection OFF: warn prominently, never block
    /// (the user may legitimately stage an off-spec config while unprotected).</summary>
    [Fact]
    public async Task protection_off_with_the_same_concern_warns_only_and_does_not_block()
    {
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce, protectionEnabled: false);
        dispatcher.Reset();

        vm.RawText = UnsafeNetprobeToml;
        await vm.PendingValidation;

        Assert.Null(vm.SaveBlockedReason);
        Assert.NotEmpty(vm.OpsecConcerns); // the warning surface still shows everything
        Assert.True(vm.IsValid);
    }

    /// <summary>Advisory concerns never block anything — even while protected.</summary>
    [Fact]
    public async Task protection_on_with_an_advisory_only_concern_does_not_block()
    {
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce, protectionEnabled: true);
        dispatcher.Reset();

        vm.RawText = SafeToml + "netprobe_address = \"9.9.9.9:53\"\n";
        await vm.PendingValidation;

        Assert.Null(vm.SaveBlockedReason);
        Assert.Contains(vm.OpsecConcerns, c => c.Severity == OpsecConcernSeverity.Advisory);
    }

    /// <summary>The banner names EVERY blocking concern (mirroring the helper policy's
    /// joined message, IC-10) — not just the first.</summary>
    [Fact]
    public async Task blocked_reason_joins_every_critical_concern()
    {
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce, protectionEnabled: true);
        dispatcher.Reset();

        // netprobe_timeout wrong AND ignore_system_dns missing: two KillSwitchCritical.
        vm.RawText = "netprobe_timeout = 60\n";
        await vm.PendingValidation;

        Assert.NotNull(vm.SaveBlockedReason);
        Assert.Contains("netprobe_timeout", vm.SaveBlockedReason, StringComparison.Ordinal);
        Assert.Contains("ignore_system_dns", vm.SaveBlockedReason, StringComparison.Ordinal);
    }

    /// <summary>Fixing the flagged keys clears the block on the next publication — the
    /// banner must never stick to an already-repaired editor.</summary>
    [Fact]
    public async Task a_fixing_edit_clears_the_blocked_reason()
    {
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce, protectionEnabled: true);
        dispatcher.Reset();

        vm.RawText = UnsafeNetprobeToml;
        await vm.PendingValidation;
        Assert.NotNull(vm.SaveBlockedReason);

        vm.RawText = SafeToml;
        await vm.PendingValidation;

        Assert.Null(vm.SaveBlockedReason);
        Assert.Empty(vm.OpsecConcerns);
    }

    // -------------------------- E3 cycle 1: Save & apply — gate, currency, dispatch

    /// <summary>A schema-clean, OPSEC-clean edit of <see cref="SafeToml"/> for tests
    /// that need a legitimately saveable candidate.</summary>
    private static readonly string SafeEditedToml =
        SafeToml.Replace("cache_size = 4096", "cache_size = 8192", StringComparison.Ordinal);

    /// <summary>Scripts the fake so a save "writes the disk" (the next Load returns the
    /// saved text under <paramref name="newSha"/>) and reports Applied — the fake-disk
    /// counterpart of the helper's successful compare-and-swap + restart.</summary>
    private static void ScriptAppliedSave(FakeConfigFileService file, string newSha)
    {
        file.SaveHandler = (text, _, _) =>
        {
            file.NextLoad = ConfigLoadResult.Ok(text, newSha);
            return Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));
        };
    }

    /// <summary>The E3 enable gate verbatim: <c>IsDirty &amp;&amp; IsValid &amp;&amp;
    /// SaveBlockedReason is null &amp;&amp; !IsBusy</c>. A freshly loaded editor has
    /// nothing to save; a valid edit arms the command.</summary>
    [Fact]
    public async Task save_is_enabled_only_after_a_dirtying_edit()
    {
        var (vm, _, _) = await LoadedAsync(SafeToml);
        Assert.False(vm.CanSave);
        Assert.False(vm.SaveAndApplyCommand.CanExecute(null));

        vm.RawText = SafeEditedToml;

        Assert.True(vm.CanSave);
        Assert.True(vm.SaveAndApplyCommand.CanExecute(null));
    }

    [Fact]
    public async Task save_is_disabled_while_the_published_validation_has_errors()
    {
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce);
        dispatcher.Reset();

        vm.RawText = SchemaErrorToml;
        await vm.PendingValidation;

        Assert.False(vm.IsValid);
        Assert.False(vm.CanSave);
    }

    [Fact]
    public async Task save_is_disabled_while_the_opsec_mirror_blocks()
    {
        var (vm, _, dispatcher) = await LoadedAsync(SafeToml, TestDebounce, protectionEnabled: true);
        dispatcher.Reset();

        vm.RawText = UnsafeNetprobeToml;
        await vm.PendingValidation;

        Assert.NotNull(vm.SaveBlockedReason);
        Assert.False(vm.CanSave);
    }

    /// <summary>The save-while-debounce-pending scenario (pre-flight fix): with a
    /// NEVER-firing debounce the published <c>IsValid</c> is still the stale load
    /// baseline (true) when the user hits Save on schema-broken text — the enable gate
    /// alone would let it through. Save must synchronously re-validate the EXACT
    /// <c>RawText</c> being sent and abort WITHOUT dispatching, with the validation
    /// panel updated to explain why.</summary>
    [Fact]
    public async Task save_revalidates_synchronously_and_aborts_without_dispatch_on_invalid_pending_text()
    {
        var (vm, file, _) = await LoadedAsync(SafeToml); // NeverDebounce: no publication will fire
        vm.RawText = SchemaErrorToml;
        Assert.True(vm.CanSave); // the STALE gate would allow it — exactly the race

        await vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Empty(file.SaveCalls); // never dispatched
        Assert.False(vm.IsValid);     // the sync re-run published the truth
        Assert.Contains(vm.ValidationIssues, i =>
            i.KeyPath == "require_dnssec" && i.Severity == ValidationSeverity.Error);
        Assert.False(vm.IsBusy);
    }

    /// <summary>The same currency re-run covers the OPSEC mirror: protection ON + an
    /// unsafe pending edit must abort client-side before a frame is ever sent
    /// (P5b-U1 — the helper would refuse it anyway; this is the UX mirror).</summary>
    [Fact]
    public async Task save_revalidates_the_opsec_mirror_synchronously_and_aborts_while_protected()
    {
        var (vm, file, _) = await LoadedAsync(SafeToml, protectionEnabled: true);
        vm.RawText = UnsafeNetprobeToml;
        Assert.Null(vm.SaveBlockedReason); // stale — the debounce never fired

        await vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Empty(file.SaveCalls);
        Assert.NotNull(vm.SaveBlockedReason);
        Assert.StartsWith("OPSEC guard: ", vm.SaveBlockedReason, StringComparison.Ordinal);
    }

    /// <summary>The dispatch itself: the EXACT current raw text with the LOAD-time base
    /// sha (P5b-E8 — the load snapshot, never a rebase). The sync re-validation also
    /// resolves the Pending raw-parse state before anything is sent.</summary>
    [Fact]
    public async Task save_dispatches_the_current_raw_text_with_the_load_time_base_sha()
    {
        var (vm, file, _) = await LoadedAsync(SafeToml);
        ScriptAppliedSave(file, new string('b', 64));

        vm.RawText = SafeEditedToml;
        Assert.Equal(RawParseState.Pending, vm.RawParseState);

        await vm.SaveAndApplyCommand.ExecuteAsync(null);

        var call = Assert.Single(file.SaveCalls);
        Assert.Equal(SafeEditedToml, call.Text);
        Assert.Equal(Sha, call.BaseSha256);
    }

    /// <summary>Applied → reload fresh from disk: new base sha, dirty cleared, and the
    /// transient "saved" notice shown.</summary>
    [Fact]
    public async Task applied_outcome_reloads_from_disk_clears_dirty_and_shows_the_saved_notice()
    {
        var (vm, file, _) = await LoadedAsync(SafeToml);
        var newSha = new string('b', 64);
        ScriptAppliedSave(file, newSha);
        var loadsBefore = file.LoadCalls;

        vm.RawText = SafeEditedToml;
        await vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Equal(loadsBefore + 1, file.LoadCalls); // re-read the disk, not trust the editor
        Assert.Equal(newSha, vm.BaseSha256);
        Assert.Equal(SafeEditedToml, vm.RawText);
        Assert.False(vm.IsDirty);
        Assert.False(vm.IsBusy);
        Assert.NotNull(vm.SaveNotice);
    }

    /// <summary>The double-save sequence (pre-flight fix): after an Applied save the
    /// fake disk holds the new bytes under a new sha — a second edit + save must carry
    /// the sha of the POST-first-save bytes, never the original load sha.</summary>
    [Fact]
    public async Task double_save_carries_the_post_first_save_sha_not_the_original()
    {
        var (vm, file, _) = await LoadedAsync(SafeToml);
        var shaAfterFirstSave = new string('b', 64);
        ScriptAppliedSave(file, shaAfterFirstSave);

        vm.RawText = SafeEditedToml;
        await vm.SaveAndApplyCommand.ExecuteAsync(null);
        Assert.Equal(Sha, file.SaveCalls[0].BaseSha256);

        ScriptAppliedSave(file, new string('c', 64));
        vm.RawText = SafeEditedToml.Replace("cache_size = 8192", "cache_size = 1024", StringComparison.Ordinal);
        await vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Equal(2, file.SaveCalls.Count);
        Assert.Equal(shaAfterFirstSave, file.SaveCalls[1].BaseSha256);
    }

    /// <summary>Double-click protection: a second invocation while a save is in flight
    /// is IGNORED (single busy owner, IC-5 — mirror of Dashboard's <c>_inFlight</c>).</summary>
    [Fact]
    public async Task save_reentry_while_busy_is_ignored()
    {
        var (vm, file, _) = await LoadedAsync(SafeToml);
        var held = new TaskCompletionSource<ConfigSaveOutcome>(TaskCreationOptions.RunContinuationsAsynchronously);
        file.SaveHandler = (_, _, _) => held.Task;

        vm.RawText = SafeEditedToml;
        var firstSave = vm.SaveAndApplyCommand.ExecuteAsync(null);
        Assert.True(vm.IsBusy);
        Assert.False(vm.CanSave); // busy disables the gate too

        await vm.SaveAndApplyCommand.ExecuteAsync(null); // the double-click: completes as a no-op

        Assert.Single(file.SaveCalls);

        var newSha = new string('b', 64);
        file.NextLoad = ConfigLoadResult.Ok(SafeEditedToml, newSha);
        held.SetResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));
        await firstSave;

        Assert.False(vm.IsBusy);
        Assert.Single(file.SaveCalls);
        Assert.Equal(newSha, vm.BaseSha256);
    }

    /// <summary>Mid-flight edit clobber guard: an edit typed while a save is in flight
    /// (the view disables the editors while busy, but a keystroke can land before the
    /// disable renders — and the VM seam is reachable regardless) must SURVIVE every
    /// write-landed outcome: never clobbered by an outcome reload, never orphaned by a
    /// forced IsDirty=false. The raw text no longer equals the DISPATCHED candidate,
    /// so the outcome handling must keep the editor dirty and skip its reload.</summary>
    [Theory]
    [InlineData(ConfigSaveOutcomeKind.Applied)]
    [InlineData(ConfigSaveOutcomeKind.RestartFailed)]
    [InlineData(ConfigSaveOutcomeKind.ProxyRejected)]
    public async Task edit_made_while_a_save_is_in_flight_survives_the_outcome(ConfigSaveOutcomeKind kind)
    {
        var (vm, file, _) = await LoadedAsync(SafeToml);
        var held = new TaskCompletionSource<ConfigSaveOutcome>(TaskCreationOptions.RunContinuationsAsynchronously);
        file.SaveHandler = (text, _, _) =>
        {
            file.NextLoad = ConfigLoadResult.Ok(text, new string('b', 64)); // the write lands on the fake disk
            return held.Task;
        };
        vm.RawText = SafeEditedToml;
        var save = vm.SaveAndApplyCommand.ExecuteAsync(null);
        Assert.True(vm.IsBusy);

        var midFlightEdit = SafeEditedToml + "cache_min_ttl = 600\n";
        vm.RawText = midFlightEdit; // typed in the in-flight window
        var loadsBefore = file.LoadCalls;

        held.SetResult(new ConfigSaveOutcome(kind, "went wrong (or right)"));
        await save;

        Assert.Equal(midFlightEdit, vm.RawText);       // never clobbered by a reload
        Assert.True(vm.IsDirty);                       // never orphaned — still saveable
        Assert.Equal(loadsBefore, file.LoadCalls);     // the reload was SKIPPED, not survived by luck
        Assert.False(vm.IsBusy);
    }

    /// <summary>The "saved" notice is TRANSIENT: the next edit clears it (a stale green
    /// notice over a dirty editor would be a lie).</summary>
    [Fact]
    public async Task an_edit_clears_the_transient_saved_notice()
    {
        var (vm, file, _) = await LoadedAsync(SafeToml);
        ScriptAppliedSave(file, new string('b', 64));
        vm.RawText = SafeEditedToml;
        await vm.SaveAndApplyCommand.ExecuteAsync(null);
        Assert.NotNull(vm.SaveNotice);

        vm.RawText = SafeToml;

        Assert.Null(vm.SaveNotice);
    }

    // ------------------------------------- E3 cycle 2: failure outcomes → states

    /// <summary>The fake disk's sha after a WRITE-LANDED outcome — what a reload
    /// re-bases <c>BaseSha256</c> onto (finding 2).</summary>
    private static readonly string PostWriteSha = new('f', 64);

    /// <summary>Loads <see cref="SafeToml"/>, makes a valid edit, and runs one save
    /// that the fake resolves with <paramref name="outcome"/>. For the WRITE-LANDED
    /// kinds (RestartFailed/ProxyRejected) the fake disk really holds the candidate
    /// afterwards — the next Load returns it under <see cref="PostWriteSha"/>, exactly
    /// like the helper's landed compare-and-swap.</summary>
    private static async Task<(ConfigurationViewModel Vm, FakeConfigFileService File)> SavedWithOutcomeAsync(
        ConfigSaveOutcome outcome)
    {
        var (vm, file, _) = await LoadedAsync(SafeToml);
        file.SaveHandler = (text, _, _) =>
        {
            if (outcome.Kind is ConfigSaveOutcomeKind.RestartFailed or ConfigSaveOutcomeKind.ProxyRejected)
            {
                file.NextLoad = ConfigLoadResult.Ok(text, PostWriteSha);
            }

            return Task.FromResult(outcome);
        };
        vm.RawText = SafeEditedToml;
        await vm.SaveAndApplyCommand.ExecuteAsync(null);
        return (vm, file);
    }

    /// <summary>BE-6 surfaced: the helper refused the compare-and-swap. The banner
    /// carries the helper's message VERBATIM (IC-10) and the user's edits stay in the
    /// editor untouched — reloading is an explicit user action, never automatic.</summary>
    [Fact]
    public async Task conflict_outcome_raises_the_banner_and_keeps_the_users_text()
    {
        const string helperMessage = "config file changed on disk since it was loaded — reload before saving";
        var (vm, _) = await SavedWithOutcomeAsync(
            new ConfigSaveOutcome(ConfigSaveOutcomeKind.Conflict, helperMessage));

        Assert.Equal(helperMessage, vm.ConflictMessage);
        Assert.Equal(SafeEditedToml, vm.RawText); // the user's text survives
        Assert.True(vm.IsDirty);                  // nothing was written
        Assert.Equal(Sha, vm.BaseSha256);         // the base did not silently rebase
        Assert.False(vm.IsBusy);
        Assert.Null(vm.SaveNotice);
    }

    /// <summary>The banner's [Reload] action is <c>LoadAsync</c>: it picks up the new
    /// on-disk file (text + fresh CAS base) and clears the banner.</summary>
    [Fact]
    public async Task reload_after_a_conflict_clears_the_banner_and_picks_up_the_new_disk_file()
    {
        var (vm, file) = await SavedWithOutcomeAsync(
            new ConfigSaveOutcome(ConfigSaveOutcomeKind.Conflict, "changed on disk"));
        var newSha = new string('d', 64);
        file.NextLoad = ConfigLoadResult.Ok(UnsafeNetprobeToml, newSha);

        await vm.LoadAsync(CancellationToken.None);

        Assert.Null(vm.ConflictMessage);
        Assert.Equal(UnsafeNetprobeToml, vm.RawText);
        Assert.Equal(newSha, vm.BaseSha256);
        Assert.False(vm.IsDirty);
    }

    /// <summary>Schema/OPSEC refusals from the helper land in the error panel verbatim
    /// (IC-10) — and nothing was written, so the editor stays dirty for a fix + retry.</summary>
    [Fact]
    public async Task rejected_outcome_shows_the_helper_message_verbatim_and_keeps_the_editor_dirty()
    {
        const string helperMessage = "OPSEC guard: netprobe_timeout must be 0 while protection is enabled";
        var (vm, _) = await SavedWithOutcomeAsync(
            new ConfigSaveOutcome(ConfigSaveOutcomeKind.Rejected, helperMessage));

        Assert.Equal(helperMessage, vm.SaveError);
        Assert.True(vm.IsDirty);
        Assert.Equal(SafeEditedToml, vm.RawText);
        Assert.Null(vm.SaveNotice);
    }

    [Theory]
    [InlineData(ConfigSaveOutcomeKind.HelperUnavailable,
        "the helper did not reply to the save — it may not have been applied; reload before retrying")]
    [InlineData(ConfigSaveOutcomeKind.TooLarge,
        "config is too large to send to the helper (limit 1 MiB per request) — trim it before saving")]
    public async Task helper_unavailable_and_too_large_surface_their_own_messages(
        ConfigSaveOutcomeKind kind, string message)
    {
        var (vm, _) = await SavedWithOutcomeAsync(new ConfigSaveOutcome(kind, message));

        Assert.Equal(message, vm.SaveError);
        Assert.True(vm.IsDirty); // no confirmed write — the edits still need saving
        Assert.Null(vm.SaveNotice);
    }

    /// <summary>P5b-E1's skew gate outcome gets its own banner (mirroring the
    /// Dashboard's F20 state), distinct from the ordinary error panel.</summary>
    [Fact]
    public async Task helper_incompatible_outcome_raises_the_f20_mirror_banner()
    {
        const string message =
            "helper protocol version 1 does not match this app's (2) — update the helper and app together, then retry";
        var (vm, _) = await SavedWithOutcomeAsync(
            new ConfigSaveOutcome(ConfigSaveOutcomeKind.HelperIncompatible, message));

        Assert.Equal(message, vm.HelperIncompatibleMessage);
        Assert.Null(vm.SaveError); // its own banner, not the generic panel
        Assert.True(vm.IsDirty);   // nothing was sent, let alone written
    }

    /// <summary>The write LANDED but the restart is unverified: a persistent non-green
    /// state with the message verbatim. The editor text IS the on-disk text now, so the
    /// editor is no longer dirty (Save disabled) — and because the write landed, the
    /// outcome reloads from disk so <c>BaseSha256</c> re-bases onto the REAL on-disk
    /// bytes (finding 2: a stale base would turn every follow-up re-edit save into a
    /// misleading Conflict whose Reload discards the fix).</summary>
    [Fact]
    public async Task restart_failed_outcome_is_persistent_with_the_message_verbatim_and_marks_the_editor_clean()
    {
        const string message = "config saved, but the proxy restart failed or its reply was lost — status unverified";
        var (vm, _) = await SavedWithOutcomeAsync(
            new ConfigSaveOutcome(ConfigSaveOutcomeKind.RestartFailed, message));

        Assert.Equal(message, vm.RestartFailedMessage);
        Assert.False(vm.IsDirty);
        Assert.False(vm.CanSave);
        Assert.Null(vm.SaveNotice); // never green
        Assert.Equal(SafeEditedToml, vm.RawText); // the (saved) text stays on screen
        Assert.Equal(PostWriteSha, vm.BaseSha256); // re-based onto the landed write
    }

    /// <summary>§7.3: write + restart succeeded but the proxy never reported running —
    /// a persistent, never-green error state ("Revert or re-edit"). The write landed,
    /// so the CAS base re-bases here too (finding 2).</summary>
    [Fact]
    public async Task proxy_rejected_outcome_is_a_persistent_never_green_state()
    {
        const string message =
            "config saved and restart issued, but the proxy did not report running — the new config appears rejected by the proxy";
        var (vm, _) = await SavedWithOutcomeAsync(
            new ConfigSaveOutcome(ConfigSaveOutcomeKind.ProxyRejected, message));

        Assert.Equal(message, vm.ProxyRejectedMessage);
        Assert.False(vm.IsDirty);
        Assert.Null(vm.SaveNotice);
        Assert.Equal(PostWriteSha, vm.BaseSha256); // re-based onto the landed write
    }

    /// <summary>Finding 2's user-visible symptom, pinned end-to-end: the recommended
    /// RE-EDIT path after a write-landed outcome must dispatch the NEW on-disk sha —
    /// with a stale base every such save would come back as a Conflict whose Reload
    /// throws away the user's fix.</summary>
    [Theory]
    [InlineData(ConfigSaveOutcomeKind.RestartFailed)]
    [InlineData(ConfigSaveOutcomeKind.ProxyRejected)]
    public async Task a_save_after_a_write_landed_outcome_sends_the_new_on_disk_sha(ConfigSaveOutcomeKind kind)
    {
        var (vm, file) = await SavedWithOutcomeAsync(new ConfigSaveOutcome(kind, "went wrong"));
        Assert.Equal(PostWriteSha, vm.BaseSha256); // the outcome reload re-based

        ScriptAppliedSave(file, new string('c', 64));
        vm.RawText = SafeToml; // the recommended re-edit
        await vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Equal(2, file.SaveCalls.Count);
        Assert.Equal(PostWriteSha, file.SaveCalls[1].BaseSha256); // NOT the load-time sha
        Assert.NotNull(vm.SaveNotice); // and the save applied cleanly — no manufactured Conflict
    }

    /// <summary>A NEW save attempt starts clean: the previous attempt's rejection
    /// message must not linger under a success.</summary>
    [Fact]
    public async Task a_new_save_attempt_clears_the_previous_rejection_message()
    {
        var (vm, file) = await SavedWithOutcomeAsync(
            new ConfigSaveOutcome(ConfigSaveOutcomeKind.Rejected, "refused"));
        Assert.NotNull(vm.SaveError);

        ScriptAppliedSave(file, new string('b', 64));
        await vm.SaveAndApplyCommand.ExecuteAsync(null); // still dirty — retry directly

        Assert.Null(vm.SaveError);
        Assert.NotNull(vm.SaveNotice);
    }

    [Fact]
    public async Task a_successful_save_clears_a_previous_conflict_banner()
    {
        var (vm, file) = await SavedWithOutcomeAsync(
            new ConfigSaveOutcome(ConfigSaveOutcomeKind.Conflict, "changed on disk"));
        Assert.NotNull(vm.ConflictMessage);

        ScriptAppliedSave(file, new string('b', 64));
        await vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Null(vm.ConflictMessage);
        Assert.NotNull(vm.SaveNotice);
    }

    /// <summary>"Clears only on next successful Applied or Revert" — this is the
    /// Applied half (Revert is cycle 3).</summary>
    [Fact]
    public async Task applied_clears_a_previous_proxy_rejected_state()
    {
        var (vm, file) = await SavedWithOutcomeAsync(
            new ConfigSaveOutcome(ConfigSaveOutcomeKind.ProxyRejected, "proxy rejected it"));
        Assert.NotNull(vm.ProxyRejectedMessage);

        ScriptAppliedSave(file, new string('b', 64));
        vm.RawText = SafeToml; // re-edit (ProxyRejected left the editor clean)
        await vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Null(vm.ProxyRejectedMessage);
        Assert.NotNull(vm.SaveNotice);
    }

    [Fact]
    public async Task applied_clears_a_previous_restart_failed_state()
    {
        var (vm, file) = await SavedWithOutcomeAsync(
            new ConfigSaveOutcome(ConfigSaveOutcomeKind.RestartFailed, "restart lost"));
        Assert.NotNull(vm.RestartFailedMessage);

        ScriptAppliedSave(file, new string('b', 64));
        vm.RawText = SafeToml; // re-edit (RestartFailed left the editor clean)
        await vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Null(vm.RestartFailedMessage);
        Assert.NotNull(vm.SaveNotice);
    }

    // ---------------------- E3 cycle 3: Revert (IC-7) + tab-activation freshness

    /// <summary>IC-7 pins the button label — the view binds this constant.</summary>
    [Fact]
    public void revert_label_is_the_ic7_wording()
    {
        Assert.Equal("Revert to on-disk config", ConfigurationViewModel.RevertLabel);
    }

    /// <summary>Revert enabled when <c>IsDirty || ProxyRejected || RestartFailed</c> —
    /// a freshly loaded clean editor has nothing to revert.</summary>
    [Fact]
    public async Task revert_is_enabled_only_after_a_dirtying_edit_on_a_healthy_editor()
    {
        var (vm, _, _) = await LoadedAsync(SafeToml);
        Assert.False(vm.CanRevert);
        Assert.False(vm.RevertCommand.CanExecute(null));

        vm.RawText = SafeEditedToml;

        Assert.True(vm.CanRevert);
        Assert.True(vm.RevertCommand.CanExecute(null));
    }

    /// <summary>The persistent post-save failure states arm Revert even though they
    /// left the editor CLEAN — Revert is their documented recovery path.</summary>
    [Theory]
    [InlineData(ConfigSaveOutcomeKind.RestartFailed)]
    [InlineData(ConfigSaveOutcomeKind.ProxyRejected)]
    public async Task revert_is_enabled_in_a_post_save_failure_state_even_though_the_editor_is_clean(
        ConfigSaveOutcomeKind kind)
    {
        var (vm, _) = await SavedWithOutcomeAsync(new ConfigSaveOutcome(kind, "went wrong"));

        Assert.False(vm.IsDirty);
        Assert.True(vm.CanRevert);
    }

    /// <summary>IC-7: Revert re-reads the on-disk file and discards unsaved edits —
    /// it never reaches the helper-side backup slot (nothing here talks to the helper).</summary>
    [Fact]
    public async Task revert_restores_the_on_disk_text_and_clears_the_save_surfaces()
    {
        var (vm, file, _) = await LoadedAsync(SafeToml);
        file.SaveHandler = (_, _, _) => Task.FromResult(
            new ConfigSaveOutcome(ConfigSaveOutcomeKind.Rejected, "refused"));
        vm.RawText = SafeEditedToml;
        await vm.SaveAndApplyCommand.ExecuteAsync(null);
        Assert.NotNull(vm.SaveError);

        await vm.RevertCommand.ExecuteAsync(null);

        Assert.Equal(SafeToml, vm.RawText); // the on-disk text, not the edit
        Assert.Equal(Sha, vm.BaseSha256);
        Assert.False(vm.IsDirty);
        Assert.Null(vm.SaveError);
        Assert.False(vm.IsBusy);
        Assert.Empty(file.SaveCalls.Skip(1)); // revert never dispatched anything
    }

    /// <summary>"Clears only on next successful Applied or Revert" — the Revert half
    /// for ProxyRejected, and RestartFailed's Revert exit alongside it.</summary>
    [Theory]
    [InlineData(ConfigSaveOutcomeKind.RestartFailed)]
    [InlineData(ConfigSaveOutcomeKind.ProxyRejected)]
    public async Task revert_clears_the_persistent_post_save_failure_states(ConfigSaveOutcomeKind kind)
    {
        var (vm, _) = await SavedWithOutcomeAsync(new ConfigSaveOutcome(kind, "went wrong"));

        await vm.RevertCommand.ExecuteAsync(null);

        Assert.Null(vm.RestartFailedMessage);
        Assert.Null(vm.ProxyRejectedMessage);
        Assert.False(vm.CanRevert); // nothing left to revert
    }

    /// <summary>The single busy owner covers Revert too: a revert issued while a save
    /// is in flight is ignored (it would reload state mid-save).</summary>
    [Fact]
    public async Task revert_while_a_save_is_in_flight_is_ignored()
    {
        var (vm, file, _) = await LoadedAsync(SafeToml);
        var held = new TaskCompletionSource<ConfigSaveOutcome>(TaskCreationOptions.RunContinuationsAsynchronously);
        file.SaveHandler = (_, _, _) => held.Task;
        vm.RawText = SafeEditedToml;
        var save = vm.SaveAndApplyCommand.ExecuteAsync(null);
        var loadsBefore = file.LoadCalls;

        Assert.False(vm.CanRevert); // busy disables the gate
        await vm.RevertCommand.ExecuteAsync(null); // and a direct invocation is a no-op

        Assert.Equal(loadsBefore, file.LoadCalls);
        Assert.Equal(SafeEditedToml, vm.RawText);

        held.SetResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Rejected, "refused"));
        await save;
    }

    /// <summary>Tab-activation freshness: a CLEAN, idle editor silently reloads so the
    /// tab never shows a stale file after outside changes.</summary>
    [Fact]
    public async Task activation_reload_refreshes_a_clean_editor_from_disk()
    {
        var (vm, file, _) = await LoadedAsync(SafeToml);
        var newSha = new string('e', 64);
        file.NextLoad = ConfigLoadResult.Ok(UnsafeNetprobeToml, newSha);
        var loadsBefore = file.LoadCalls;

        await vm.OnTabActivatedAsync();

        Assert.Equal(loadsBefore + 1, file.LoadCalls);
        Assert.Equal(UnsafeNetprobeToml, vm.RawText);
        Assert.Equal(newSha, vm.BaseSha256);
    }

    /// <summary>NEVER while dirty: a tab switch must not silently discard edits.</summary>
    [Fact]
    public async Task activation_reload_is_skipped_while_the_editor_is_dirty()
    {
        var (vm, file, _) = await LoadedAsync(SafeToml);
        vm.RawText = SafeEditedToml;
        var loadsBefore = file.LoadCalls;

        await vm.OnTabActivatedAsync();

        Assert.Equal(loadsBefore, file.LoadCalls);
        Assert.Equal(SafeEditedToml, vm.RawText); // the edit survives the tab switch
        Assert.True(vm.IsDirty);
    }

    /// <summary>The 5g-2 deep-link's arming contract (WP2 review fix): the deep link arms its
    /// one-shot section re-apply ONLY when <c>WillReloadOnActivation</c> says a reload (and
    /// therefore a VisibleSections replacement) is coming. So the predicate must mirror the
    /// activation guard exactly, and a REFUSED activation must leave the VisibleSections
    /// reference untouched — otherwise a stale armed handler would fire on the next filter
    /// keystroke and yank the user's section selection back to the deep-link target.</summary>
    [Fact]
    public async Task will_reload_on_activation_mirrors_the_guard_and_a_refused_activation_keeps_visible_sections()
    {
        var (vm, _, _) = await LoadedAsync(SafeToml);
        Assert.True(vm.WillReloadOnActivation); // clean + idle: a reload (replacement) is coming

        vm.RawText = SafeEditedToml;            // dirty: activation must refuse
        Assert.False(vm.WillReloadOnActivation);

        var sectionsBefore = vm.VisibleSections;
        await vm.OnTabActivatedAsync();
        Assert.Same(sectionsBefore, vm.VisibleSections); // refused ⇒ NOT replaced ⇒ arming would be stale
    }

    /// <summary>ProxyRejected persists across an unrelated (activation) refresh — the
    /// refresh still runs (the editor is clean) and re-bases the sha, but the
    /// never-green state survives; only Applied or Revert clear it. RestartFailed, by
    /// contrast, has "successful refresh" among its defined exits.</summary>
    [Fact]
    public async Task proxy_rejected_persists_across_an_activation_refresh_and_clears_on_revert()
    {
        var (vm, file) = await SavedWithOutcomeAsync(
            new ConfigSaveOutcome(ConfigSaveOutcomeKind.ProxyRejected, "proxy rejected it"));
        var newSha = new string('e', 64);
        file.NextLoad = ConfigLoadResult.Ok(SafeEditedToml, newSha); // the disk holds the saved bytes
        var loadsBefore = file.LoadCalls;

        await vm.OnTabActivatedAsync();

        Assert.Equal(loadsBefore + 1, file.LoadCalls); // the refresh really ran
        Assert.Equal(newSha, vm.BaseSha256);           // and re-based the stale sha
        Assert.NotNull(vm.ProxyRejectedMessage);       // but the state survives it

        await vm.RevertCommand.ExecuteAsync(null);

        Assert.Null(vm.ProxyRejectedMessage);
    }

    [Fact]
    public async Task restart_failed_clears_on_a_successful_activation_refresh()
    {
        var (vm, file) = await SavedWithOutcomeAsync(
            new ConfigSaveOutcome(ConfigSaveOutcomeKind.RestartFailed, "restart lost"));
        file.NextLoad = ConfigLoadResult.Ok(SafeEditedToml, new string('e', 64));

        await vm.OnTabActivatedAsync();

        Assert.Null(vm.RestartFailedMessage);
    }
}
