using System.Collections.Concurrent;
using DnsCryptControl.Core.Rules;
using DnsCryptControl.Platform;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// C1: <see cref="RuleFamilyEditorViewModel"/> — the family-agnostic per-family list⇄raw editor.
/// Drives the four real codecs (names/IPs/cloaking/forwarding) over
/// <see cref="IRuleFamilyCodec"/> and asserts the IC-1 structured⇄raw discipline PER FAMILY:
/// a structured edit regenerates the raw text; a raw edit debounce-re-parses and rebuilds the
/// rows; an Error-severity lint leaves the text Failed with structured editing disabled (IC-11);
/// the codec round-trips; a superseded debounce session is dropped without publishing.
///
/// <para>Pure-POCO/IC-5: no WPF types, every post-await write through the injected
/// <see cref="IUiDispatcher"/>, and all timing deterministic — a short or never-firing injected
/// debounce plus a <see cref="TaskCompletionSource"/>-backed gate, NO wall-clock sleeps (mirroring
/// <c>ConfigurationViewModelTests</c>' <c>ManualGate</c>/<c>NeverDebounce</c>).</para>
/// </summary>
public class RuleFamilyEditorViewModelTests
{
    /// <summary>A firing debounce short enough to fire promptly; every wait is an awaited post/gate
    /// signal, never a sleep, so the exact length is latency-only.</summary>
    private static readonly TimeSpan TestDebounce = TimeSpan.FromMilliseconds(10);

    /// <summary>A debounce that NEVER fires (infinite), so mid-window assertions on Pending can never
    /// race a background publication.</summary>
    private static readonly TimeSpan NeverDebounce = Timeout.InfiniteTimeSpan;

    private sealed class SynchronousDispatcher : IUiDispatcher, IDisposable
    {
        private readonly SemaphoreSlim _posts = new(0);

        public void Dispose() => _posts.Dispose();

        public void Post(Action action)
        {
            action();
            _posts.Release(); // release AFTER the action so awaited state is visible
        }

        public async Task WaitForPostAsync()
        {
            Assert.True(
                await _posts.WaitAsync(TimeSpan.FromSeconds(10)),
                "timed out waiting for a dispatcher post");
        }
    }

    /// <summary>A <see cref="TaskCompletionSource"/>-backed awaitable gate that HOLDS every re-parse
    /// run where it starts, so a test can interleave edits between a run's start and its publication.
    /// Created WITHOUT RunContinuationsAsynchronously so SetResult runs the released continuation
    /// inline on the releasing thread — "was never published" is then a deterministic assertion.</summary>
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

        public async Task<TaskCompletionSource> NextArrivalAsync()
        {
            Assert.True(
                await _arrivals.WaitAsync(TimeSpan.FromSeconds(10)),
                "timed out waiting for a re-parse run to reach the gate");
            Assert.True(_held.TryDequeue(out var tcs));
            return tcs!;
        }
    }

    private static RuleFamilyEditorViewModel NamesEditor(
        SynchronousDispatcher dispatcher,
        TimeSpan? debounce = null,
        Func<CancellationToken, Task>? gate = null) =>
        new(new NameRuleFamilyCodec(RuleFileKind.BlockedNames), dispatcher, debounce ?? NeverDebounce, gate);

    // ------------------------------------------------------------- 5d-VM-4: oversize parse short-circuit

    [Fact]
    public void oversize_raw_body_skips_the_parse_and_stays_saveable()
    {
        // 5d-VM-4 (perf, found on the VM): a raw body over the 1 MiB save cap must NOT be parsed into tens of
        // thousands of rows (that froze the UI for minutes on paste). It skips the parse for a lightweight
        // "too large to list" state, but stays IsValid so the Save/Enable path reaches the accurate TooLarge
        // outcome (the 1 MiB message), not the invalid-lines refusal.
        using var dispatcher = new SynchronousDispatcher();
        var editor = NamesEditor(dispatcher); // NeverDebounce → no background parse can race this

        // ~1.12 MiB of valid rule lines: without the guard this would build ~80k rows.
        var sb = new System.Text.StringBuilder();
        for (var i = 0; i < 80_000; i++)
        {
            sb.Append("*.ads.example\n");
        }

        editor.RawText = sb.ToString();
        editor.ReparseRawText();

        Assert.Empty(editor.Rows);               // the guard fired — NOT 80k rows
        Assert.True(editor.IsValid);             // large is not invalid
        Assert.False(editor.IsStructuredEditable);
        Assert.Contains("too large", editor.Summary);
    }

    // ------------------------------------------------------------- A5: extraLint augmentor

    [Fact]
    public void extraLint_findings_merge_onto_rows_and_whole_file_findings()
    {
        using var dispatcher = new SynchronousDispatcher();
        // Augmentor flags line 2 with a Warning (as the A5 schedule check does for an undefined ref).
        Func<string, IReadOnlyList<RuleLintFinding>> extra = _ => new[]
        {
            new RuleLintFinding(RuleLintSeverity.Warning, 2, "undefined @schedule"),
        };
        using var vm = new RuleFamilyEditorViewModel(
            new NameRuleFamilyCodec(RuleFileKind.BlockedNames), dispatcher, NeverDebounce, gate: null, extraLint: extra);

        vm.Load("ads.example.com\ntracker.example.com @work");

        // The extra finding is anchored onto its 1-based row (line 2) and in the whole-file list.
        Assert.Contains(vm.Findings, f => f.Severity == RuleLintSeverity.Warning && f.LineNumber == 2);
        var row2 = vm.Rows[1];
        Assert.Contains(row2.Findings, f => f.Severity == RuleLintSeverity.Warning);
        Assert.Equal(RuleLintSeverity.Warning, row2.WorstSeverity);
        // A Warning never blocks: the family stays valid/structured-editable (IC-11).
        Assert.True(vm.IsValid);
        Assert.True(vm.IsStructuredEditable);
    }

    [Fact]
    public void summary_counts_invalid_LINES_not_findings_whenLineHasMultipleErrors()
    {
        // Carried C3: the summary said "K invalid lines" but counted Error FINDINGS, so a line with
        // two Error findings reported "2 invalid lines" while FilteringViewModel.CountRows (row-based)
        // reported 1 — a drift. The editor must count invalid ROWS. Inject a SECOND Error on line 1
        // (which is already an Error via the degenerate '=' pattern) and assert the summary says ONE.
        using var dispatcher = new SynchronousDispatcher();
        Func<string, IReadOnlyList<RuleLintFinding>> extra = _ => new[]
        {
            new RuleLintFinding(RuleLintSeverity.Error, 1, "a second error on the same line"),
        };
        using var vm = new RuleFamilyEditorViewModel(
            new NameRuleFamilyCodec(RuleFileKind.BlockedNames), dispatcher, NeverDebounce, gate: null, extraLint: extra);

        vm.Load("="); // degenerate pattern => one codec Error on line 1; extra adds a second Error.

        // Two Error findings on line 1, but ONE invalid line.
        Assert.Equal(2, vm.Findings.Count(f => f.Severity == RuleLintSeverity.Error && f.LineNumber == 1));
        Assert.Contains("1 invalid line ", vm.Summary);
        Assert.DoesNotContain("2 invalid line", vm.Summary);
    }

    // ------------------------------------------------------------- load / projection

    [Fact]
    public void load_projects_rows_and_seeds_raw_text_verbatim()
    {
        using var dispatcher = new SynchronousDispatcher();
        using var vm = NamesEditor(dispatcher);

        const string content = "# a header\nads.example.com\n\n=exact.example.com";
        vm.Load(content);

        // Raw text is the user's exact bytes (IC-1b — never eagerly canonicalized).
        Assert.Equal(content, vm.RawText);
        // One row per physical line, kinds classified.
        Assert.Equal(4, vm.Rows.Count);
        Assert.Equal(RuleRowKind.Comment, vm.Rows[0].Kind);
        Assert.Equal(RuleRowKind.Rule, vm.Rows[1].Kind);
        Assert.Equal(RuleRowKind.Blank, vm.Rows[2].Kind);
        Assert.Equal(RuleRowKind.Rule, vm.Rows[3].Kind);
        Assert.Equal(RawParseState.Clean, vm.RawParseState);
        Assert.True(vm.IsStructuredEditable);
        Assert.True(vm.IsValid);
        Assert.False(vm.IsDirty);
        // Line numbers are 1-based and match the physical line (row index + 1).
        Assert.Equal(1, vm.Rows[0].LineNumber);
        Assert.Equal(2, vm.Rows[1].LineNumber);
    }

    [Fact]
    public void load_summary_derives_from_content_not_a_toggle()
    {
        using var dispatcher = new SynchronousDispatcher();
        using var vm = NamesEditor(dispatcher);

        vm.Load("# note\nads.example.com\ntracker.example.com");

        // 2 rules, 1 comment (IC-16 content-derived).
        Assert.Contains("2 rules", vm.Summary);
        Assert.Contains("1 comment", vm.Summary);
    }

    [Fact]
    public void load_empty_content_is_zero_rows()
    {
        using var dispatcher = new SynchronousDispatcher();
        using var vm = NamesEditor(dispatcher);

        vm.Load(string.Empty);

        Assert.Empty(vm.Rows);
        Assert.Equal(string.Empty, vm.RawText);
        Assert.True(vm.IsStructuredEditable);
        Assert.Contains("0 rules", vm.Summary);
    }

    // ------------------------------------------------------------- structured edit → raw regen

    [Fact]
    public void structured_edit_regenerates_canonical_raw_text_and_marks_dirty()
    {
        using var dispatcher = new SynchronousDispatcher();
        using var vm = NamesEditor(dispatcher);
        vm.Load("ads.example.com");

        // A structured "add a suffix rule" edit: the new ordered row set. '*.x' canonicalizes to the
        // suffix pattern '*.x' verbatim (Pattern is preserved raw), joined with '\n'.
        vm.ApplyStructuredEdit(new[] { "ads.example.com", "*.tracker.example.com" });

        Assert.True(vm.IsDirty);
        Assert.Equal("ads.example.com\n*.tracker.example.com", vm.RawText);
        Assert.Equal(2, vm.Rows.Count);
        Assert.Equal(RawParseState.Clean, vm.RawParseState);
    }

    [Fact]
    public void structured_edit_is_refused_while_structured_editing_is_disabled()
    {
        using var dispatcher = new SynchronousDispatcher();
        using var vm = NamesEditor(dispatcher);
        // A bare '=' pattern (full len 1 < 2) is an Error → Failed → structured disabled.
        vm.Load("=");
        vm.ReparseRawText();

        Assert.Equal(RawParseState.Failed, vm.RawParseState);
        Assert.False(vm.IsStructuredEditable);
        Assert.Throws<InvalidOperationException>(() => vm.ApplyStructuredEdit(new[] { "ads.example.com" }));
    }

    // ------------------------------------------------------------- raw edit → debounced re-parse

    [Fact]
    public async Task raw_edit_marks_pending_then_debounced_reparse_rebuilds_rows()
    {
        using var dispatcher = new SynchronousDispatcher();
        using var vm = NamesEditor(dispatcher, TestDebounce);
        vm.Load("ads.example.com");
        Assert.Single(vm.Rows);

        vm.RawText = "ads.example.com\ntracker.example.com";
        // Immediately after a raw edit (pre-fire): Pending + dirty, rows not yet rebuilt.
        Assert.Equal(RawParseState.Pending, vm.RawParseState);
        Assert.True(vm.IsDirty);

        await dispatcher.WaitForPostAsync(); // the debounced re-parse publishes

        Assert.Equal(RawParseState.Clean, vm.RawParseState);
        Assert.Equal(2, vm.Rows.Count);
        Assert.True(vm.IsStructuredEditable);
    }

    [Fact]
    public async Task raw_edit_with_error_lint_fails_and_disables_structured_editing()
    {
        using var dispatcher = new SynchronousDispatcher();
        using var vm = NamesEditor(dispatcher, TestDebounce);
        vm.Load("ads.example.com");

        // Two '@' on a line is a per-line Error (schedule split); the proxy would skip it.
        vm.RawText = "ads.example.com @a @b";
        await dispatcher.WaitForPostAsync();

        Assert.Equal(RawParseState.Failed, vm.RawParseState);
        Assert.False(vm.IsStructuredEditable);
        Assert.False(vm.IsValid);
        Assert.Contains(vm.Findings, f => f.Severity == RuleLintSeverity.Error);
        // The offending row carries the finding and its worst severity (IC-10/IC-16).
        var row = vm.Rows.Single(r => r.HasFindings);
        Assert.Equal(RuleLintSeverity.Error, row.WorstSeverity);
        Assert.Equal(RuleRowKind.Unparsed, row.Kind);
    }

    [Fact]
    public async Task raw_edit_with_warning_only_stays_editable_and_valid()
    {
        using var dispatcher = new SynchronousDispatcher();
        // Forwarding: a $RESOLVCONF relative path is a Warning that KEEPS the rule.
        using var vm = new RuleFamilyEditorViewModel(
            new ForwardRuleFamilyCodec(), dispatcher, TestDebounce);
        vm.Load(string.Empty);

        vm.RawText = "example.com $RESOLVCONF:relative/path.conf";
        await dispatcher.WaitForPostAsync();

        Assert.Equal(RawParseState.Clean, vm.RawParseState);
        Assert.True(vm.IsStructuredEditable);
        Assert.True(vm.IsValid); // a Warning never blocks (IC-11)
        Assert.Contains(vm.Findings, f => f.Severity == RuleLintSeverity.Warning);
    }

    // ------------------------------------------------------------- round-trip (all families)

    [Theory]
    [MemberData(nameof(RoundTripVectors))]
    public void codec_round_trip_is_a_fixed_point(IRuleFamilyCodec codec, string content)
    {
        var first = codec.Parse(content);
        var second = codec.Parse(first.CanonicalText);

        // parse → serialize → parse is a fixed point on the canonical text (IC-4).
        Assert.Equal(first.CanonicalText, second.CanonicalText);
        Assert.Equal(first.Rows.Count, second.Rows.Count);
    }

    public static IEnumerable<object[]> RoundTripVectors()
    {
        yield return new object[]
        {
            new NameRuleFamilyCodec(RuleFileKind.BlockedNames),
            "# header\nads.example.com\n=exact.example.com\n*ads*\nads*\n\ntracker.example.com @weekend",
        };
        yield return new object[]
        {
            new IpRuleFamilyCodec(RuleFileKind.BlockedIps),
            "# ips\n192.168.1.1\n10.0.0.0/8\n10.*\n\n2001:db8::1",
        };
        yield return new object[]
        {
            new CloakRuleFamilyCodec(),
            "# cloak\nexample.com 192.168.1.1\nalias.example.com =target.example.com",
        };
        yield return new object[]
        {
            new ForwardRuleFamilyCodec(),
            "# forward\nexample.com 9.9.9.9,8.8.8.8\ninternal.example.com $BOOTSTRAP\n. 1.1.1.1",
        };
    }

    // ------------------------------------------------------------- stale-drop (superseded session)

    [Fact]
    public async Task a_superseded_debounce_session_is_dropped_without_publishing()
    {
        using var dispatcher = new SynchronousDispatcher();
        using var gate = new ManualGate();
        using var vm = NamesEditor(dispatcher, TestDebounce, gate.GateAsync);
        vm.Load("ads.example.com");

        // First raw edit → session A reaches the gate (past its debounce delay), held.
        vm.RawText = "first.example.com";
        var releaseA = await gate.NextArrivalAsync();

        // A newer raw edit supersedes session A and starts session B before A is released.
        vm.RawText = "second.example.com";
        var releaseB = await gate.NextArrivalAsync();

        // Release the STALE session A: it re-checks cancellation and must publish NOTHING (no post).
        releaseA.SetResult();
        Assert.Equal(RawParseState.Pending, vm.RawParseState); // A did not resolve the pending edit

        // Release session B: it is the live session and publishes the LATEST text's rows.
        releaseB.SetResult();
        await dispatcher.WaitForPostAsync();

        Assert.Equal(RawParseState.Clean, vm.RawParseState);
        Assert.Single(vm.Rows);
        Assert.Equal("second.example.com", vm.RawText);
    }

    [Fact]
    public async Task a_structured_edit_supersedes_a_pending_raw_reparse_publication()
    {
        using var dispatcher = new SynchronousDispatcher();
        using var gate = new ManualGate();
        using var vm = NamesEditor(dispatcher, TestDebounce, gate.GateAsync);
        vm.Load("ads.example.com");

        // A raw edit starts a session, held at the gate.
        vm.RawText = "raw.example.com";
        var release = await gate.NextArrivalAsync();

        // Before it publishes, a structured edit resolves the pending state synchronously (Clean).
        vm.ApplyStructuredEdit(new[] { "structured.example.com" });
        Assert.Equal(RawParseState.Clean, vm.RawParseState);

        // Releasing the now-stale raw session must not overwrite the structured result: its UI-thread
        // re-check sees RawParseState != Pending and drops (no clobber of the structured rows).
        release.SetResult();

        Assert.Equal("structured.example.com", vm.RawText);
        Assert.Single(vm.Rows);
    }

    // ------------------------------------------------------------- family-agnostic Kind wiring

    [Fact]
    public void editor_exposes_its_codec_kind()
    {
        using var dispatcher = new SynchronousDispatcher();
        using var names = new RuleFamilyEditorViewModel(
            new NameRuleFamilyCodec(RuleFileKind.AllowedNames), dispatcher, NeverDebounce);
        using var ips = new RuleFamilyEditorViewModel(
            new IpRuleFamilyCodec(RuleFileKind.BlockedIps), dispatcher, NeverDebounce);

        Assert.Equal(RuleFileKind.AllowedNames, names.Kind);
        Assert.Equal(RuleFileKind.BlockedIps, ips.Kind);
    }
}
