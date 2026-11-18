using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using DnsCryptControl.Core.Rules;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// The per-family rule editor (C1), instantiated ONCE per rule family (blocked/allowed names,
/// blocked/allowed IPs, cloaking, forwarding). Family-agnostic: an injected
/// <see cref="IRuleFamilyCodec"/> supplies the family's Core parser/serializer, so ONE view-model
/// drives every family. Mirrors <c>ConfigurationViewModel</c>'s IC-1 structured⇄raw discipline PER
/// FAMILY:
/// <list type="bullet">
///   <item>the structured side is <see cref="Rows"/> (a <see cref="RuleRowViewModel"/> per physical
///     line), projected from the parsed <c>.txt</c>;</item>
///   <item>the raw side is <see cref="RawText"/> — the family's <c>.txt</c> is the truth (IC-1b);</item>
///   <item><see cref="RawParseState"/> tracks whether the rows ARE the current text
///     (<see cref="RawParseState.Clean"/>), a user raw edit awaits re-parse
///     (<see cref="RawParseState.Pending"/>), or the last re-parse had a FATAL lint
///     (<see cref="RawParseState.Failed"/> → structured editing disabled, IC-11);</item>
///   <item>every user raw edit marks Pending + dirty and restarts a 400 ms one-CTS debounce that
///     re-parses off the UI thread and publishes via <see cref="IUiDispatcher.Post"/> (IC-5).</item>
/// </list>
///
/// <para>Pure POCO <see cref="ObservableObject"/> (IC-5): zero WPF types; every post-await observable
/// write goes through the injected <see cref="IUiDispatcher"/>; the debounce interval and an
/// awaitable gate are injectable so tests are deterministic with zero sleeps (mirroring
/// <c>ConfigurationViewModel</c>'s <c>ManualGate</c>/<c>NeverDebounce</c> fixtures).</para>
///
/// <para>STRICT-LINT GATE (IC-11): a re-parse whose findings include any
/// <see cref="RuleLintSeverity.Error"/> leaves the raw text <see cref="RawParseState.Failed"/> and
/// structured editing disabled (<see cref="IsStructuredEditable"/> false) — the row list stays
/// display-only until the raw text is fixed, exactly as a TOML parse error greys the config
/// editor's structured pane. Warnings never fail. This VM owns the family's editor state only; the
/// save/enable-and-wire orchestration is C2's <c>FilteringViewModel</c>.</para>
/// </summary>
public sealed partial class RuleFamilyEditorViewModel : ObservableObject, IDisposable
{
    private static readonly TimeSpan DefaultDebounce = TimeSpan.FromMilliseconds(400);

    /// <summary>Production re-parse gate: a no-op. Tests inject an awaitable gate to sequence runs
    /// deterministically (IC-5) — see the ctor doc.</summary>
    private static readonly Func<CancellationToken, Task> ImmediateGate = static _ => Task.CompletedTask;

    private readonly IRuleFamilyCodec _codec;
    private readonly IUiDispatcher _ui;
    private readonly TimeSpan _debounce;
    private readonly Func<CancellationToken, Task> _gate;

    /// <summary>An optional cross-family lint augmentor (A5): given the raw text, returns EXTRA
    /// findings the per-file codec cannot produce because they need config-level context (e.g. an
    /// undefined <c>@schedule</c> needs the config's <c>[schedules]</c> set). Merged into the parse's
    /// rows/Findings/summary at publish time. Pure/total; defaults to none.</summary>
    private readonly Func<string, IReadOnlyList<RuleLintFinding>>? _extraLint;

    /// <summary>One cancellation source per EDIT SESSION: every raw edit cancels the previous session
    /// and starts a new one, so at most the LATEST edit's re-parse can ever publish. UI-thread-affine.</summary>
    private CancellationTokenSource? _cts;

    /// <summary>True while the VM ITSELF is writing <see cref="RawText"/> (load, or the regeneration
    /// after a structured edit): those writes are projections of the row list, not user raw edits, so
    /// they must not mark the parse Pending or the state dirty (mirrors ConfigurationViewModel).</summary>
    private bool _suppressRawTextSideEffects;

    /// <param name="debounceInterval">
    /// The re-parse debounce interval; defaults to ~400 ms. Exposed only so tests can inject a short
    /// (or never-firing) deterministic interval instead of depending on wall-clock timing (IC-5).
    /// </param>
    /// <param name="gate">
    /// An awaitable gate invoked at the START of every debounced re-parse run (production default:
    /// completed task). Tests inject a <see cref="TaskCompletionSource"/>-backed gate to hold/release
    /// runs and prove stale-session results are dropped — deterministically, with no sleeps.
    /// </param>
    /// <param name="extraLint">
    /// An optional cross-family lint augmentor (A5): given the raw text it returns EXTRA findings the
    /// per-file codec cannot produce (they need config-level context, e.g. undefined <c>@schedule</c>
    /// resolution against the config's <c>[schedules]</c> table). Merged into each parse's
    /// rows/Findings/summary. Must be pure/total (it runs on the off-thread debounce too).
    /// </param>
    public RuleFamilyEditorViewModel(
        IRuleFamilyCodec codec,
        IUiDispatcher ui,
        TimeSpan? debounceInterval = null,
        Func<CancellationToken, Task>? gate = null,
        Func<string, IReadOnlyList<RuleLintFinding>>? extraLint = null)
    {
        ArgumentNullException.ThrowIfNull(codec);
        ArgumentNullException.ThrowIfNull(ui);
        _codec = codec;
        _ui = ui;
        _debounce = debounceInterval ?? DefaultDebounce;
        _gate = gate ?? ImmediateGate;
        _extraLint = extraLint;
    }

    /// <summary>The helper rule-file kind this editor edits (maps to a fixed <c>.txt</c> filename).</summary>
    public RuleFileKind Kind => _codec.Kind;

    /// <summary>The structured side (IC-1): one row per physical line of the <c>.txt</c>, display-only
    /// while <see cref="IsStructuredEditable"/> is false.</summary>
    [ObservableProperty]
    private IReadOnlyList<RuleRowViewModel> _rows = Array.Empty<RuleRowViewModel>();

    /// <summary>The raw side (IC-1b): the family's <c>.txt</c> content. The truth; the rows project it.</summary>
    [ObservableProperty]
    private string _rawText = string.Empty;

    /// <summary>Where the row list stands relative to the raw text (Clean/Pending/Failed).</summary>
    [ObservableProperty]
    private RawParseState _rawParseState;

    /// <summary>False while the raw text has a FATAL (Error-severity) lint or nothing is loaded — the
    /// structured pane greys out and shows the last-good rows only (IC-11).</summary>
    [ObservableProperty]
    private bool _isStructuredEditable;

    /// <summary>True when the editor's raw text differs from the on-disk content it was loaded with —
    /// C2's Save gate consumes this.</summary>
    [ObservableProperty]
    private bool _isDirty;

    /// <summary>All lint findings for the current text (Errors AND Warnings), in line order — the
    /// panel's richness (per-row findings live on the row too).</summary>
    [ObservableProperty]
    private IReadOnlyList<RuleLintFinding> _findings = Array.Empty<RuleLintFinding>();

    /// <summary>True when the last published parse carried no Error-severity finding — C2's Save gate
    /// consumes this (a Warning never blocks; only an Error does, IC-11). Seeded on load.</summary>
    [ObservableProperty]
    private bool _isValid = true;

    /// <summary>Content-derived summary (IC-16): "N rules · M comments · K invalid" over the CURRENT
    /// parse, so the displayed state derives from CONTENT not a toggle.</summary>
    [ObservableProperty]
    private string _summary = "0 rules.";

    /// <summary>True when the current raw text is NONEMPTY but past the list guard (5d-VM-4), so
    /// <see cref="Rows"/> is empty because the content is UNLISTED, not because there is none. Set
    /// only by <see cref="PublishOversize"/>; every real parse (<see cref="PublishParse"/>) resets
    /// it. C2's derived state consumes this so a wired family carrying a saved multi-MB blocklist
    /// counts as ACTIVE and never wears the "enabled, but empty" banner (an empty-Rows honesty
    /// signal would otherwise invert into a lie for oversize content).</summary>
    [ObservableProperty]
    private bool _isOversizeUnlisted;

    /// <summary>
    /// (Re)loads the editor from a family's raw <c>.txt</c> content: parses it, projects the rows,
    /// seeds the raw text and the parse/lint state. Discards any unsaved edits. Synchronous and
    /// UI-thread-affine (the caller supplies the already-read text — the file read is C2/B2's job).
    /// An oversize body (5d-VM-4) skips the parse for the same lightweight "too large to list"
    /// state as the other two parse paths: C2 re-Loads every family on tab activation, so a SAVED
    /// multi-MB list would otherwise re-freeze the UI on every Filtering visit.
    /// </summary>
    public void Load(string? content)
    {
        CancelSession();

        // The truth is the raw text the user gave us; the canonical text is only used to DETECT
        // divergence and to regenerate after a structured edit. Seeding RawText with the input
        // preserves the user's exact bytes until they choose to canonicalize (IC-1b/IC-4).
        var text = content ?? string.Empty;
        if (text.Length > OversizeParseSkipChars)
        {
            SetRawTextInternal(text);
            PublishOversize(text.Length);
            IsDirty = false;
            return;
        }

        var result = ParseAndAugment(text);
        SetRawTextInternal(text);
        PublishParse(result);
        IsDirty = false;
    }

    /// <summary>
    /// Applies a STRUCTURED edit: replaces the row list wholesale (add/remove/edit rows is expressed
    /// as the new ordered row set), regenerates the raw text canonically from those rows, and
    /// re-parses (synchronously) so the rows and findings reflect the new text (IC-1). Refused while
    /// structured editing is disabled (nothing loaded / the raw text has a FATAL lint) — mirroring
    /// <c>ConfigurationViewModel.ApplyEdit</c>'s guard.
    /// </summary>
    /// <param name="newRowTexts">The new ordered per-line texts (each a full line; joined with '\n').</param>
    /// <exception cref="InvalidOperationException">Structured editing is disabled.</exception>
    public void ApplyStructuredEdit(IReadOnlyList<string> newRowTexts)
    {
        ArgumentNullException.ThrowIfNull(newRowTexts);

        // A user raw edit may still be awaiting the debounced re-parse (Pending). Resolve it
        // synchronously first so a stale row set can't silently discard the user's typed raw change
        // (the exact IC-1 hazard the one-document invariant prevents in ConfigurationViewModel).
        if (RawParseState == RawParseState.Pending)
        {
            ReparseRawText();
        }

        if (!IsStructuredEditable)
        {
            throw new InvalidOperationException(
                "Structured editing is disabled — load a rule file and fix any invalid (red) lines first.");
        }

        SetRawTextInternal(string.Join('\n', newRowTexts));
        IsDirty = true;
        ReparseRawText(); // structured edit → the rows/findings reflect the regenerated raw text
    }

    /// <summary>Perf guard threshold (5d-VM-4): past ~1 MiB the editor stops listing line-by-line —
    /// building hundreds of thousands of row VMs froze the UI on paste. DECOUPLED from the transport
    /// cap since v5 (<see cref="IpcSerializer.MaxBytes"/>, 16 MiB): a body between this guard and the
    /// cap still SAVES verbatim (the helper line-validates it; the proxy skips lines it can't parse) —
    /// it just isn't itemised here. <see cref="PublishOversize"/> words the summary per tier.</summary>
    private const int OversizeParseSkipChars = 1_048_576;

    /// <summary>
    /// Re-parses the CURRENT raw text synchronously (the debounce drives this after a user raw edit):
    /// clean/warn-only → the rows REPLACE and structured editing is enabled; any Error finding →
    /// <see cref="RawParseState.Failed"/> and structured editing disabled (IC-11). An oversize body
    /// (5d-VM-4) skips the parse for a lightweight "too large to list" state. UI-thread-affine.
    /// </summary>
    public void ReparseRawText()
    {
        var text = RawText ?? string.Empty;
        if (text.Length > OversizeParseSkipChars)
        {
            PublishOversize(text.Length);
            return;
        }

        PublishParse(ParseAndAugment(text));
    }

    /// <summary>Parses <paramref name="text"/> through the codec, then merges any cross-family
    /// augmentor findings (A5) onto the owning rows / whole-file Findings. Pure/total.</summary>
    private RuleParseResult ParseAndAugment(string? text)
    {
        var result = _codec.Parse(text);
        if (_extraLint is null)
        {
            return result;
        }

        var extra = _extraLint(text ?? string.Empty);
        return extra.Count == 0 ? result : MergeFindings(result, extra);
    }

    /// <summary>Returns a new <see cref="RuleParseResult"/> with <paramref name="extra"/> findings
    /// merged into the whole-file <see cref="RuleParseResult.Findings"/> and onto each finding's
    /// 1-based owning row (out-of-range line numbers are dropped defensively). Row/text order and
    /// canonical text are unchanged.</summary>
    private static RuleParseResult MergeFindings(RuleParseResult result, IReadOnlyList<RuleLintFinding> extra)
    {
        var rows = new RuleRowModel[result.Rows.Count];
        for (var i = 0; i < result.Rows.Count; i++)
        {
            rows[i] = result.Rows[i];
        }

        foreach (var finding in extra)
        {
            var idx = finding.LineNumber - 1;
            if (idx < 0 || idx >= rows.Length)
            {
                continue;
            }

            var merged = new List<RuleLintFinding>(rows[idx].Findings) { finding };
            rows[idx] = rows[idx] with { Findings = merged };
        }

        // Keep whole-file findings in line order so the panel lists them coherently.
        var allFindings = result.Findings.Concat(extra)
            .OrderBy(f => f.LineNumber)
            .ToArray();

        return result with { Rows = rows, Findings = allFindings };
    }

    /// <summary>Publishes one parse result onto the editor's surfaces (UI-thread-affine): rows,
    /// findings, summary, validity, and the parse-state transition. A parse with any Error finding is
    /// FATAL (Failed + structured disabled); warn-only or clean is editable.</summary>
    private void PublishParse(RuleParseResult result) => PublishParse(result, BuildRowViewModels(result));

    /// <summary>The overload the debounced pipeline uses: the row view-models were already BUILT
    /// off-thread (<see cref="BuildRowViewModels"/>), so the UI thread only pays the array swap and
    /// the cheap derived-state scans — never an O(n) allocation loop on a large paste.</summary>
    private void PublishParse(RuleParseResult result, RuleRowViewModel[] rows)
    {
        Rows = rows;
        Findings = result.Findings;

        // The FATAL gate is "any Error finding present anywhere" (defensive: even an unanchored
        // finding blocks the save). The summary counts invalid LINES (rows with >=1 Error), NOT Error
        // findings — a single line with two Error findings is ONE invalid line. Counting findings here
        // would drift from FilteringViewModel.CountRows (which counts rows), making the two "K invalid"
        // summaries disagree (carried C3).
        var hasError = false;
        foreach (var finding in result.Findings)
        {
            if (finding.Severity == RuleLintSeverity.Error)
            {
                hasError = true;
                break;
            }
        }

        var invalidLines = 0;
        foreach (var row in result.Rows)
        {
            foreach (var finding in row.Findings)
            {
                if (finding.Severity == RuleLintSeverity.Error)
                {
                    invalidLines++;
                    break;
                }
            }
        }

        IsValid = !hasError;
        IsStructuredEditable = !hasError;
        IsOversizeUnlisted = false; // a real parse means the rows ARE the content again
        RawParseState = hasError ? RawParseState.Failed : RawParseState.Clean;
        Summary = ComputeSummary(result.Rows, invalidLines);
    }

    /// <summary>Builds the per-line row view-models for a parse result. Pure — safe to run off the
    /// UI thread (the row VMs are immutable POCOs), which is exactly where the debounced pipeline
    /// runs it so a large paste never allocates tens of thousands of rows on the UI thread.</summary>
    private static RuleRowViewModel[] BuildRowViewModels(RuleParseResult result)
    {
        var rows = new RuleRowViewModel[result.Rows.Count];
        for (var i = 0; i < result.Rows.Count; i++)
        {
            rows[i] = new RuleRowViewModel(i + 1, result.Rows[i]);
        }

        return rows;
    }

    /// <summary>5d-VM-4: publishes a lightweight "too large to list" state for a raw body past the
    /// list guard — empty rows (no hundreds-of-thousands-of-row build on paste), structured editing
    /// disabled, but <see cref="IsValid"/> stays TRUE so Save proceeds (guard-to-cap bodies save
    /// verbatim) or reaches the accurate TooLarge outcome (past-cap bodies) rather than the
    /// invalid-lines refusal. Two honest tiers: chars &gt; the byte cap ⟹ certainly unsendable
    /// (UTF-8 is ≥ 1 byte/char before envelope inflation); otherwise the char count alone cannot
    /// prove the ENVELOPE bytes fit (savability is decided on the serialized request's UTF-8
    /// bytes, IC-14), so tier 2 promises only a CONDITIONAL save — "sends it as-is if it fits" —
    /// with the per-line check deferred to the helper. UI-thread-affine.</summary>
    private void PublishOversize(int length)
    {
        Rows = Array.Empty<RuleRowViewModel>();
        Findings = Array.Empty<RuleLintFinding>();
        IsValid = true;
        IsStructuredEditable = false;
        IsOversizeUnlisted = true;
        RawParseState = RawParseState.Clean;
        Summary = length > IpcSerializer.MaxBytes
            ? $"{length:N0} characters — too large to send to the helper ({IpcSerializer.MaxBytes / 1_048_576} MiB per-request limit); Save will refuse it. Split the list."
            : $"{length:N0} characters — too large to list line-by-line; Save sends it as-is if it fits the {IpcSerializer.MaxBytes / 1_048_576} MiB request limit (the helper checks each line; the proxy skips lines it can't parse).";
    }

    /// <summary>Content-derived summary (IC-16): rule/comment counts + invalid-LINE count over the
    /// CURRENT parse (rows with >=1 Error finding, matching <c>FilteringViewModel.CountRows</c> so the
    /// two summaries never drift). A blank line is not counted in any bucket (neither rule nor comment).</summary>
    private static string ComputeSummary(IReadOnlyList<RuleRowModel> rows, int invalidLines)
    {
        var rules = 0;
        var comments = 0;
        foreach (var row in rows)
        {
            switch (row.Kind)
            {
                case RuleRowKind.Rule:
                    rules++;
                    break;
                case RuleRowKind.Comment:
                    comments++;
                    break;
                default:
                    break;
            }
        }

        var rulesWord = rules == 1 ? "rule" : "rules";
        var summary = $"{rules} {rulesWord} · {comments} comment{(comments == 1 ? string.Empty : "s")}";
        if (invalidLines > 0)
        {
            summary += $" · {invalidLines} invalid line{(invalidLines == 1 ? string.Empty : "s")} (fix before saving)";
        }
        else
        {
            summary += ".";
        }

        return summary;
    }

    /// <summary>Any non-suppressed write is a USER raw edit: dirty + parse Pending (the debounced
    /// re-parse picks it up). Mirrors <c>ConfigurationViewModel.OnRawTextChanged</c>.</summary>
    partial void OnRawTextChanged(string value)
    {
        if (_suppressRawTextSideEffects)
        {
            return;
        }

        IsDirty = true;
        RawParseState = RawParseState.Pending;
        RestartDebounce();
    }

    private void SetRawTextInternal(string text)
    {
        _suppressRawTextSideEffects = true;
        try
        {
            RawText = text;
        }
        finally
        {
            _suppressRawTextSideEffects = false;
        }
    }

    // ------------------------------------------- debounced off-thread re-parse pipeline (IC-5)

    private void RestartDebounce()
    {
        CancelSession();
        _cts = new CancellationTokenSource();
        _ = RunReparseAsync(RawText, _cts.Token);
    }

    private void CancelSession()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }

    private async Task RunReparseAsync(string candidate, CancellationToken sessionToken)
    {
        try
        {
            await Task.Delay(_debounce, sessionToken).ConfigureAwait(false);

            // Oversize short-circuit (5d-VM-4) on the DEBOUNCED path too — a multi-MB paste lands
            // here, not in the synchronous ReparseRawText, and parsing + building tens of thousands
            // of rows for a body that cannot be saved anyway is exactly the paste freeze the guard
            // documents. Publish the same lightweight state, with the same stale-drop discipline.
            if (candidate.Length > OversizeParseSkipChars)
            {
                _ui.Post(() =>
                {
                    if (sessionToken.IsCancellationRequested || RawParseState != RawParseState.Pending)
                    {
                        return;
                    }

                    PublishOversize(candidate.Length);
                });
                return;
            }

            // The whole run — gate + parse + row-VM build — stays off the UI thread; only the
            // finished result is marshalled (IC-5). Core parsing is pure/total, so no throw escapes.
            await Task.Run(
                async () =>
                {
                    await _gate(sessionToken).ConfigureAwait(false);

                    var result = ParseAndAugment(candidate);
                    var rows = BuildRowViewModels(result);

                    // Stale drop: a newer edit (or a reload) cancelled this session while the run was
                    // already past its delay — its result describes a text the user moved beyond.
                    if (sessionToken.IsCancellationRequested)
                    {
                        return;
                    }

                    _ui.Post(() =>
                    {
                        // Re-check on the UI thread: the session may have gone stale between the post
                        // and its dispatch (production dispatchers queue).
                        if (sessionToken.IsCancellationRequested)
                        {
                            return;
                        }

                        // Only resolve a still-Pending raw edit. If a structured edit (or a reload)
                        // already moved the state to Clean/Failed, this publication is stale content.
                        if (RawParseState != RawParseState.Pending)
                        {
                            return;
                        }

                        PublishParse(result, rows);
                    });
                },
                sessionToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Expected: this session was superseded by a newer edit's debounce restart.
        }
    }

    public void Dispose()
    {
        CancelSession();
        GC.SuppressFinalize(this);
    }
}
