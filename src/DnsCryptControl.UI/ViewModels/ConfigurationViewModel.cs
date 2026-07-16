using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsCryptControl.Core.Schema;
using DnsCryptControl.Core.Toml;
using DnsCryptControl.Core.Validation;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>Where the raw editor's text stands relative to the shared document:
/// <see cref="Clean"/> = the doc IS the current text; <see cref="Pending"/> = the user
/// edited the raw text and a re-parse has not run yet (E2's debounce drives it);
/// <see cref="Failed"/> = the last re-parse (or the load itself) had TOML errors — the
/// structured pane is display-only until the raw text is fixed.</summary>
public enum RawParseState
{
    Clean,
    Pending,
    Failed,
}

/// <summary>
/// The Configuration tab's view-model (E1 core): loads <c>dnscrypt-proxy.toml</c>
/// through <see cref="IConfigFileService.Load"/> (one byte-read; the load-time sha is
/// the save-time CAS base, P5b-E8), projects the full <see cref="ConfigCatalog"/> into
/// curated sections, and keeps the structured pane and the raw editor projections of
/// ONE <see cref="TomlConfigDocument"/> (IC-1) — structured edits mutate the syntax
/// tree surgically and the raw text is always <c>doc.ToText()</c>; TOML text is NEVER
/// regenerated from the derived model (comments and unknown keys must survive).
///
/// <para>E2 adds the debounced off-thread validation pipeline: every structured or raw
/// edit restarts ONE debounce session; on fire the candidate raw text is parsed and run
/// through <see cref="ConfigValidator"/> + <see cref="OpsecConfigRules"/> off the UI
/// thread, and the results — the FULL local issue list, the OPSEC concerns,
/// <see cref="IsValid"/>, and E1's Pending raw-parse-state transition — are published
/// via the dispatcher.</para>
///
/// <para>PURE POCO <see cref="ObservableObject"/> mirroring <see cref="DashboardViewModel"/>
/// (IC-5): zero WPF type references; every observable write that happens after an
/// awaited call goes through the injected <see cref="IUiDispatcher"/>, never directly.</para>
/// </summary>
public partial class ConfigurationViewModel : ObservableObject, IDisposable
{
    private static readonly TimeSpan DefaultValidationDebounce = TimeSpan.FromMilliseconds(400);

    /// <summary>Production validation gate: a no-op. Tests inject an awaitable gate to
    /// sequence runs deterministically (IC-5) — see the ctor doc.</summary>
    private static readonly Func<CancellationToken, Task> ImmediateValidationGate = static _ => Task.CompletedTask;

    private readonly IConfigFileService _configFile;
    private readonly IProtectionStateReader _stateReader;
    private readonly IUiDispatcher _ui;
    private readonly TimeSpan _validationDebounce;
    private readonly Func<CancellationToken, Task> _validationGate;

    /// <summary>One cancellation source per EDIT SESSION (E2): every structured or raw
    /// edit cancels the previous session and starts a new one, so at most the LATEST
    /// edit's validation run can ever publish. UI-thread-affine.</summary>
    private CancellationTokenSource? _validationCts;
    private Task? _validationRun;

    /// <summary>The single source of truth both editor views project (IC-1). After a
    /// failed raw re-parse this keeps the LAST-GOOD document for display only —
    /// structured EDITS are gated on <see cref="IsStructuredEditable"/>.</summary>
    private TomlConfigDocument? _doc;

    /// <summary>True while the VM ITSELF is writing <see cref="RawText"/> (load, or the
    /// regeneration after a structured edit) — those writes are projections of the doc,
    /// not user raw edits, so they must not mark the parse Pending or the state dirty.</summary>
    private bool _suppressRawTextSideEffects;

    [ObservableProperty]
    private IReadOnlyList<ConfigSectionViewModel> _sections = Array.Empty<ConfigSectionViewModel>();

    /// <summary>The sections the nav actually shows: all of them when no filter is
    /// active, only those with at least one matching entry while one is (§8.3).</summary>
    [ObservableProperty]
    private IReadOnlyList<ConfigSectionViewModel> _visibleSections = Array.Empty<ConfigSectionViewModel>();

    /// <summary>§8.3 search box: case-insensitive contains-match over every entry's
    /// key path and doc text, across ALL sections.</summary>
    [ObservableProperty]
    private string _filterText = string.Empty;

    [ObservableProperty]
    private string _rawText = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    [NotifyPropertyChangedFor(nameof(CanRevert))]
    [NotifyCanExecuteChangedFor(nameof(SaveAndApplyCommand))]
    [NotifyCanExecuteChangedFor(nameof(RevertCommand))]
    private bool _isDirty;

    [ObservableProperty]
    private RawParseState _rawParseState;

    /// <summary>False while the raw text has TOML parse errors (or nothing is loaded) —
    /// the structured pane greys out and only shows the last-good values.</summary>
    [ObservableProperty]
    private bool _isStructuredEditable;

    /// <summary>Distinct load-failure state (file missing/locked/unreadable): the whole
    /// editor is disabled, unlike a PARSE failure which keeps the raw editor usable.</summary>
    [ObservableProperty]
    private bool _loadFailed;

    [ObservableProperty]
    private string? _loadError;

    /// <summary>The FULL local validation result for the current text — Errors AND
    /// Warnings. The wire only ever carries the FIRST error, so the panel's richness
    /// comes from this local run (E2).</summary>
    [ObservableProperty]
    private IReadOnlyList<ValidationIssue> _validationIssues = Array.Empty<ValidationIssue>();

    /// <summary>OPSEC rule findings for the current text (P5b-U1: the editor ALWAYS
    /// warns on these; whether one also blocks is the protection-gated mirror).</summary>
    [ObservableProperty]
    private IReadOnlyList<OpsecConcern> _opsecConcerns = Array.Empty<OpsecConcern>();

    /// <summary>True when the last published validation carried no Error-severity issue
    /// (warnings do not invalidate). Seeded from parse-cleanliness on load — findings
    /// publish per EDIT. E3's Save gate consumes this.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    [NotifyCanExecuteChangedFor(nameof(SaveAndApplyCommand))]
    private bool _isValid;

    /// <summary>The client-side OPSEC block mirror (P5b-U1/F24): non-null while
    /// protection is ON (intent read off disk at validation time) and the candidate
    /// raises any KillSwitchCritical/ProtectionCritical concern — Save disabled, banner
    /// shows this text. UX ONLY: the helper's write policy enforces the same rules at
    /// the trust boundary regardless (IC-3/IC-4).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    [NotifyCanExecuteChangedFor(nameof(SaveAndApplyCommand))]
    private string? _saveBlockedReason;

    /// <summary>Single busy owner for this VM (IC-5, mirroring Dashboard's
    /// <c>_inFlight</c> discipline, made observable so the view can disable buttons):
    /// true while a Save &amp; apply is in flight; both E3 commands ignore re-entry
    /// while set.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    [NotifyPropertyChangedFor(nameof(CanRevert))]
    [NotifyCanExecuteChangedFor(nameof(SaveAndApplyCommand))]
    [NotifyCanExecuteChangedFor(nameof(RevertCommand))]
    private bool _isBusy;

    /// <summary>The TRANSIENT "saved" notice (E3): set after an Applied save's reload,
    /// cleared by the next edit or save attempt — never a persistent surface.</summary>
    [ObservableProperty]
    private string? _saveNotice;

    /// <summary>The error panel's save-refusal line (E3): the helper's Rejected
    /// message — or the HelperUnavailable/TooLarge orchestration message — VERBATIM
    /// (IC-10). Null when the last attempt did not fail that way.</summary>
    [ObservableProperty]
    private string? _saveError;

    /// <summary>BE-6 conflict banner (non-null = shown): the helper refused the
    /// compare-and-swap because the on-disk file changed since it was loaded. The
    /// user's edits STAY in the editor; the banner's [Reload] action is
    /// <see cref="LoadAsync"/> — an explicit user choice, never automatic.</summary>
    [ObservableProperty]
    private string? _conflictMessage;

    /// <summary>P5b-E1 version-skew banner (non-null = shown), mirroring the
    /// Dashboard's F20 HelperIncompatible state: the save path refused to send
    /// anything to a helper on a different protocol version.</summary>
    [ObservableProperty]
    private string? _helperIncompatibleMessage;

    /// <summary>Persistent non-green state (E3): the config WAS written but the proxy
    /// restart failed or its reply was lost — status unverified. Clears on the next
    /// Applied, Revert, or successful (re)load.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanRevert))]
    [NotifyCanExecuteChangedFor(nameof(RevertCommand))]
    private string? _restartFailedMessage;

    /// <summary>Persistent error state (§7.3, NEVER green): the config WAS written and
    /// the restart issued, but the proxy never reported running — the new config
    /// appears rejected by the proxy. Clears ONLY on the next successful Applied or an
    /// explicit Revert — it deliberately SURVIVES silent reloads.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanRevert))]
    [NotifyCanExecuteChangedFor(nameof(RevertCommand))]
    private string? _proxyRejectedMessage;

    /// <summary>Lowercase-hex SHA-256 of the on-disk bytes AS LOADED — the
    /// optimistic-concurrency base every save sends (P5b-E8: the load-time snapshot,
    /// never a silent fresh-read rebase). Null until a successful load.</summary>
    public string? BaseSha256 { get; private set; }

    /// <param name="validationDebounceInterval">
    /// The E2 edit-debounce interval; defaults to ~400 ms. Exposed only so tests can
    /// inject a short (or never-firing) deterministic interval instead of depending on
    /// wall-clock timing (IC-5).
    /// </param>
    /// <param name="validationGate">
    /// An awaitable gate invoked at the START of every debounced validation run
    /// (production default: completed task). Tests inject a
    /// <see cref="TaskCompletionSource"/>-backed gate to hold/release runs and prove
    /// stale-session results are dropped — deterministically, with no sleeps.
    /// </param>
    public ConfigurationViewModel(
        IConfigFileService configFile,
        IProtectionStateReader stateReader,
        IUiDispatcher ui,
        TimeSpan? validationDebounceInterval = null,
        Func<CancellationToken, Task>? validationGate = null)
    {
        ArgumentNullException.ThrowIfNull(configFile);
        ArgumentNullException.ThrowIfNull(stateReader);
        ArgumentNullException.ThrowIfNull(ui);
        _configFile = configFile;
        _stateReader = stateReader;
        _ui = ui;
        _validationDebounce = validationDebounceInterval ?? DefaultValidationDebounce;
        _validationGate = validationGate ?? ImmediateValidationGate;
    }

    /// <summary>
    /// (Re)loads the on-disk config and rebuilds the whole editor state: sections and
    /// entries from the real catalog, the raw text, and the CAS base sha. Discards any
    /// unsaved edits — Revert (IC-7) and E3's Conflict "Reload" both route here.
    /// </summary>
    public async Task LoadAsync(CancellationToken ct)
    {
        var load = await Task.Run(_configFile.Load, ct).ConfigureAwait(false);
        if (!load.Success)
        {
            _ui.Post(() =>
            {
                // The discarded edits' in-flight validation session dies with them — an
                // orphaned run must never publish findings over the fresh baseline.
                CancelValidationSession();
                _doc = null;
                BaseSha256 = null;
                Sections = Array.Empty<ConfigSectionViewModel>();
                VisibleSections = Array.Empty<ConfigSectionViewModel>();
                SetRawTextInternal(string.Empty);
                IsDirty = false;
                IsStructuredEditable = false;
                RawParseState = RawParseState.Clean;
                ResetValidationState(isValid: false);
                LoadError = load.Error;
                LoadFailed = true;
            });
            return;
        }

        // Parse + section building happen off the UI thread; only the publication of
        // the finished object graph is marshalled (IC-5).
        var doc = TomlConfigDocument.Parse(load.Text!);
        var sections = BuildSections(doc);

        _ui.Post(() =>
        {
            // See the failure path above: reloading discards unsaved edits AND their
            // in-flight validation session (deterministically pinned by the
            // reload_discards_a_pending_validation_session test).
            CancelValidationSession();
            _doc = doc;
            BaseSha256 = load.Sha256;
            Sections = sections;
            SetRawTextInternal(load.Text!);
            IsDirty = false;
            // A file that loads but does not PARSE is not a load failure: the raw
            // editor shows the text for fixing; only the structured pane is disabled.
            IsStructuredEditable = !doc.HasErrors;
            RawParseState = doc.HasErrors ? RawParseState.Failed : RawParseState.Clean;
            ResetValidationState(isValid: !doc.HasErrors);
            LoadError = null;
            LoadFailed = false;
            // E3: a successful (re)load re-baselines the per-attempt save surfaces, and
            // RestartFailed's defined exits include "successful refresh". The Applied
            // path re-posts its notice AFTER this reload, so clearing it here is safe.
            // ProxyRejectedMessage deliberately SURVIVES: its only exits are a
            // successful Applied or an explicit Revert (§7.3 — never silently green).
            SaveNotice = null;
            SaveError = null;
            ConflictMessage = null;
            HelperIncompatibleMessage = null;
            RestartFailedMessage = null;
            ApplyFilter(); // a live filter stays applied across a reload
            // P5b-U1 pristine-load validation: the freshly loaded text must validate
            // too — an OPSEC-unsafe or schema-invalid-but-parse-clean file must never
            // wear a Valid badge with zero warnings until the first edit. Safe to seed
            // from here: the publication path never touches IsDirty, and RawParseState
            // is Clean/Failed post-load (never Pending), so it can only publish
            // findings — it cannot replace the document.
            RestartValidationDebounce();
        });
    }

    /// <summary>Load discards edits, so it also resets the validation surface to the
    /// baseline: no findings yet — findings publish per EDIT (E2's debounce). The
    /// load-time doc's parse-cleanliness seeds <see cref="IsValid"/> so E3's Save gate
    /// stays meaningful before the first edit's run fires.</summary>
    private void ResetValidationState(bool isValid)
    {
        ValidationIssues = Array.Empty<ValidationIssue>();
        OpsecConcerns = Array.Empty<OpsecConcern>();
        IsValid = isValid;
        SaveBlockedReason = null;
    }

    /// <summary>Groups the catalog on the curated A4 <c>Group</c> field, preserving the
    /// catalog's first-occurrence order (the mockup's nav order), and projects each
    /// entry's current value from <paramref name="doc"/>.</summary>
    private static List<ConfigSectionViewModel> BuildSections(TomlConfigDocument doc)
    {
        var sections = new List<ConfigSectionViewModel>();
        foreach (var group in ConfigCatalog.All.GroupBy(d => d.Group))
        {
            var entries = new List<SettingEntryViewModel>();
            foreach (var descriptor in group)
            {
                var entry = new SettingEntryViewModel(descriptor);
                entry.RefreshFrom(doc);
                entries.Add(entry);
            }

            // 5g-3/WP4: attach the group's plain-language explainer — WP4 authored one for
            // EVERY catalog group (coverage is test-enforced); null is only the safety path
            // for a future group added without one.
            ConfigSectionDescriptions.All.TryGetValue(group.Key, out var description);
            sections.Add(new ConfigSectionViewModel(group.Key, entries, description));
        }

        return sections;
    }

    /// <summary>
    /// Applies a structured edit: a SURGICAL syntax-tree mutation on the shared
    /// document (IC-1 — never a model re-serialization), then re-projects the entry and
    /// regenerates the raw text as <c>doc.ToText()</c>. <paramref name="newValue"/> is
    /// the typed value per <see cref="SettingEntryViewModel.ValueType"/>; null means
    /// "reset to default" = remove the key so the proxy's own default takes over.
    /// </summary>
    /// <exception cref="InvalidOperationException">The entry is raw-only (P5b-E3), or
    /// structured editing is disabled (nothing loaded / raw text has parse errors —
    /// including a pending user raw edit that fails the synchronous re-parse below).</exception>
    /// <exception cref="ArgumentException">The value's type does not match the entry's.</exception>
    public void ApplyEdit(SettingEntryViewModel entry, object? newValue)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (entry.IsRawOnly)
        {
            throw new InvalidOperationException(
                $"'{entry.KeyPath}' has no structured editor in this phase — edit it in the Raw view.");
        }

        // A user raw edit may still be awaiting the debounced re-parse (Pending).
        // Mutating the STALE document here would regenerate RawText from it and
        // silently DISCARD the user's typed change — the exact failure mode IC-1's
        // one-document invariant exists to prevent. Re-parse synchronously first:
        // clean → the edit lands on the CURRENT raw text (both changes coexist);
        // failed → Failed/IsStructuredEditable=false and the guard below refuses.
        if (RawParseState == RawParseState.Pending)
        {
            ReparseRawText();
        }

        if (_doc is null || !IsStructuredEditable)
        {
            throw new InvalidOperationException(
                "Structured editing is disabled — load a config and fix any raw-TOML parse errors first.");
        }

        if (newValue is null)
        {
            _doc.RemoveKey(entry.KeyPath);
        }
        else
        {
            WriteValue(_doc, entry, newValue);
        }

        entry.RefreshFrom(_doc);
        SetRawTextInternal(_doc.ToText()); // IC-1: after a structured edit, the raw text IS doc.ToText()
        IsDirty = true;
        SaveNotice = null; // E3: the "saved" notice is transient — any edit clears it
        RestartValidationDebounce(); // E2: EVERY edit — structured or raw — revalidates
    }

    private static void WriteValue(TomlConfigDocument doc, SettingEntryViewModel entry, object newValue)
    {
        switch (entry.ValueType)
        {
            case SettingValueType.Bool when newValue is bool b:
                doc.SetBool(entry.KeyPath, b);
                return;
            case SettingValueType.Long when newValue is long l:
                doc.SetLong(entry.KeyPath, l);
                return;
            case SettingValueType.Long when newValue is int i:
                doc.SetLong(entry.KeyPath, i);
                return;
            case SettingValueType.Float when newValue is double d:
                doc.SetDouble(entry.KeyPath, d);
                return;
            case SettingValueType.Float when newValue is long l:
                doc.SetDouble(entry.KeyPath, l);
                return;
            case SettingValueType.Float when newValue is int i:
                doc.SetDouble(entry.KeyPath, i);
                return;
            case SettingValueType.String when newValue is string s:
                doc.SetString(entry.KeyPath, s);
                return;
            case SettingValueType.StringArray when newValue is IReadOnlyList<string> a:
                doc.SetStringArray(entry.KeyPath, a);
                return;
            default:
                throw new ArgumentException(
                    $"A {newValue.GetType().Name} value does not match setting type {entry.ValueType} for '{entry.KeyPath}'.",
                    nameof(newValue));
        }
    }

    /// <summary>
    /// Re-parses the CURRENT raw text (P5b-E2; E2's debounce drives this after a user
    /// raw edit): parse-clean → the new document REPLACES the old one and every entry
    /// refreshes from it; parse errors → the last-good document is kept for display
    /// only and the structured pane stays disabled until a clean re-parse.
    /// Synchronous and UI-thread-affine — callers off the UI thread must marshal.
    /// </summary>
    public void ReparseRawText()
    {
        var parsed = TomlConfigDocument.Parse(RawText);
        if (parsed.HasErrors)
        {
            RawParseState = RawParseState.Failed;
            IsStructuredEditable = false;
            return;
        }

        ReplaceDocument(parsed);
    }

    /// <summary>A parse-clean re-parse of the raw text REPLACES the shared document
    /// (IC-1/P5b-E2) and every entry re-projects from it.</summary>
    private void ReplaceDocument(TomlConfigDocument parsed)
    {
        _doc = parsed;
        foreach (var section in Sections)
        {
            foreach (var entry in section.Entries)
            {
                entry.RefreshFrom(parsed);
            }
        }

        RawParseState = RawParseState.Clean;
        IsStructuredEditable = true;
    }

    /// <summary>Any non-suppressed write is a USER raw edit: dirty + parse Pending
    /// (E2's debounced re-parse picks it up).</summary>
    partial void OnRawTextChanged(string value)
    {
        if (_suppressRawTextSideEffects)
        {
            return;
        }

        IsDirty = true;
        RawParseState = RawParseState.Pending;
        SaveNotice = null; // E3: the "saved" notice is transient — any edit clears it
        RestartValidationDebounce();
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

    partial void OnFilterTextChanged(string value) => ApplyFilter();

    /// <summary>Recomputes every section's visible entries and hides sections with
    /// zero matches. Synchronous, UI-thread-affine (runs from the FilterText binding
    /// setter or inside the load publication post).</summary>
    private void ApplyFilter()
    {
        var filter = FilterText.Trim();
        foreach (var section in Sections)
        {
            section.ApplyFilter(filter);
        }

        VisibleSections = filter.Length == 0
            ? Sections
            : Sections.Where(s => s.VisibleEntries.Count > 0).ToArray();
    }

    // ----------------------------------- E2: debounced off-thread validation pipeline

    /// <summary>Test seam (6d): the in-flight debounced validation run, or a completed task when none is
    /// pending. Tests await THIS to observe a validation cycle deterministically instead of racing a
    /// wall-clock dispatcher-post timeout - the run completes exactly when its publication has posted (the
    /// dispatcher post is the last thing the run does), so awaiting it is starvation-proof (it takes as long
    /// as the thread pool needs, never a false timeout). Not part of the production surface.</summary>
    internal Task PendingValidation => _validationRun ?? Task.CompletedTask;

    /// <summary>
    /// Restarts the edit-session debounce: cancels the previous session's token and
    /// starts a new run over the CURRENT raw text. Called on every structured edit and
    /// every user raw edit. UI-thread-affine like every other mutator here.
    /// </summary>
    private void RestartValidationDebounce()
    {
        CancelValidationSession();
        _validationCts = new CancellationTokenSource();
        _validationRun = RunValidationAsync(RawText, _validationCts.Token);
    }

    private void CancelValidationSession()
    {
        _validationCts?.Cancel();
        _validationCts?.Dispose();
        _validationCts = null;
    }

    private async Task RunValidationAsync(string candidate, CancellationToken sessionToken)
    {
        try
        {
            await Task.Delay(_validationDebounce, sessionToken).ConfigureAwait(false);

            // The whole run — gate, parse, schema validation, OPSEC evaluation — stays
            // off the UI thread; only the finished results are marshalled (IC-5).
            await Task.Run(
                async () =>
                {
                    await _validationGate(sessionToken).ConfigureAwait(false);

                    var doc = TomlConfigDocument.Parse(candidate);
                    var report = ConfigValidator.Validate(doc);
                    var concerns = OpsecConfigRules.Evaluate(doc);

                    // The block mirror reads the protection INTENT at validation time
                    // (P5b-U1). The reader is the display-polarity one (all-false on any
                    // read failure): a wrongly-ENABLED Save is fine here because the
                    // helper's fail-closed write policy enforces regardless.
                    var intent = _stateReader.Read();

                    // Stale drop (E2): a newer edit (or a reload) cancelled this session
                    // while the run was already past its delay — its results describe a
                    // text the user has moved beyond. Drop WITHOUT posting.
                    if (sessionToken.IsCancellationRequested)
                    {
                        return;
                    }

                    _ui.Post(() =>
                    {
                        // Re-check on the UI thread: the session may have gone stale
                        // between the post and its dispatch (production dispatchers queue).
                        if (sessionToken.IsCancellationRequested)
                        {
                            return;
                        }

                        PublishValidation(doc, report, concerns, intent);
                    });
                },
                sessionToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Expected: this session was superseded by a newer edit's debounce restart —
            // dropping silently IS the contract.
        }
        catch (Exception)
        {
            // A fault escaping this fire-and-forget run would go unobserved and silently
            // freeze the validation panel/OPSEC warnings at stale values — a safety
            // concern for this OPSEC tool. Swallow and let the next edit's run try
            // again. CA1031 is suppressed for this file only; see .editorconfig.
        }
    }

    /// <summary>
    /// UI-thread publication of one validation run (E2): the FULL local issue list, the
    /// OPSEC concerns, <see cref="IsValid"/>, and E1's raw-parse-state transition — a
    /// <see cref="RawParseState.Pending"/> user raw edit resolves HERE with the
    /// already-parsed candidate (parse-clean REPLACES the shared doc and the structured
    /// values refresh; parse errors grey the structured pane out). Any raw-text change
    /// restarts the session, so <paramref name="doc"/> is always the parse of the
    /// CURRENT <see cref="RawText"/> when a publication lands.
    /// </summary>
    private void PublishValidation(
        TomlConfigDocument doc,
        ValidationReport report,
        IReadOnlyList<OpsecConcern> concerns,
        ProtectionIntent intent)
    {
        if (RawParseState == RawParseState.Pending)
        {
            if (doc.HasErrors)
            {
                RawParseState = RawParseState.Failed;
                IsStructuredEditable = false;
            }
            else
            {
                ReplaceDocument(doc);
            }
        }

        ValidationIssues = report.Issues;
        OpsecConcerns = concerns;
        IsValid = report.IsValid;
        SaveBlockedReason = ComputeSaveBlockedReason(intent, concerns);
    }

    /// <summary>P5b-U1's client-side mirror of <c>ProtectionAwareConfigWritePolicy</c>:
    /// protection ON + any critical concern → the "OPSEC guard: "-prefixed banner text
    /// joining EVERY blocking concern (IC-10 message shape), plus the plan-worded
    /// guidance. Advisory concerns never block; protection OFF never blocks.</summary>
    private static string? ComputeSaveBlockedReason(ProtectionIntent intent, IReadOnlyList<OpsecConcern> concerns)
    {
        if (!intent.ProtectionEnabled)
        {
            return null;
        }

        var blocking = concerns
            .Where(c => c.Severity is OpsecConcernSeverity.KillSwitchCritical or OpsecConcernSeverity.ProtectionCritical)
            .Select(c => c.Message)
            .ToList();
        if (blocking.Count == 0)
        {
            return null;
        }

        return "OPSEC guard: " + string.Join("; ", blocking)
            + " — disable protection to save an off-spec config, or fix the flagged keys";
    }

    // -------------------------------------- E3: Save & apply command + outcome states

    /// <summary>E3's Save enable gate, verbatim from the plan: dirty, schema-valid per
    /// the LAST PUBLISHED validation, not OPSEC-blocked, and idle. The published
    /// <see cref="IsValid"/>/<see cref="SaveBlockedReason"/> can be STALE while an
    /// edit's debounce is still pending — the command body closes that race by
    /// synchronously re-validating the exact text it is about to send.</summary>
    public bool CanSave => IsDirty && IsValid && SaveBlockedReason is null && !IsBusy;

    /// <summary>
    /// Save &amp; apply (E3): synchronously re-validate the EXACT <see cref="RawText"/>
    /// being sent (parse + <see cref="ConfigValidator"/> + the OPSEC mirror — the
    /// validation-currency pre-flight fix), abort with the panel updated if anything
    /// fails, then dispatch <see cref="IConfigFileService.SaveAndApplyAsync"/> with the
    /// LOAD-time base sha (P5b-E8) under the single busy gate.
    ///
    /// <para>DELIBERATELY not cancellable (no <c>CancellationToken</c> parameter): a
    /// cancellable <c>AsyncRelayCommand</c> CANCELS the previous invocation's token on
    /// re-invocation, so a double-click would abort an in-flight save between the write
    /// and the restart — manufacturing exactly the RestartFailed hazard the double-click
    /// guard exists to prevent. Once dispatched, a save runs to its outcome (bounded by
    /// the service's injectable status-poll timeout).</para>
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanSave))]
    private async Task SaveAndApplyAsync()
    {
        // ExecuteAsync does not itself consult CanExecute, so re-entry (double-click
        // while busy) and the hard preconditions are re-checked here — the Dashboard's
        // _inFlight discipline.
        if (IsBusy || !IsDirty || BaseSha256 is null)
        {
            return;
        }

        // Validation currency: the enable gate alone races the debounce. Re-run the
        // same parse + schema validation + OPSEC-mirror check synchronously on the
        // EXACT candidate text (cheap, in-memory), publish the result either way (the
        // panel explains an abort), and only then dispatch. This run supersedes any
        // pending debounce session — cancel it so a stale publication can never land
        // after (or during) the save.
        var candidate = RawText;
        var baseSha = BaseSha256;
        CancelValidationSession();
        var doc = TomlConfigDocument.Parse(candidate);
        var report = ConfigValidator.Validate(doc);
        var concerns = OpsecConfigRules.Evaluate(doc);
        PublishValidation(doc, report, concerns, _stateReader.Read()); // pre-await: still on the UI thread
        if (!IsValid || SaveBlockedReason is not null)
        {
            return; // the validation panel now carries the reason
        }

        IsBusy = true;
        // A new attempt starts clean: the PREVIOUS attempt's per-attempt surfaces must
        // not linger under this one's outcome. The persistent RestartFailed/
        // ProxyRejected states are NOT cleared here — only their defined exits clear
        // them (Applied / Revert / successful reload).
        SaveNotice = null;
        SaveError = null;
        ConflictMessage = null;
        HelperIncompatibleMessage = null;
        try
        {
            var outcome = await _configFile
                .SaveAndApplyAsync(candidate, baseSha, CancellationToken.None)
                .ConfigureAwait(false);
            await ApplySaveOutcomeAsync(outcome, candidate).ConfigureAwait(false);
        }
        finally
        {
            _ui.Post(() => IsBusy = false);
        }
    }

    /// <summary>Maps a save outcome onto the editor's state surfaces. Runs on a
    /// post-await continuation — every observable write posts (IC-5).
    /// <paramref name="candidate"/> is the exact text the save DISPATCHED: when the
    /// raw text has moved past it (an edit landed while the save was in flight), the
    /// write-landed arms keep the editor dirty and skip their reload — a reload would
    /// destroy the newer edit, and a forced clean state would orphan it.</summary>
    private async Task ApplySaveOutcomeAsync(ConfigSaveOutcome outcome, string candidate)
    {
        // Belt and suspenders: the view disables the editors while IsBusy, but a
        // keystroke can land before the disable renders, and the VM seam has no view
        // in tests. Reading RawText off the UI thread here is stable — edits are
        // UI-thread-affine and the view blocks new ones for the rest of the outcome
        // handling while the busy flag is up.
        var editedMidFlight = !string.Equals(RawText, candidate, StringComparison.Ordinal);
        switch (outcome.Kind)
        {
            case ConfigSaveOutcomeKind.Applied:
                if (editedMidFlight)
                {
                    // The save itself succeeded, but reloading would clobber the newer
                    // edit — keep the editor dirty on the user's text and say so.
                    _ui.Post(() =>
                    {
                        ProxyRejectedMessage = null; // the save WAS applied — its defined exit
                        SaveNotice = "Configuration saved and applied — an edit made during the save is still unsaved.";
                    });
                    break;
                }

                // Reload fresh from disk: the new base sha for the NEXT save comes from
                // re-reading the file the helper just wrote, never from trusting the
                // editor's own text (IC-9 — the sha is always over on-disk bytes).
                await LoadAsync(CancellationToken.None).ConfigureAwait(false);
                _ui.Post(() =>
                {
                    // Applied is one of ProxyRejected's only two exits (the other is
                    // an explicit Revert) — the reload above deliberately spares it.
                    ProxyRejectedMessage = null;
                    SaveNotice = "Configuration saved and applied.";
                });
                break;

            case ConfigSaveOutcomeKind.Conflict:
                // Nothing was written; the user's text stays. Reloading is the
                // banner's explicit action, never automatic (the plan's Conflict UX).
                _ui.Post(() => ConflictMessage = outcome.Message
                    ?? "config changed on disk — Reload to pick up the new file; your edits stay in the editor until you Reload");
                break;

            case ConfigSaveOutcomeKind.HelperIncompatible:
                _ui.Post(() => HelperIncompatibleMessage = outcome.Message
                    ?? "helper protocol version does not match this app — update the helper and app together, then retry");
                break;

            case ConfigSaveOutcomeKind.RestartFailed:
                // The write LANDED: disk == the dispatched candidate, so (absent a
                // mid-flight edit) reloading clobbers nothing and re-bases the CAS
                // sha — with a stale base the recommended re-edit path would always
                // manufacture a Conflict whose Reload discards the user's fix. The
                // reload also clears dirty, mirroring the Applied arm's ordering.
                // MANDATORY ordering: LoadAsync's publication clears
                // RestartFailedMessage, so the persistent state posts strictly AFTER.
                if (!editedMidFlight)
                {
                    await LoadAsync(CancellationToken.None).ConfigureAwait(false);
                }

                _ui.Post(() => RestartFailedMessage = outcome.Message
                    ?? "config saved, but the proxy restart failed — status unverified");
                break;

            case ConfigSaveOutcomeKind.ProxyRejected:
                // Same as RestartFailed: the write landed, so reload-first re-bases
                // the sha and clears dirty; a mid-flight edit skips the reload and
                // stays dirty. LoadAsync deliberately spares ProxyRejectedMessage,
                // but keep the post-reload ordering symmetric with RestartFailed.
                if (!editedMidFlight)
                {
                    await LoadAsync(CancellationToken.None).ConfigureAwait(false);
                }

                _ui.Post(() => ProxyRejectedMessage = outcome.Message
                    ?? "new config rejected by proxy — Revert or re-edit");
                break;

            case ConfigSaveOutcomeKind.Rejected:
            case ConfigSaveOutcomeKind.HelperUnavailable:
            case ConfigSaveOutcomeKind.TooLarge:
            default:
                // Refusals and transport losses share the error panel; the message is
                // the helper's/orchestrator's own, shown verbatim (IC-10). The default
                // arm keeps any FUTURE outcome kind visible instead of silently green.
                _ui.Post(() => SaveError = outcome.Message ?? "the save failed");
                break;
        }
    }

    // ------------------------------- E3: Revert (IC-7) + tab-activation freshness

    /// <summary>The Revert button's label, pinned by IC-7 — the view binds this.</summary>
    public const string RevertLabel = "Revert to on-disk config";

    /// <summary>Revert's enable gate: something to discard (dirty) or a persistent
    /// post-save failure state whose documented recovery is Revert — and never while
    /// the single busy owner is held by a save.</summary>
    public bool CanRevert =>
        !IsBusy && (IsDirty || RestartFailedMessage is not null || ProxyRejectedMessage is not null);

    /// <summary>
    /// "Revert to on-disk config" (IC-7): re-reads the on-disk file and discards
    /// unsaved edits. It NEVER reaches the helper-side backup slot — nothing here talks
    /// to the helper at all. Revert is a defined exit for BOTH persistent post-save
    /// failure states. Non-cancellable for the same reason as Save: a re-invocation
    /// must be a no-op, not a cancellation of the in-flight reload.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanRevert))]
    private async Task RevertAsync()
    {
        if (IsBusy)
        {
            return; // never reload state out from under an in-flight save
        }

        IsBusy = true;
        // Pre-await (UI thread): Revert exits every save-outcome surface, including the
        // ProxyRejected state that deliberately survives ordinary reloads.
        SaveNotice = null;
        SaveError = null;
        ConflictMessage = null;
        HelperIncompatibleMessage = null;
        RestartFailedMessage = null;
        ProxyRejectedMessage = null;
        try
        {
            await LoadAsync(CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            _ui.Post(() => IsBusy = false);
        }
    }

    /// <summary>
    /// Tab-activation freshness hook (E3; the shell calls this on tab selection, F2):
    /// a CLEAN, idle editor silently reloads so the tab never shows a stale file after
    /// outside changes — and it re-bases a stale post-write sha after
    /// RestartFailed/ProxyRejected. NEVER while dirty (a tab switch must not discard
    /// edits) and never while the busy owner is held.
    /// </summary>
    public Task OnTabActivatedAsync()
    {
        if (!WillReloadOnActivation)
        {
            return Task.CompletedTask;
        }

        return LoadAsync(CancellationToken.None);
    }

    /// <summary>True when <see cref="OnTabActivatedAsync"/> would actually reload — and thus
    /// REPLACE <see cref="VisibleSections"/>. The 5g-2 deep-link reads this BEFORE switching
    /// tabs to decide whether to arm its one-shot re-apply: arming when no reload is coming
    /// leaves a stale handler that the next filter keystroke would fire, yanking the user's
    /// section selection back (WP2 review finding). Single source of truth with the guard above.</summary>
    public bool WillReloadOnActivation => !IsDirty && !IsBusy;

    public void Dispose()
    {
        CancelValidationSession();
        GC.SuppressFinalize(this);
    }
}
