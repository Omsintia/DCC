using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using DnsCryptControl.Core.Rules;
using DnsCryptControl.Core.Toml;
using DnsCryptControl.Platform;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// The Filtering tab (Phase 5d, C2): owns the six per-family rule editors
/// (<see cref="RuleFamilyEditorViewModel"/>) and the block_*/cloak_*/reject_ttl config toggles,
/// and orchestrates the two write paths they ride:
/// <list type="bullet">
///   <item>the family <c>.txt</c> body → the helper's unconditional <c>WriteRuleFile</c> verb
///     (via <see cref="IRuleFileService"/>, IC-13 no-CAS, simplified outcome map);</item>
///   <item>the toggles and the <c>*_file</c>/<c>cloaking_rules</c>/<c>forwarding_rules</c> config
///     keys → the 5b/5c fresh read-modify-write with divergence detection (IC-9), reusing the
///     <c>AnonymizedDnsViewModel</c> <c>_staged</c>/<c>StagedOp</c> pattern EXTENDED to
///     <see cref="StagedKind.Long"/>/<see cref="StagedKind.String"/>.</item>
/// </list>
///
/// <para>ENABLE-AND-WIRE (IC-12, the spike): enabling a family writes its <c>.txt</c> FIRST and only
/// on <see cref="RuleFileWriteOutcomeKind.Applied"/> stages the <c>&lt;family&gt;_file</c> config key
/// — so the proxy is never wired to a missing file. NO-HIJACK: if the key already points at a path
/// other than our canonical <c>%ProgramData%\DnsCryptControl\&lt;fixed&gt;.txt</c>, neither the key nor
/// the <c>.txt</c> is touched; the family goes read-only with an external-path honesty banner. STALENESS
/// (IC-13): before a <c>.txt</c> save the on-disk mtime is re-read and a change since load is warned.</para>
///
/// <para>Pure POCO <see cref="ObservableObject"/> (IC-5): zero WPF types; every post-await observable
/// write goes through the injected <see cref="IUiDispatcher"/>; injectable seams keep tests
/// deterministic with zero sleeps.</para>
/// </summary>
public sealed partial class FilteringViewModel : ObservableObject, IDisposable
{
    private readonly IConfigFileService _configFile;
    private readonly IRuleFileService _ruleFiles;
    private readonly IUiDispatcher _ui;

    private readonly IReadOnlyList<FamilyContext> _families;
    private readonly Dictionary<RuleFamily, FamilyContext> _byFamily;

    /// <summary>Staged config-key edits awaiting Save &amp; apply (IC-9), keyed by config key path.
    /// Holds BOTH the toggle ops (Bool/Long) and the enable-and-wire <c>*_file</c> ops (String).</summary>
    private readonly Dictionary<string, StagedOp> _staged = new(StringComparer.Ordinal);

    /// <summary>The config values read at load (browse-time baseline for the IC-9 divergence check).</summary>
    private readonly Dictionary<string, object?> _loadedValues = new(StringComparer.Ordinal);

    /// <summary>The schedule names defined in the config's <c>[schedules]</c> table, read at Load and
    /// captured by the names-family editors' cross-family lint augmentor (A5). OrdinalIgnoreCase to
    /// mirror go-toml's case-folding of the <c>[schedules.&lt;name&gt;]</c> keys. Mutated in place on
    /// Load (Clear + repopulate) so the augmentor's closure always sees the current set.</summary>
    private readonly HashSet<string> _definedSchedules = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>True while a Load post is repopulating per-family context (file-key value + external
    /// flag): the editors' <c>Rows</c> republish DURING that window would recompute the derived state
    /// against half-set context, so the auto-recompute is suppressed and Load recomputes ONCE at the
    /// end, when every family's wiring is settled.</summary>
    private bool _suppressDerivedRecompute;

    // ---------------------------------------------------------------- observable surfaces

    /// <summary>The six per-family editors, in a stable render order.</summary>
    public IReadOnlyList<RuleFamilyEditorViewModel> Editors { get; }

    [ObservableProperty]
    private bool _loadFailed;

    [ObservableProperty]
    private string? _loadError;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSaveConfig))]
    private bool _isBusy;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSaveConfig))]
    private bool _isDirty;

    /// <summary>The last per-family save notice, keyed by family (verbatim helper messages, IC-10).</summary>
    [ObservableProperty]
    private IReadOnlyDictionary<RuleFamily, string> _familyNotices =
        new Dictionary<RuleFamily, string>();

    [ObservableProperty]
    private IReadOnlyDictionary<RuleFamily, string> _familyErrors =
        new Dictionary<RuleFamily, string>();

    /// <summary>Per-family "wired to an external file you manage — editor read-only here" banner (IC-12).</summary>
    [ObservableProperty]
    private IReadOnlyDictionary<RuleFamily, string> _externalPathBanners =
        new Dictionary<RuleFamily, string>();

    /// <summary>Per-family "the .txt changed on disk since you loaded — reload or overwrite?" warning (IC-13).</summary>
    [ObservableProperty]
    private IReadOnlyDictionary<RuleFamily, string> _stalenessWarnings =
        new Dictionary<RuleFamily, string>();

    // ------------------------------------------------- C3: content-derived honesty (IC-16)

    /// <summary>Per-family "N rules · M comments · K invalid" summary, derived from the family's
    /// CURRENT parsed CONTENT (the editor's rows/findings), NEVER the wiring toggle (IC-16). Always
    /// present for every family (a stable render key); "0 rules · 0 comments." for an empty family.</summary>
    [ObservableProperty]
    private IReadOnlyDictionary<RuleFamily, string> _familySummaries =
        new Dictionary<RuleFamily, string>();

    /// <summary>Per-family honesty banner (IC-16): non-null/present ONLY when the family's <c>*_file</c>
    /// is wired (loaded-or-staged, and OURS not external) yet the <c>.txt</c> holds zero rules — i.e.
    /// "enabled, but nothing is blocked yet". Entry ABSENT (not shown) otherwise, so the View binds
    /// visibility to key presence. Content-derived: the toggle being on never fabricates a protection
    /// claim, and turning it on over an empty file surfaces THIS banner rather than a count.</summary>
    [ObservableProperty]
    private IReadOnlyDictionary<RuleFamily, string> _emptyButWiredBanners =
        new Dictionary<RuleFamily, string>();

    /// <summary>The overall headline: "K of 6 families active" — derived from CONTENT (a family is
    /// "active" only when it is wired to OUR <c>.txt</c> AND that <c>.txt</c> holds ≥1 rule). A wired
    /// but empty family, an unwired family, and an externally-managed family all count as NOT active.</summary>
    [ObservableProperty]
    private string _activeFamiliesHeadline = "0 of 6 filtering families active.";

    /// <summary>The config-write Conflict banner (IC-9): the toggle/`*_file` write aborted because a
    /// staged key changed on disk since it was staged.</summary>
    [ObservableProperty]
    private string? _conflictMessage;

    [ObservableProperty]
    private string? _saveError;

    [ObservableProperty]
    private string? _saveNotice;

    // ---------------------------------------------------------------- toggle projection

    /// <summary>The effective (staged-if-present, else loaded) value of each config toggle, surfaced
    /// for the view's controls. Longs are the raw integer; bools are boxed. Recomputed on every stage.</summary>
    [ObservableProperty]
    private IReadOnlyDictionary<string, object?> _toggleValues =
        new Dictionary<string, object?>(StringComparer.Ordinal);

    public FilteringViewModel(
        IConfigFileService configFile,
        IRuleFileService ruleFiles,
        IReadOnlyList<IRuleFamilyCodec> codecs,
        IUiDispatcher ui,
        TimeSpan? debounceInterval = null,
        Func<CancellationToken, Task>? gate = null)
    {
        ArgumentNullException.ThrowIfNull(configFile);
        ArgumentNullException.ThrowIfNull(ruleFiles);
        ArgumentNullException.ThrowIfNull(codecs);
        ArgumentNullException.ThrowIfNull(ui);
        _configFile = configFile;
        _ruleFiles = ruleFiles;
        _ui = ui;

        var contexts = new List<FamilyContext>(FamilyDescriptors.Count);
        var byKind = codecs.ToDictionary(static c => c.Kind);
        foreach (var descriptor in FamilyDescriptors)
        {
            if (!byKind.TryGetValue(descriptor.Kind, out var codec))
            {
                throw new ArgumentException(
                    $"no codec supplied for rule-file kind {descriptor.Kind}", nameof(codecs));
            }

            // A5: only the two names families carry @schedule references, so only they get the
            // cross-family augmentor that warns on a reference not defined in the config's [schedules].
            var extraLint = descriptor.Kind is RuleFileKind.BlockedNames or RuleFileKind.AllowedNames
                ? (Func<string, IReadOnlyList<RuleLintFinding>>)ScheduleLint
                : null;

            var editor = new RuleFamilyEditorViewModel(codec, ui, debounceInterval, gate, extraLint);
            contexts.Add(new FamilyContext(descriptor, editor));
        }

        _families = contexts;
        _byFamily = contexts.ToDictionary(static c => c.Descriptor.Family);
        Editors = contexts.Select(static c => c.Editor).ToArray();

        // C3 (IC-16): the derived honesty/summary state follows the family's CONTENT, so it must
        // recompute whenever an editor's parse changes — a user raw edit (debounced re-parse) or a
        // structured edit both republish Rows/Findings on the UI thread. The editor's IUiDispatcher is
        // the SAME instance we hold, so these callbacks arrive UI-thread-affine (IC-5) — recompute inline.
        foreach (var context in _families)
        {
            context.Editor.PropertyChanged += (_, e) =>
            {
                if (!_suppressDerivedRecompute
                    && e.PropertyName is nameof(RuleFamilyEditorViewModel.Rows)
                        or nameof(RuleFamilyEditorViewModel.Findings))
                {
                    RefreshDerivedState();
                }
            };
        }
    }

    // --------------------------------------------------------------- load

    /// <summary>
    /// Loads the config (for the toggles + the <c>*_file</c> baseline) and every family's <c>.txt</c>
    /// off the UI thread, then publishes the whole projection in ONE dispatcher post. Fail-closed:
    /// never throws; discards staged edits (Revert / Reload route here).
    /// </summary>
    public async Task LoadAsync(CancellationToken ct)
    {
        var snapshot = await Task.Run(LoadSnapshot, ct).ConfigureAwait(false);

        _ui.Post(() =>
        {
            _staged.Clear();
            _loadedValues.Clear();
            IsDirty = false;
            ConflictMessage = null;
            SaveError = null;
            SaveNotice = null;
            FamilyNotices = new Dictionary<RuleFamily, string>();
            FamilyErrors = new Dictionary<RuleFamily, string>();
            StalenessWarnings = new Dictionary<RuleFamily, string>();

            // Suppress the per-editor auto-recompute while we repopulate every family's wiring; Load
            // recomputes the derived state ONCE at the end, when all context is settled.
            _suppressDerivedRecompute = true;
            try
            {
                // A5: refresh the defined-schedule set BEFORE the editors re-parse, so the names
                // augmentor validates against the freshly-loaded [schedules] table (empty on failure).
                _definedSchedules.Clear();
                foreach (var name in snapshot.DefinedSchedules)
                {
                    _definedSchedules.Add(name);
                }

                if (!snapshot.Success)
                {
                    LoadError = snapshot.Error;
                    LoadFailed = true;
                    ExternalPathBanners = new Dictionary<RuleFamily, string>();
                    foreach (var context in _families)
                    {
                        context.Editor.Load(string.Empty);
                        context.ResetLoadState();
                    }

                    RefreshToggleValues();
                    return;
                }

                foreach (var (key, value) in snapshot.LoadedValues)
                {
                    _loadedValues[key] = value;
                }

                var externalBanners = new Dictionary<RuleFamily, string>();
                foreach (var context in _families)
                {
                    var fileState = snapshot.FamilyFiles[context.Descriptor.Family];
                    context.Editor.Load(fileState.Content);
                    context.LoadedFileKeyValue = fileState.FileKeyValue;
                    context.LoadedMtimeUtc = fileState.MtimeUtc;
                    context.IsExternallyManaged = fileState.IsExternallyManaged;

                    if (fileState.IsExternallyManaged)
                    {
                        externalBanners[context.Descriptor.Family] =
                            $"'{context.Descriptor.FileKeyPath}' is wired to an external file you manage " +
                            $"({fileState.FileKeyValue}) — this editor is read-only for that family. " +
                            "Point the key at the built-in file, or edit the external file directly.";
                    }
                }

                ExternalPathBanners = externalBanners;
                LoadError = null;
                LoadFailed = false;
                RefreshToggleValues();
            }
            finally
            {
                _suppressDerivedRecompute = false;
                RefreshDerivedState();
            }
        });
    }

    /// <summary>Off-thread: read config + every family's <c>.txt</c> + mtime. Never throws.</summary>
    private LoadSnapshotResult LoadSnapshot()
    {
        ConfigLoadResult load;
        try
        {
            load = _configFile.Load();
        }
        catch (Exception ex)
        {
            return LoadSnapshotResult.Fail(ex.Message);
        }

        if (!load.Success)
        {
            return LoadSnapshotResult.Fail(load.Error ?? "the config could not be read");
        }

        TomlConfigDocument doc;
        try
        {
            doc = TomlConfigDocument.Parse(load.Text!);
        }
        catch (Exception ex)
        {
            return LoadSnapshotResult.Fail(ex.Message);
        }

        if (doc.HasErrors)
        {
            return LoadSnapshotResult.Fail("the on-disk config has TOML errors — fix it in the Configuration tab first.");
        }

        // A5: the schedule names defined in [schedules] — the set the names-family augmentor validates
        // @schedule references against. Absent/malformed table => empty set (every reference undefined).
        var schedules = new List<string>();
        if (doc.TryGetSubTables("schedules", out var scheduleTables))
        {
            foreach (var sub in scheduleTables)
            {
                schedules.Add(sub.Name);
            }
        }

        var loadedValues = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var key in ToggleBoolKeys)
        {
            loadedValues[key] = doc.TryGetBool(key, out var b) ? b : (object?)null;
        }

        foreach (var key in ToggleLongKeys)
        {
            loadedValues[key] = doc.TryGetLong(key, out var l) ? l : (object?)null;
        }

        var familyFiles = new Dictionary<RuleFamily, FamilyFileState>();
        foreach (var descriptor in FamilyDescriptors)
        {
            var keyValue = doc.TryGetString(descriptor.FileKeyPath, out var s) ? s : null;
            loadedValues[descriptor.FileKeyPath] = keyValue;

            // No-hijack (IC-12): the key is "ours" when absent/empty OR it already equals our canonical
            // path (case-insensitive, since Windows paths are). Any other non-empty value is an external
            // file we must never overwrite — the family is read-only and we neither read nor write our .txt.
            var isExternal = !string.IsNullOrEmpty(keyValue)
                && !PathEqualsCanonical(keyValue!, descriptor.CanonicalFullPath);

            string content;
            DateTime? mtime;
            if (isExternal)
            {
                content = string.Empty;
                mtime = null;
            }
            else
            {
                var snapshotFile = _ruleFiles.ReadRuleFile(descriptor.Kind);
                content = snapshotFile.State == RuleFileState.Present ? snapshotFile.Content : string.Empty;
                mtime = snapshotFile.LastWriteUtc;
            }

            familyFiles[descriptor.Family] = new FamilyFileState(content, keyValue, mtime, isExternal);
        }

        return LoadSnapshotResult.Ok(load.Sha256!, loadedValues, familyFiles, schedules);
    }

    // --------------------------------------------------------------- enable-and-wire (IC-12)

    /// <summary>
    /// Enables a family (IC-12 ordered enable-and-wire): (1) writes the family's <c>.txt</c> FIRST via
    /// <see cref="IRuleFileService"/>; (2) ONLY on <see cref="RuleFileWriteOutcomeKind.Applied"/> stages
    /// the <c>&lt;family&gt;_file</c> config key = our canonical path, so the proxy is never wired to a
    /// missing file. Refused (no-op) for an externally-managed family (no-hijack). Runs the IC-13
    /// staleness re-read before the write. Never throws.
    /// </summary>
    public async Task EnableFamilyAsync(RuleFamily family, CancellationToken ct)
    {
        var context = _byFamily[family];
        if (context.IsExternallyManaged || IsBusy)
        {
            return;
        }

        // A FATAL-lint (Error) raw text must never be wired — mirror SaveFamilyFileAsync's IsValid gate
        // (IC-11). Without this, Enable & wire would write an invalid rule file that Save correctly refuses
        // (a fail-open IP, or a startup-breaking cloak/forwarding rule that stops the proxy on the next
        // apply), defeating the strict-lint protection on the primary first-setup button.
        if (!context.Editor.IsValid)
        {
            _ui.Post(() => FamilyErrors = WithEntry(FamilyErrors, family,
                "this rule file has invalid (red) lines — fix them before enabling."));
            return;
        }

        IsBusy = true;
        try
        {
            // IC-13: re-read the on-disk mtime immediately before the write; a change since load is a
            // staleness warning (the .txt write is unconditional last-writer-wins, so we cannot CAS —
            // we surface the divergence and still let the user proceed).
            var freshMtime = _ruleFiles.TryGetMtime(context.Descriptor.Kind);
            if (IsStale(context.LoadedMtimeUtc, freshMtime))
            {
                _ui.Post(() => StalenessWarnings = WithEntry(
                    StalenessWarnings, family,
                    "this rule file changed on disk since you loaded it — reload to review, or Enable again to overwrite it."));
            }

            var content = context.Editor.RawText;

            // (1) the .txt write FIRST — the proxy is never wired to a missing file. The service's
            // contract is "never throws", but guard anyway so a transport throw degrades to a typed
            // HelperUnavailable outcome (fail-closed) rather than escaping the try/finally.
            RuleFileWriteOutcome outcome;
            try
            {
                outcome = await _ruleFiles.WriteRuleFileAsync(context.Descriptor.Kind, content, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                outcome = new RuleFileWriteOutcome(
                    RuleFileWriteOutcomeKind.HelperUnavailable,
                    "the save could not be sent to the helper — the rule file may not have been written; reload before retrying.");
            }

            if (outcome.Kind != RuleFileWriteOutcomeKind.Applied)
            {
                _ui.Post(() => ApplyTxtOutcome(family, outcome));
                return;
            }

            // (2) only NOW stage the config key = our canonical path (rides the IC-9 WriteConfig at Save).
            _ui.Post(() =>
            {
                // Re-read the mtime the write ACTUALLY produced (M2), mirroring SaveFamilyFileAsync.
                // Anchoring to the PRE-write freshMtime (M1, or null for a missing-at-load file) would
                // make the very next Save/Enable see M2 != M1 and spuriously flag the file as
                // "changed on disk since you loaded it" with no external writer involved.
                context.LoadedMtimeUtc = _ruleFiles.TryGetMtime(context.Descriptor.Kind) ?? freshMtime;
                StageString(context.Descriptor.FileKeyPath, context.Descriptor.CanonicalFullPath);
                // A successful write clears any prior per-family error (mirrors ApplyTxtOutcome's Applied
                // case in SaveFamilyFileAsync) so a stale "Could not save" banner does not linger.
                FamilyErrors = WithoutEntry(FamilyErrors, family);
                FamilyNotices = WithEntry(FamilyNotices, family,
                    outcome.Message ?? "rule file written; wiring it into the config on Save.");
                RefreshStagedState();
                // The newly-staged *_file op changes the family's effective wiring — the derived
                // active/empty state now follows it (content-derived, IC-16).
                RefreshDerivedState();
            });
        }
        finally
        {
            _ui.Post(() => IsBusy = false);
        }
    }

    /// <summary>
    /// Saves a family's edited <c>.txt</c> body (IC-13 no-CAS): staleness re-read → the simplified
    /// outcome map (Applied/Rejected/HelperUnavailable/TooLarge). Does NOT touch the config key — that
    /// is only (re)wired by <see cref="EnableFamilyAsync"/>. Refused for an externally-managed family.
    /// </summary>
    public async Task SaveFamilyFileAsync(RuleFamily family, CancellationToken ct)
    {
        var context = _byFamily[family];
        if (context.IsExternallyManaged || IsBusy)
        {
            return;
        }

        // A FATAL-lint (Error) raw text must never be sent — mirror the editor's IsValid gate (IC-11).
        if (!context.Editor.IsValid)
        {
            _ui.Post(() => FamilyErrors = WithEntry(FamilyErrors, family,
                "this rule file has invalid (red) lines — fix them before saving."));
            return;
        }

        IsBusy = true;
        try
        {
            var freshMtime = _ruleFiles.TryGetMtime(context.Descriptor.Kind);
            if (IsStale(context.LoadedMtimeUtc, freshMtime))
            {
                _ui.Post(() => StalenessWarnings = WithEntry(
                    StalenessWarnings, family,
                    "this rule file changed on disk since you loaded it — reload to review, or Save again to overwrite it."));
            }

            RuleFileWriteOutcome outcome;
            try
            {
                outcome = await _ruleFiles
                    .WriteRuleFileAsync(context.Descriptor.Kind, context.Editor.RawText, ct)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Contract is "never throws", but fail closed if it ever does.
                outcome = new RuleFileWriteOutcome(
                    RuleFileWriteOutcomeKind.HelperUnavailable,
                    "the save could not be sent to the helper — the rule file may not have been written; reload before retrying.");
            }

            _ui.Post(() =>
            {
                if (outcome.Kind == RuleFileWriteOutcomeKind.Applied)
                {
                    // Re-anchor the load-time mtime to what we just wrote so a subsequent Save is not
                    // spuriously flagged stale. The staleness warning itself SURVIVES: if the user
                    // overwrote a version that had changed on disk, that fact stays surfaced until the
                    // next Load — clearing it here would hide that they clobbered a newer file.
                    context.LoadedMtimeUtc = _ruleFiles.TryGetMtime(context.Descriptor.Kind) ?? freshMtime;
                }

                ApplyTxtOutcome(family, outcome);
            });
        }
        finally
        {
            _ui.Post(() => IsBusy = false);
        }
    }

    /// <summary>Maps a rule-file write outcome onto the per-family notice/error surfaces (verbatim
    /// helper messages, IC-10). The simplified map: only Applied/Rejected/HelperUnavailable/TooLarge.</summary>
    private void ApplyTxtOutcome(RuleFamily family, RuleFileWriteOutcome outcome)
    {
        switch (outcome.Kind)
        {
            case RuleFileWriteOutcomeKind.Applied:
                FamilyErrors = WithoutEntry(FamilyErrors, family);
                FamilyNotices = WithEntry(FamilyNotices, family, outcome.Message ?? "rule file saved.");
                break;

            case RuleFileWriteOutcomeKind.Rejected:
            case RuleFileWriteOutcomeKind.HelperUnavailable:
            case RuleFileWriteOutcomeKind.TooLarge:
            default:
                FamilyNotices = WithoutEntry(FamilyNotices, family);
                FamilyErrors = WithEntry(FamilyErrors, family, outcome.Message ?? "the rule file could not be saved.");
                break;
        }
    }

    // --------------------------------------------------------------- toggles (IC-9 staging)

    /// <summary>Stages a boolean toggle edit (block_ipv6/block_unqualified/block_undelegated/cloak_ptr).</summary>
    public void StageToggleBool(string keyPath, bool value)
    {
        if (!ToggleBoolKeys.Contains(keyPath))
        {
            throw new ArgumentException($"'{keyPath}' is not a filtering boolean toggle.", nameof(keyPath));
        }

        var loaded = _loadedValues.TryGetValue(keyPath, out var v) ? v as bool? : null;
        _staged[keyPath] = new StagedOp(keyPath, StagedKind.Bool, loaded, value);
        RefreshStagedState();
    }

    /// <summary>Stages a long toggle edit (reject_ttl/cloak_ttl).</summary>
    public void StageToggleLong(string keyPath, long value)
    {
        if (!ToggleLongKeys.Contains(keyPath))
        {
            throw new ArgumentException($"'{keyPath}' is not a filtering integer toggle.", nameof(keyPath));
        }

        var loaded = _loadedValues.TryGetValue(keyPath, out var v) ? v as long? : null;
        _staged[keyPath] = new StagedOp(keyPath, StagedKind.Long, loaded, value);
        RefreshStagedState();
    }

    private void StageString(string keyPath, string value)
    {
        var loaded = _loadedValues.TryGetValue(keyPath, out var v) ? v as string : null;
        _staged[keyPath] = new StagedOp(keyPath, StagedKind.String, loaded, value);
    }

    private void RefreshStagedState()
    {
        IsDirty = _staged.Count > 0;
        SaveNotice = null;
        RefreshToggleValues();
    }

    private void RefreshToggleValues()
    {
        var values = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var key in ToggleBoolKeys.Concat(ToggleLongKeys))
        {
            values[key] = _staged.TryGetValue(key, out var op)
                ? op.FinalValue
                : (_loadedValues.TryGetValue(key, out var loaded) ? loaded : null);
        }

        ToggleValues = values;
    }

    // ------------------------------------------------- A5: cross-family @schedule validation

    /// <summary>
    /// The names-family lint augmentor (A5): re-parses the family's raw text as a
    /// <see cref="NameRuleFile"/> and returns a <see cref="RuleLintSeverity.Warning"/> for every
    /// <c>@schedule</c> reference NOT present in the config's <c>[schedules]</c> table
    /// (<see cref="_definedSchedules"/>). The proxy silently DROPS a rule whose schedule is undefined
    /// (it blocks nothing) — a security-relevant silent no-op for a blocking tool — so it must be
    /// surfaced. Pure/total: no throw, no I/O; runs on the editor's off-thread debounce too. Captured
    /// once per names editor; reads <see cref="_definedSchedules"/> live so a reload's new set applies.
    /// </summary>
    private IReadOnlyList<RuleLintFinding> ScheduleLint(string rawText) =>
        ScheduleReferences.FindUndefined(NameRuleFile.Parse(rawText), _definedSchedules);

    // ------------------------------------------------- C3: content-derived honesty (IC-16)

    /// <summary>
    /// Recomputes the per-family summary + honesty banners + the overall "K families active" headline
    /// from the families' CURRENT CONTENT (their editors' parsed rows/findings) and the EFFECTIVE
    /// wiring (staged-if-present, else loaded <c>*_file</c> value) — NEVER the toggle position. Mirrors
    /// <c>AnonymizedDnsViewModel.RefreshDerivedState</c>: displayed state is what the content actually
    /// achieves. UI-thread-affine; called after Load, after an enable-wire stage, after a config
    /// outcome, and on every editor parse change. Externally-managed families are excluded (their
    /// content is unknown to us — the external-path banner speaks for them).
    /// </summary>
    private void RefreshDerivedState()
    {
        var summaries = new Dictionary<RuleFamily, string>();
        var emptyBanners = new Dictionary<RuleFamily, string>();
        var activeCount = 0;

        foreach (var context in _families)
        {
            var family = context.Descriptor.Family;
            var (rules, comments, invalid) = CountRows(context.Editor);
            summaries[family] = FormatSummary(rules, comments, invalid);

            // "Wired" = the EFFECTIVE *_file value (staged-if-present, else loaded) is non-empty. This
            // derives enablement from the config CONTENT, not any UI toggle. An externally-managed
            // family is wired-elsewhere: its content is opaque to us, so it is neither "active" nor a
            // candidate for the empty-but-wired honesty banner (the external-path banner covers it).
            if (context.IsExternallyManaged)
            {
                continue;
            }

            var wired = !string.IsNullOrEmpty(EffectiveFileKeyValue(context));
            if (!wired)
            {
                continue;
            }

            if (rules > 0)
            {
                activeCount++;
            }
            else
            {
                emptyBanners[family] =
                    $"'{context.Descriptor.FileKeyPath}' is wired to the built-in file, but that file has no " +
                    "rules — nothing is blocked yet. Add rules below (and Save) to start filtering.";
            }
        }

        FamilySummaries = summaries;
        EmptyButWiredBanners = emptyBanners;
        ActiveFamiliesHeadline = $"{activeCount} of {_families.Count} filtering families active.";
    }

    /// <summary>The EFFECTIVE <c>*_file</c> value for a family: the staged String op if one is pending
    /// (enable-and-wire), else the value read at load. Empty/absent ⇒ not wired.</summary>
    private string? EffectiveFileKeyValue(FamilyContext context) =>
        _staged.TryGetValue(context.Descriptor.FileKeyPath, out var op) && op.Kind == StagedKind.String
            ? op.FinalValue as string
            : context.LoadedFileKeyValue;

    /// <summary>Counts a family's rule / comment / invalid(Error-lint) lines from the editor's CURRENT
    /// parsed rows — the content, not the toggle. A blank line is neither a rule nor a comment.</summary>
    private static (int Rules, int Comments, int Invalid) CountRows(RuleFamilyEditorViewModel editor)
    {
        var rules = 0;
        var comments = 0;
        var invalid = 0;
        foreach (var row in editor.Rows)
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

            if (row.WorstSeverity == RuleLintSeverity.Error)
            {
                invalid++;
            }
        }

        return (rules, comments, invalid);
    }

    /// <summary>"N rules · M comments[ · K invalid lines (fix before saving)]." — the per-family
    /// content summary (mirrors the editor's own <c>ComputeSummary</c> so the two never drift).</summary>
    private static string FormatSummary(int rules, int comments, int invalid)
    {
        var summary =
            $"{rules} rule{(rules == 1 ? string.Empty : "s")} · {comments} comment{(comments == 1 ? string.Empty : "s")}";
        return invalid > 0
            ? summary + $" · {invalid} invalid line{(invalid == 1 ? string.Empty : "s")} (fix before saving)."
            : summary + ".";
    }

    // --------------------------------------------------------------- Save & apply (IC-9)

    public bool CanSaveConfig => IsDirty && !IsBusy;

    /// <summary>
    /// Save &amp; apply the staged toggle + <c>*_file</c> config-key edits (IC-9): fresh
    /// <see cref="IConfigFileService.Load"/> → fresh doc → ABORT with a preserved staged set + a Conflict
    /// banner when the fresh load fails, the fresh doc <c>HasErrors</c>, or ANY staged key now reads ≠
    /// its browse-time value; else apply the staged ops surgically and hand the candidate + FRESH sha to
    /// <see cref="IConfigFileService.SaveAndApplyAsync"/>. The family <c>.txt</c> bodies are a SEPARATE
    /// path (no CAS) — this only writes config keys. Never throws.
    /// </summary>
    public async Task SaveConfigAsync(CancellationToken ct)
    {
        if (IsBusy || _staged.Count == 0)
        {
            return;
        }

        var dispatched = _staged.Values.ToArray();

        IsBusy = true;
        SaveError = null;
        SaveNotice = null;
        ConflictMessage = null;
        try
        {
            var prepared = await Task.Run(() => PrepareSave(dispatched), ct).ConfigureAwait(false);
            if (!prepared.Success)
            {
                _ui.Post(() => ConflictMessage = prepared.ConflictReason);
                return;
            }

            var outcome = await _configFile
                .SaveAndApplyAsync(prepared.CandidateText!, prepared.FreshSha!, ct)
                .ConfigureAwait(false);

            _ui.Post(() => ApplyConfigOutcome(outcome, dispatched));
        }
        finally
        {
            _ui.Post(() => IsBusy = false);
        }
    }

    /// <summary>IC-9 fresh read + divergence check + candidate build. Off-thread; never throws.</summary>
    private PrepareResult PrepareSave(IReadOnlyList<StagedOp> ops)
    {
        ConfigLoadResult fresh;
        try
        {
            fresh = _configFile.Load();
        }
        catch (Exception ex)
        {
            return PrepareResult.Conflict(
                "config could not be re-read before saving (" + ex.Message + ") — your staged changes stay; Reload to review.");
        }

        if (!fresh.Success)
        {
            return PrepareResult.Conflict(
                "config changed underneath your staged changes — Reload to review; your staged changes stay until you Reload/Revert.");
        }

        TomlConfigDocument doc;
        try
        {
            doc = TomlConfigDocument.Parse(fresh.Text!);
        }
        catch (Exception ex)
        {
            return PrepareResult.Conflict("the on-disk config could not be parsed (" + ex.Message + ") — Reload to review.");
        }

        if (doc.HasErrors)
        {
            return PrepareResult.Conflict(
                "the on-disk config now has TOML errors — Reload to review; your staged changes stay until you Reload/Revert.");
        }

        // (c) any staged op's key now reads != its browse-time value.
        foreach (var op in ops)
        {
            if (Diverged(doc, op))
            {
                return PrepareResult.Conflict(
                    $"'{op.KeyPath}' changed on disk since you staged your edit — Reload to review; your staged changes stay until you Reload/Revert.");
            }
        }

        try
        {
            foreach (var op in ops)
            {
                switch (op.Kind)
                {
                    case StagedKind.Bool when op.FinalValue is bool b:
                        doc.SetBool(op.KeyPath, b);
                        break;
                    case StagedKind.Long when op.FinalValue is long l:
                        doc.SetLong(op.KeyPath, l);
                        break;
                    case StagedKind.String when op.FinalValue is string s:
                        doc.SetString(op.KeyPath, s);
                        break;
                    default:
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            return PrepareResult.Conflict("the staged changes could not be applied (" + ex.Message + ") — Reload to review.");
        }

        return PrepareResult.Ok(doc.ToText(), fresh.Sha256!);
    }

    /// <summary>True when the fresh on-disk value of a staged op's key differs from its browse-time
    /// value (IC-9(c)). An absent key reads as null; the compare is exact per kind.</summary>
    private static bool Diverged(TomlConfigDocument doc, StagedOp op)
    {
        switch (op.Kind)
        {
            case StagedKind.Bool:
            {
                var now = doc.TryGetBool(op.KeyPath, out var b) ? b : (bool?)null;
                return !Nullable.Equals(now, op.BrowseTimeValue as bool?);
            }

            case StagedKind.Long:
            {
                var now = doc.TryGetLong(op.KeyPath, out var l) ? l : (long?)null;
                return !Nullable.Equals(now, op.BrowseTimeValue as long?);
            }

            case StagedKind.String:
            {
                var now = doc.TryGetString(op.KeyPath, out var s) ? s : null;
                return !string.Equals(now, op.BrowseTimeValue as string, StringComparison.Ordinal);
            }

            default:
                return false;
        }
    }

    private void ApplyConfigOutcome(ConfigSaveOutcome outcome, IReadOnlyList<StagedOp> dispatched)
    {
        switch (outcome.Kind)
        {
            case ConfigSaveOutcomeKind.Applied:
                RemoveDispatchedOps(dispatched);
                SaveNotice = "Filtering settings saved and applied.";
                break;

            case ConfigSaveOutcomeKind.Conflict:
                ConflictMessage = outcome.Message
                    ?? "config changed on disk — Reload to review; your staged changes stay until you Reload/Revert.";
                break;

            case ConfigSaveOutcomeKind.RestartFailed:
                RemoveDispatchedOps(dispatched);
                SaveError = outcome.Message ?? "config saved, but the proxy restart failed — status unverified.";
                break;

            case ConfigSaveOutcomeKind.ProxyRejected:
                RemoveDispatchedOps(dispatched);
                SaveError = outcome.Message ?? "config saved, but the proxy did not report running — it appears rejected.";
                break;

            case ConfigSaveOutcomeKind.HelperIncompatible:
            case ConfigSaveOutcomeKind.Rejected:
            case ConfigSaveOutcomeKind.HelperUnavailable:
            case ConfigSaveOutcomeKind.TooLarge:
            default:
                SaveError = outcome.Message ?? "the save failed.";
                break;
        }
    }

    private void RemoveDispatchedOps(IReadOnlyList<StagedOp> dispatched)
    {
        foreach (var op in dispatched)
        {
            if (_staged.TryGetValue(op.KeyPath, out var current) && ReferenceEquals(current, op))
            {
                _staged.Remove(op.KeyPath);

                // Re-anchor the applied value into the load-time baselines so the derived state (and a
                // later divergence check) reflects what is now on disk without waiting for a reload. For
                // a *_file String op this keeps the family "wired" after the enable-wire is applied.
                _loadedValues[op.KeyPath] = op.FinalValue;
                if (op.Kind == StagedKind.String
                    && _byFamily.Values.FirstOrDefault(c => c.Descriptor.FileKeyPath == op.KeyPath) is { } ctx)
                {
                    ctx.LoadedFileKeyValue = op.FinalValue as string;
                }
            }
        }

        IsDirty = _staged.Count > 0;
        RefreshToggleValues();
        RefreshDerivedState();
    }

    // --------------------------------------------------------------- revert / activation

    public Task OnTabActivatedAsync()
    {
        if (IsDirty || IsBusy)
        {
            return Task.CompletedTask;
        }

        return LoadAsync(CancellationToken.None);
    }

    public async Task RevertAsync(CancellationToken ct)
    {
        if (IsBusy)
        {
            return;
        }

        await LoadAsync(ct).ConfigureAwait(false);
    }

    public void Dispose()
    {
        foreach (var context in _families)
        {
            context.Editor.Dispose();
        }

        GC.SuppressFinalize(this);
    }

    // --------------------------------------------------------------- map helpers (UI-thread-affine)

    /// <summary>Immutably sets one family's entry in a per-family message map, replacing the whole map
    /// so the [ObservableProperty] setter fires its own change notification (the source-generated setter
    /// only raises on reference change — a mutated dictionary would be silent).</summary>
    private static Dictionary<RuleFamily, string> WithEntry(
        IReadOnlyDictionary<RuleFamily, string> map, RuleFamily family, string message)
    {
        var next = new Dictionary<RuleFamily, string>((IDictionary<RuleFamily, string>)map)
        {
            [family] = message,
        };
        return next;
    }

    private static Dictionary<RuleFamily, string> WithoutEntry(
        IReadOnlyDictionary<RuleFamily, string> map, RuleFamily family)
    {
        var next = new Dictionary<RuleFamily, string>((IDictionary<RuleFamily, string>)map);
        next.Remove(family);
        return next;
    }

    // --------------------------------------------------------------- static family metadata

    private static bool PathEqualsCanonical(string value, string canonical) =>
        string.Equals(
            value.Trim().TrimEnd('\\', '/'),
            canonical.TrimEnd('\\', '/'),
            StringComparison.OrdinalIgnoreCase);

    private static bool IsStale(DateTime? loaded, DateTime? fresh)
    {
        // Missing at load → present now (or vice-versa), or a different write time, is staleness. If we
        // could not stat at load (null) but can now, treat as changed; both-null (still missing) is clean.
        if (loaded is null && fresh is null)
        {
            return false;
        }

        return !Nullable.Equals(loaded, fresh);
    }

    private static readonly IReadOnlyList<string> ToggleBoolKeys = new[]
    {
        "block_ipv6",
        "block_unqualified",
        "block_undelegated",
        "cloak_ptr",
    };

    private static readonly IReadOnlyList<string> ToggleLongKeys = new[]
    {
        "reject_ttl",
        "cloak_ttl",
    };

    /// <summary>The six rule families' fixed metadata: the helper kind, the config key that wires the
    /// <c>.txt</c> into the proxy, and our canonical filename/path (the ONLY value we ever write for the
    /// key — never user text, IC-7). The names/IPs families are section-scoped keys; cloaking/forwarding
    /// are top-level keys.</summary>
    private static readonly IReadOnlyList<FamilyDescriptor> FamilyDescriptors = new[]
    {
        new FamilyDescriptor(RuleFamily.BlockedNames, RuleFileKind.BlockedNames,
            "blocked_names.blocked_names_file", "blocked-names.txt"),
        new FamilyDescriptor(RuleFamily.AllowedNames, RuleFileKind.AllowedNames,
            "allowed_names.allowed_names_file", "allowed-names.txt"),
        new FamilyDescriptor(RuleFamily.BlockedIps, RuleFileKind.BlockedIps,
            "blocked_ips.blocked_ips_file", "blocked-ips.txt"),
        new FamilyDescriptor(RuleFamily.AllowedIps, RuleFileKind.AllowedIps,
            "allowed_ips.allowed_ips_file", "allowed-ips.txt"),
        new FamilyDescriptor(RuleFamily.Cloaking, RuleFileKind.Cloaking,
            "cloaking_rules", "cloaking-rules.txt"),
        new FamilyDescriptor(RuleFamily.Forwarding, RuleFileKind.Forwarding,
            "forwarding_rules", "forwarding-rules.txt"),
    };

    // --------------------------------------------------------------- projection DTOs

    /// <summary>The identity of one rule family (a stable render/lookup key).</summary>
    public enum RuleFamily
    {
        BlockedNames,
        AllowedNames,
        BlockedIps,
        AllowedIps,
        Cloaking,
        Forwarding,
    }

    private enum StagedKind
    {
        Bool,
        Long,
        String,
    }

    /// <summary>One staged config-key edit (IC-9): the browse-time value (for divergence) and the final
    /// value to write. <see cref="BrowseTimeValue"/>/<see cref="FinalValue"/> are boxed bool/long/string
    /// per <see cref="Kind"/> (an absent key at load boxes as null).</summary>
    private sealed record StagedOp(
        string KeyPath,
        StagedKind Kind,
        object? BrowseTimeValue,
        object? FinalValue);

    /// <summary>Fixed per-family metadata (see <see cref="FamilyDescriptors"/>).</summary>
    private sealed record FamilyDescriptor(
        RuleFamily Family,
        RuleFileKind Kind,
        string FileKeyPath,
        string CanonicalFileName)
    {
        /// <summary>The canonical absolute path our <c>*_file</c> key points at (the no-hijack anchor).</summary>
        public string CanonicalFullPath => System.IO.Path.Combine(UiPaths.ProgramDataDir, CanonicalFileName);
    }

    /// <summary>Mutable per-family runtime state (load-time file key value + mtime + external flag).</summary>
    private sealed class FamilyContext
    {
        public FamilyContext(FamilyDescriptor descriptor, RuleFamilyEditorViewModel editor)
        {
            Descriptor = descriptor;
            Editor = editor;
        }

        public FamilyDescriptor Descriptor { get; }

        public RuleFamilyEditorViewModel Editor { get; }

        public string? LoadedFileKeyValue { get; set; }

        public DateTime? LoadedMtimeUtc { get; set; }

        public bool IsExternallyManaged { get; set; }

        public void ResetLoadState()
        {
            LoadedFileKeyValue = null;
            LoadedMtimeUtc = null;
            IsExternallyManaged = false;
        }
    }

    private sealed record FamilyFileState(
        string Content,
        string? FileKeyValue,
        DateTime? MtimeUtc,
        bool IsExternallyManaged);

    private sealed record LoadSnapshotResult(
        bool Success,
        string? Error,
        string? Sha256,
        IReadOnlyDictionary<string, object?> LoadedValues,
        IReadOnlyDictionary<RuleFamily, FamilyFileState> FamilyFiles,
        IReadOnlyList<string> DefinedSchedules)
    {
        public static LoadSnapshotResult Fail(string error) => new(
            false, error, null,
            new Dictionary<string, object?>(),
            new Dictionary<RuleFamily, FamilyFileState>(),
            Array.Empty<string>());

        public static LoadSnapshotResult Ok(
            string sha,
            IReadOnlyDictionary<string, object?> loadedValues,
            IReadOnlyDictionary<RuleFamily, FamilyFileState> familyFiles,
            IReadOnlyList<string> definedSchedules) =>
            new(true, null, sha, loadedValues, familyFiles, definedSchedules);
    }

    private sealed record PrepareResult(bool Success, string? CandidateText, string? FreshSha, string? ConflictReason)
    {
        public static PrepareResult Ok(string candidate, string sha) => new(true, candidate, sha, null);

        public static PrepareResult Conflict(string reason) => new(false, null, null, reason);
    }
}
