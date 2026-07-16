using System.Collections.Generic;
using System.Linq;
using DnsCryptControl.Core.Schema;
using DnsCryptControl.Core.Toml;
using Tomlyn.Model;

namespace DnsCryptControl.Core.Validation;

/// <summary>
/// Validates a parsed dnscrypt-proxy.toml against the authoritative ConfigCatalog:
/// syntax errors (Error), wrong value types for known keys (Error), unknown keys
/// (Warning), and deprecated keys (Warning with migration hint).
/// </summary>
public static class ConfigValidator
{
    // Sections whose immediate children are user-chosen names (dynamic tables), e.g.
    // [sources.public-resolvers], [schedules.night], [static.myserver]. Inside these we
    // do not emit "unknown key/section" warnings, because the child names and their
    // sub-keys are not fixed catalog entries. (Deep type-checking within these sections
    // is handled later by the structured editor.)
    private static readonly HashSet<string> DynamicSections =
        new(System.StringComparer.Ordinal) { "sources", "schedules", "static" };

    public static ValidationReport Validate(TomlConfigDocument doc)
    {
        System.ArgumentNullException.ThrowIfNull(doc);
        var issues = new List<ValidationIssue>();

        if (doc.HasErrors)
        {
            foreach (var err in doc.Errors)
                issues.Add(new ValidationIssue("(syntax)", err, ValidationSeverity.Error));
            return new ValidationReport(issues); // can't reason about a broken document
        }

        ValidateTable(doc, prefix: "", suppressUnknown: false, issues);
        return new ValidationReport(issues);
    }

    private static void ValidateTable(TomlConfigDocument doc, string prefix, bool suppressUnknown, List<ValidationIssue> issues)
    {
        var raw = prefix.Length == 0 ? doc.GetRaw0() : doc.GetRaw(prefix);
        if (raw is not TomlTable table) return;

        foreach (var key in table.Keys)
        {
            var path = prefix.Length == 0 ? key : $"{prefix}.{key}";
            var value = table[key];

            if (value is TomlTable)
            {
                if (prefix.Length == 0)
                {
                    // top-level table => a [section]
                    if (ConfigCatalog.Sections.Contains(key))
                        ValidateTable(doc, path, DynamicSections.Contains(key), issues);
                    else if (!suppressUnknown)
                        issues.Add(new ValidationIssue(path, $"Unknown section '[{path}]'.", ValidationSeverity.Warning));
                }
                else
                {
                    // nested table within a section (e.g. a dynamic <name> sub-table)
                    ValidateTable(doc, path, suppressUnknown, issues);
                }
                continue;
            }

            var descriptor = ConfigCatalog.Find(path);
            if (descriptor is null)
            {
                if (!suppressUnknown)
                    issues.Add(new ValidationIssue(path, $"Unknown key '{path}'.", ValidationSeverity.Warning));
                continue;
            }

            if (descriptor.Deprecated)
            {
                var hint = descriptor.ReplacedBy is { Length: > 0 } r
                    ? $"Key '{path}' is deprecated; use '{r}'."
                    : $"Key '{path}' is deprecated.";
                issues.Add(new ValidationIssue(path, hint, ValidationSeverity.Warning));
            }

            if (!TypeMatches(descriptor.Type, value))
                issues.Add(new ValidationIssue(path,
                    $"Key '{path}' expects {descriptor.Type} but got {value?.GetType().Name ?? "null"}.",
                    ValidationSeverity.Error));
        }
    }

    private static bool TypeMatches(SettingValueType expected, object? value) => expected switch
    {
        SettingValueType.Bool => value is bool,
        SettingValueType.Long => value is long,
        SettingValueType.Float => value is double or long,
        SettingValueType.String => value is string,
        SettingValueType.StringArray => value is TomlArray,
        SettingValueType.Table => value is TomlTable,
        // An array of inline tables (anonymized_dns.routes = [ {..}, {..} ]) is a TomlArray; the
        // [[section.key]] array-of-tables form is a TomlTableArray. Accept both.
        SettingValueType.TableArray => value is TomlArray or TomlTableArray,
        _ => false,
    };
}
