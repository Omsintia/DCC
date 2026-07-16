using DnsCryptControl.Core.Sources;
using DnsCryptControl.Core.Stamps;
using DnsCryptControl.Core.Toml;
using Tomlyn.Model;

namespace DnsCryptControl.Core.AnonymizedDns;

/// <summary>
/// Reads and writes <c>[anonymized_dns].routes</c> — the domain layer over
/// <see cref="TomlConfigDocument"/>'s inline-table-array mutators. Reads BOTH the inline
/// (<c>routes = [ {…} ]</c>) and <c>[[anonymized_dns.routes]]</c> forms; writes ONLY the
/// inline form, and refuses (via <see cref="CanWrite"/>) when a structured write would lose
/// data or corrupt the document (IC-12).
/// </summary>
public static class AnonymizedDnsRoutes
{
    /// <summary>The dotted key path routes live at.</summary>
    public const string KeyPath = "anonymized_dns.routes";

    /// <summary>
    /// Reads the routes from either on-disk form. An absent key yields <c>true</c> with an empty
    /// list. Fail-closed: a malformed element (missing/empty server_name, non-string via list, or
    /// an unexpected extra key) yields <c>false</c> with a reason, never a partial silent read.
    /// </summary>
    public static bool TryRead(TomlConfigDocument doc, out IReadOnlyList<AnonRoute> routes, out IReadOnlyList<string> errors)
    {
        ArgumentNullException.ThrowIfNull(doc);
        var errorList = new List<string>();
        errors = errorList;
        routes = Array.Empty<AnonRoute>();

        if (doc.GetRaw(KeyPath) is null) return true; // absent → no routes (not an error)
        if (!doc.TryGetTableArray(KeyPath, out var items))
        {
            errorList.Add("anonymized_dns.routes is not an array of tables.");
            return false;
        }

        var result = new List<AnonRoute>();
        foreach (var item in items)
        {
            if (!item.TryGetValue("server_name", out var serverObj) || serverObj is not string server || server.Length == 0)
            {
                errorList.Add("A route is missing a non-empty server_name.");
                return false;
            }
            if (!item.TryGetValue("via", out var viaObj) || viaObj is not TomlArray viaArray)
            {
                errorList.Add($"Route [{server}] has no via[] relay list.");
                return false;
            }
            var via = new List<string>(viaArray.Count);
            foreach (var v in viaArray)
            {
                if (v is not string relay)
                {
                    errorList.Add($"Route [{server}] has a non-string via entry.");
                    return false;
                }
                via.Add(relay);
            }
            foreach (var key in item.Keys)
            {
                if (key is not ("server_name" or "via"))
                {
                    errorList.Add($"Route [{server}] has an unexpected key '{key}'.");
                    return false; // a wholesale rewrite would drop it — refuse to read-then-write it
                }
            }
            result.Add(new AnonRoute(server, via));
        }

        routes = result;
        return true;
    }

    /// <summary>
    /// True when routes can be written structurally: the document parses cleanly, routes are not
    /// in <c>[[array-of-tables]]</c> form, and every existing element is exactly
    /// <c>{ server_name, via }</c>. Otherwise <paramref name="reason"/> is a user-presentable
    /// message pointing at the raw editor.
    /// </summary>
    public static bool CanWrite(TomlConfigDocument doc, out string? reason)
    {
        ArgumentNullException.ThrowIfNull(doc);
        if (doc.HasErrors) { reason = "The configuration has parse errors — fix them in the raw editor first."; return false; }
        if (doc.UsesTableArraySyntax(KeyPath))
        {
            reason = "Routes are defined as [[anonymized_dns.routes]] blocks in this config — edit them in the raw editor.";
            return false;
        }
        if (!TryRead(doc, out _, out var errors))
        {
            reason = (errors.Count > 0 ? errors[0] : "The routes are malformed.") + " Edit them in the raw editor.";
            return false;
        }
        reason = null;
        return true;
    }

    /// <summary>
    /// Writes <paramref name="routes"/> as a canonical inline-table array. Callers MUST gate on
    /// <see cref="CanWrite"/> first. Names are validated per IC-7 (server_name and via names must
    /// be the bare allowlist or <c>*</c>; a via entry may also be a valid relay <c>sdns://</c> stamp).
    /// </summary>
    /// <exception cref="ArgumentException">A server_name or via entry fails the IC-7 gate.</exception>
    /// <exception cref="InvalidOperationException">The document has parse errors or routes are in [[…]] form (IC-12).</exception>
    public static void Write(TomlConfigDocument doc, IReadOnlyList<AnonRoute> routes)
    {
        ArgumentNullException.ThrowIfNull(doc);
        ArgumentNullException.ThrowIfNull(routes);

        var items = new List<TomlInlineTableValue>(routes.Count);
        foreach (var route in routes)
        {
            if (!IsValidServerName(route.ServerName))
                throw new ArgumentException($"Invalid route server_name '{route.ServerName}'.", nameof(routes));
            var via = route.Via ?? Array.Empty<string>();
            foreach (var relay in via)
            {
                if (!IsValidVia(relay))
                    throw new ArgumentException($"Invalid via entry '{relay}' in route '{route.ServerName}'.", nameof(routes));
            }
            items.Add(new TomlInlineTableValue()
                .AddString("server_name", route.ServerName)
                .AddStringArray("via", via.ToArray()));
        }

        doc.SetInlineTableArray(KeyPath, items);
    }

    private static bool IsValidServerName(string s) => s == "*" || IsBareName(s);

    private static bool IsValidVia(string s)
    {
        if (s == "*" || IsBareName(s)) return true;
        if (s.StartsWith("sdns:", StringComparison.Ordinal))
            return ServerStampParser.TryParse(s, out var stamp, out _) && stamp is { IsRelay: true };
        return false;
    }

    // The IC-7 bare-name allowlist; the shared predicate lives in ServerNamePolicy.
    private static bool IsBareName(string s) => ServerNamePolicy.IsAllowedName(s);
}
