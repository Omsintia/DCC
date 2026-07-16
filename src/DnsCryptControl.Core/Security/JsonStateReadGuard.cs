using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace DnsCryptControl.Core.Security;

/// <summary>
/// Guards the app's off-disk JSON STATE reads (protection.json, ui-state.json, backup.json,
/// installed-binary.json) against a pathologically large or deeply-nested file. These records are a few
/// hundred bytes; a file far above that is corrupt or hostile - the same encoding-amplification class that
/// ballooned a config to 2.26 GB applies to state files too, and <see cref="File.ReadAllText(string)"/> of
/// a multi-GB file OOMs the process before any JSON parsing (and OutOfMemoryException is NOT in these
/// stores' narrow IO/UAC/Json catch lists). ProtectionStateStore in particular is the FAIL-CLOSED AUTHORITY
/// the config write policy and boot reconciliation depend on, so a read that OOMs there defeats fail-closed.
/// Every state reader checks <see cref="IsOversized"/> before reading and <see cref="IsWellFormedWithinDepth"/>
/// before deserializing, so it fails closed to its default instead. Never touches the (working, source-gen)
/// deserialize path itself.
/// </summary>
public static class JsonStateReadGuard
{
    /// <summary>The largest JSON state file the app will read off disk. 1 MiB is thousands of times a real
    /// record and far below the size that would balloon a read; a state file above it is corrupt/hostile.</summary>
    public const long MaxStateBytes = 1L * 1024 * 1024;

    /// <summary>The deepest JSON nesting a state file may have - matches the IPC serializer's hardened cap
    /// (the framework default is 64). A deeper file is an abuse shape, rejected before deserialization.</summary>
    public const int MaxStateDepth = 16;

    /// <summary>True when the file at <paramref name="path"/> exists and exceeds <see cref="MaxStateBytes"/>.
    /// Never throws: a length that can't be read fails toward "not oversized" so the caller's normal read
    /// runs and surfaces the real I/O error via its existing fail-closed catch.</summary>
    public static bool IsOversized(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists && info.Length > MaxStateBytes;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
        catch (ArgumentException) { return false; }
    }

    /// <summary>True when <paramref name="json"/> is well-formed AND nests no deeper than
    /// <see cref="MaxStateDepth"/>. Malformed or too-deep JSON returns <see langword="false"/> so the caller
    /// fails closed BEFORE the source-gen deserialize runs (the deserialize would reject it too, but only at
    /// the framework's depth 64). Never throws. Empty/whitespace is treated as not-well-formed (fail-closed),
    /// matching the stores' existing behaviour of defaulting on an empty/unparseable file.</summary>
    public static bool IsWellFormedWithinDepth(string? json)
    {
        if (string.IsNullOrEmpty(json))
        {
            return false;
        }

        try
        {
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(json), new JsonReaderOptions { MaxDepth = MaxStateDepth });
            while (reader.Read())
            {
            }

            return true;
        }
        catch (JsonException)
        {
            return false; // malformed OR nested past MaxStateDepth -> fail closed
        }
    }
}
