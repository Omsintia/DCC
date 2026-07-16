using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

namespace DnsCryptControl.Core.Security;

/// <summary>
/// Scrubs filesystem paths and Windows SIDs out of a human-readable error/diagnostic message before it
/// crosses a trust boundary - the privileged LocalSystem helper -> unprivileged UI IPC reply, and the UI's
/// own error surfaces that a user can copy into a shared diagnostics export. A raw platform exception
/// message routinely carries the interactive user's profile path (<c>C:\Users\&lt;name&gt;\...</c>) or a
/// machine/account SID (<c>S-1-5-21-...</c>), which is PII / host-fingerprinting the app never needs to
/// disclose to a lower-privilege reader (finding F6). Applied at the single IPC failure chokepoint
/// (<c>Result.Fail</c>) so every handler's platform-origin message is redacted identically, and at the UI's
/// config-error sites that interpolate a raw exception message.
/// <para>
/// Contract: <b>TOTAL</b> (never throws - it runs on an error path and must never mask the real failure with
/// one of its own), <b>IDEMPOTENT</b> (<c>Redact(Redact(x)) == Redact(x)</c> - the placeholder tokens contain
/// none of the patterns it matches), and a <b>NO-OP on clean text</b> (a message with no path or SID is
/// returned byte-for-byte). It is deliberately biased toward safety over completeness of the message: an
/// unquoted path followed by prose is redacted greedily to the next delimiter, so a message may lose trailing
/// words rather than ever leak a partial path. It intentionally does NOT redact URLs/hostnames (public source
/// URLs are not the secret here) - a <c>scheme://</c> authority is excluded so it is not mistaken for a path.
/// </para>
/// <para>
/// Known residuals (accepted): an UNQUOTED path whose user name contains a space redacts only up to that
/// space, and a DRIVE-LESS path (bare <c>\Users\name\...</c> or relative <c>Users\name\...</c>) is not
/// matched. Both are acceptable because the message sources this scrubs - .NET IO/UAC exceptions and Win32
/// error text - quote full drive-rooted paths (redacted whole by the quoted rule), and no traced call site
/// emits a drive-less path. This is a defense-in-depth net; the clipboard diagnostics export is separately
/// scrubbed by construction (health fields only).
/// </para>
/// </summary>
public static class MessageScrub
{
    /// <summary>Replacement token for a redacted filesystem path. Contains none of the matched patterns
    /// (no drive-colon-separator, no leading double-separator) so re-running Redact is a fixed point.</summary>
    public const string PathPlaceholder = "<path>";

    /// <summary>Replacement token for a redacted Windows security identifier.</summary>
    public const string SidPlaceholder = "<sid>";

    // A QUOTED path - the shape .NET IOException/UnauthorizedAccessException use: 'C:\...' or "\\srv\...".
    // Matched FIRST and running to the closing quote, so a profile path whose user name contains a space
    // ('C:\Users\John Smith\AppData\x') is redacted WHOLE - the unquoted rules below stop at the first space.
    // Requires a drive or UNC prefix right after the opening quote, so an ordinary quoted word is untouched.
    private static readonly Regex QuotedPath =
        new(@"(['""])(?:[A-Za-z]:[\\/]|[\\/]{2})[^'""<>|\r\n]*\1", RegexOptions.CultureInvariant);

    // A UNC / device path: \\server\share\..., \\.\device, \\?\C:\...  (a leading double path-separator).
    // Matched FIRST so a \\?\C:\ device path is redacted whole in one pass, before the drive rule sees the
    // embedded C:\. The (?<!:) lookbehind keeps it off a scheme's "://" (e.g. https://host) - a URL is not a
    // path we need to hide. The tail runs to the next whitespace, quote, angle bracket, or pipe: all four are
    // illegal in a Windows path component, so they are safe delimiters, while ':' and ')' stay IN (a device
    // path embeds a ':' and "Program Files (x86)" embeds ')').
    private static readonly Regex UncPath =
        new(@"(?<!:)[\\/]{2}[^\s""'<>|]+", RegexOptions.CultureInvariant);

    // A drive-rooted path: C:\..., d:/...  (a single drive letter, a colon, a separator, then path chars).
    // The (?<![A-Za-z]) lookbehind requires the drive letter to stand alone, so the trailing letter of a URL
    // scheme ("http" -> the 'p' in "p://") is NOT read as a drive letter, while " C:\" / "'C:\" / a leading
    // "C:\" all match. The colon+separator anchor keeps it off innocuous "3:45" times and "key:value" text.
    private static readonly Regex DrivePath =
        new(@"(?<![A-Za-z])[A-Za-z]:[\\/][^\s""'<>|]*", RegexOptions.CultureInvariant);

    // A Windows security identifier: S-1-<authority>(-<subauthority>)+ (e.g. S-1-5-21-...-1001, S-1-5-18).
    // Requires at least one subauthority so it matches real SIDs but not a bare "S-1-5" fragment.
    // IgnoreCase is belt-and-suspenders: SecurityIdentifier.Value yields an uppercase "S-1-...", but a
    // third-party/registry message could embed a lowercase "s-1-..." and it must still be redacted.
    private static readonly Regex Sid =
        new(@"S-1-\d+(?:-\d+)+", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    /// <summary>Returns <paramref name="message"/> with any drive/UNC/device path replaced by
    /// <see cref="PathPlaceholder"/> and any SID by <see cref="SidPlaceholder"/>. Null or empty is returned
    /// unchanged. Never throws.</summary>
    [return: NotNullIfNotNull(nameof(message))]
    public static string? Redact(string? message)
    {
        if (string.IsNullOrEmpty(message))
        {
            return message;
        }

        var scrubbed = QuotedPath.Replace(message, PathPlaceholder);
        scrubbed = UncPath.Replace(scrubbed, PathPlaceholder);
        scrubbed = DrivePath.Replace(scrubbed, PathPlaceholder);
        scrubbed = Sid.Replace(scrubbed, SidPlaceholder);
        return scrubbed;
    }
}
