using System;
using System.Linq;
using CsCheck;
using DnsCryptControl.Core.Security;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz + regression properties for <see cref="MessageScrub.Redact"/> - the fix for finding F6 (an error
/// message crossing the privileged-helper -> unprivileged-UI wire can carry the interactive user's profile
/// path or a machine/account SID). Oracles: it is TOTAL + IDEMPOTENT + deterministic over arbitrary text;
/// an embedded Windows profile path is redacted whole (the user-name and every backslash gone); an embedded
/// SID is redacted; and clean text (no path/SID) is returned byte-for-byte. Boundary examples pin the exact
/// output shapes (quoted / unquoted / UNC / device / SID / URL-not-a-path) and prove the placeholders are a
/// fixed point. See the fuzzing design notes.
/// </summary>
public class MessageScrubProperties
{
    // Text guaranteed to hold NO path/SID trigger: lowercase letters, digits, spaces only - no ':' (drive),
    // no '\' or '/' (UNC), no uppercase 'S'/'-' (SID). So it can only appear in Redact's output unchanged,
    // and it can never smuggle a copy of the injected path/SID markers we assert are gone.
    private static readonly Gen<string> CleanText =
        Gen.String.Select(s => new string(s.Where(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or ' ').ToArray()));

    // Like CleanText but with NO spaces - a single path segment (e.g. a user name) for an UNQUOTED path,
    // where the drive rule deliberately stops at the first whitespace (that spaced-and-unquoted case is a
    // documented residual, so the no-leak oracle must not feed it one).
    private static readonly Gen<string> Segment =
        Gen.String.Select(s => new string(s.Where(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9')).ToArray()));

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Total_idempotent_and_deterministic_over_arbitrary_text() =>
        Gen.String.Sample(s =>
        {
            // A throw would fail the property. once == again = deterministic; once == twice = idempotent.
            var once = MessageScrub.Redact(s);
            var twice = MessageScrub.Redact(once);
            var again = MessageScrub.Redact(s);
            return once == again && once == twice;
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void No_op_on_text_without_a_path_or_sid() =>
        CleanText.Sample(s => MessageScrub.Redact(s) == s, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Redacts_an_embedded_windows_profile_path() =>
        Gen.Select(Segment, CleanText, CleanText, (secret, pre, post) => (secret, pre, post)).Sample(t =>
        {
            // A profile path with no spaces (the dominant real shape) embedded in clean prose. pre/post carry
            // no backslash, so a backslash surviving the scrub could ONLY be an unredacted piece of the path.
            var path = @"C:\Users\" + (t.secret.Length == 0 ? "u" : t.secret) + @"\AppData\Local\app.json";
            var msg = t.pre + " " + path + " " + t.post;
            var red = MessageScrub.Redact(msg);
            return red is not null
                && red.Contains(MessageScrub.PathPlaceholder, StringComparison.Ordinal)
                && !red.Contains('\\')          // the whole path (and the user-name inside it) is gone
                && !red.Contains(":\\", StringComparison.Ordinal);
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Redacts_an_embedded_sid() =>
        Gen.Select(Gen.UInt, Gen.UInt, Gen.UInt, Gen.UInt, CleanText, (a, b, c, rid, pre) => (a, b, c, rid, pre)).Sample(t =>
        {
            var sid = $"S-1-5-21-{t.a}-{t.b}-{t.c}-{t.rid}";
            var msg = t.pre + " owner " + sid + " denied";
            var red = MessageScrub.Redact(msg);
            // CleanText can't contain "S-1-" (no uppercase S / '-'), so the marker is gone iff the SID was scrubbed.
            return red is not null
                && red.Contains(MessageScrub.SidPlaceholder, StringComparison.Ordinal)
                && !red.Contains(sid, StringComparison.Ordinal)
                && !red.Contains("S-1-", StringComparison.Ordinal);
        }, iter: Fuzz.Iter);

    [Theory]
    // Quoted drive path (the .NET IOException/UnauthorizedAccessException shape) - redacted whole.
    [InlineData(@"Access to the path 'C:\Users\user\AppData\Local\config.json' is denied.", "Access to the path <path> is denied.")]
    // Quoted path whose user name contains a space - still redacted whole (unquoted rules would stop at the space).
    [InlineData(@"could not open 'C:\Users\John Smith\AppData\x.toml' now", "could not open <path> now")]
    // Unquoted drive path, no spaces - redacted to the next whitespace.
    [InlineData(@"could not read C:\ProgramData\DnsCryptControl\proxy\dnscrypt-proxy.toml", "could not read <path>")]
    // Quoted UNC path.
    [InlineData(@"open '\\fileserver\share\secret\notes.txt' failed", "open <path> failed")]
    // Unquoted device path (\\?\...).
    [InlineData(@"device \\?\C:\Windows\System32\drivers here", "device <path> here")]
    // A full account SID.
    [InlineData("owner S-1-5-21-1004336348-1177238915-682003330-1001 lacks access", "owner <sid> lacks access")]
    // A well-known short SID (LocalSystem).
    [InlineData("the LocalSystem account S-1-5-18 was used", "the LocalSystem account <sid> was used")]
    // A lowercase SID (belt-and-suspenders: IgnoreCase) is redacted too.
    [InlineData("owner s-1-5-21-1004336348-1177238915-682003330-1001 denied", "owner <sid> denied")]
    // A URL is NOT a filesystem path - the scheme's "://" must not be mistaken for one.
    [InlineData("download from https://raw.githubusercontent.com/x/y/list.md failed", "download from https://raw.githubusercontent.com/x/y/list.md failed")]
    // Clean text is returned byte-for-byte.
    [InlineData("nothing sensitive here 12345", "nothing sensitive here 12345")]
    // Quoted device path with spaces and parens - redacted whole.
    [InlineData(@"load '\\?\C:\Program Files (x86)\App\x.dll' error", "load <path> error")]
    public void Boundary_examples(string input, string expected)
    {
        Assert.Equal(expected, MessageScrub.Redact(input));
        // The output is a fixed point: redacting an already-scrubbed message changes nothing.
        Assert.Equal(expected, MessageScrub.Redact(expected));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Null_or_empty_passes_through(string? input) =>
        Assert.Equal(input, MessageScrub.Redact(input));
}
