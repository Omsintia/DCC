using System;
using System.IO;
using CsCheck;
using DnsCryptControl.Core.Security;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz properties for the path-confinement primitive <see cref="SafePath"/> - the anti zip-slip /
/// anti path-traversal (CWE-22) guard used by zip extraction and installer staging. Untrusted entry
/// names arrive from downloaded/unpacked archives; a single missed traversal shape (..\, ../, rooted
/// C:\, /x, UNC \\host\share, device \\.\COM1, extended \\?\, ADS file:stream, embedded NUL, or a
/// backslash/slash mix) would let an attacker write outside the staging directory.
///
/// Three invariants are asserted. (1) CONFINEMENT ROUND-TRIP: whenever <see cref="SafePath.ResolveWithinBase"/>
/// RETURNS a path, that path must satisfy <see cref="SafePath.IsWithinBase"/> - it is provably inside the
/// base. (2) SINGLE-THROW-TYPE / FAIL-CLOSED: the ONLY exception ResolveWithinBase may throw is
/// <see cref="ArgumentException"/> (its documented contract); any other escaping exception is a totality
/// bug, and every curated escape shape must be REJECTED (thrown), never resolved. (3) IsWithinBase never
/// FAILS OPEN: it either throws only ArgumentException or returns a bool, and a returned <c>true</c> is
/// cross-checked against a ground-truth ordinal-prefix oracle so a genuinely-escaping candidate can never
/// be reported as confined. See the fuzzing design notes.
/// </summary>
public class SafePathProperties
{
    // A fixed, trusted staging base (mirrors ProgramData\DnsCryptControl\staging). Ordinal-only logic,
    // so the concrete drive letter is irrelevant to what is being proven.
    private const string BaseDir = @"C:\ProgramData\DnsCryptControl\staging";

    // Curated hostile PREFIXES/segments, one per traversal family. Each is prepended to (or mixed with)
    // a random segment so the fuzzer explores the guard with attacker-controlled tails as well.
    private static readonly string[] HostilePrefixes =
    {
        "..\\", "../", "..\\..\\", "../../", "sub\\..\\..\\", "sub/../../",
        "C:\\", "C:/", "\\", "/", "D:\\Windows\\",              // rooted / absolute
        "\\\\host\\share\\", "//host/share/",                     // UNC
        "\\\\.\\", "\\\\?\\", "\\\\?\\C:\\",                       // device / extended-length
        "CON\\", "NUL\\", "AUX\\", "PRN\\", "COM1\\", "LPT1\\",    // reserved device as a component
        "sub\\CON\\", "sub/nul/",                                  // reserved device mid-path
    };

    // Curated hostile SUFFIXES/whole-names that must also fail closed (ADS, NUL, device-with-extension).
    private static readonly string[] HostileNames =
    {
        "CON", "con", "NUL", "aux", "PRN", "COM1", "LPT9",
        "CON.txt", "NUL.log", "CON ", " CON", "aux.h.c",
        "name:stream", "file.txt:$DATA", "a:b",                   // ADS / stream / drive-ish colon
        "..", "....", "a..b", "a\\..", "..\\",
        "sub\\..\\..\\escape.dll",
        "name\0stream", "\0", "pre\0..\\post",                    // embedded NUL
        ".", "a\\.\\b", "a\\\\b",                                 // legal-ish (single dot / empty comp)
        "normal.txt", "sub/normal.txt", "a b c",                  // benign, must RESOLVE and confine
    };

    // Benign, guaranteed-legal relative names: no traversal, colon, rooting, UNC, device, or NUL. These
    // must ALWAYS resolve (never throw) and always confine - the "must not over-reject" side of the guard.
    private static readonly string[] BenignNames =
    {
        "file.txt", "sub\\file.txt", "sub/file.txt", "a\\b\\c\\d.bin",
        "COM0", "COM10", "CONx", "LPT0", "config.toml", "x", "under_score-1.2.3",
    };

    /// <summary>Random-tailed hostile name: a curated escape prefix concatenated with an arbitrary
    /// string segment, OR a curated whole hostile name, OR a purely random string (which is itself a
    /// valid untrusted input the guard must survive). Covers every documented traversal family plus
    /// attacker-controlled noise on the tail.</summary>
    private static readonly Gen<string> HostilePathGen =
        Gen.OneOf(
            Gen.Select(Gen.Int[0, HostilePrefixes.Length - 1], Gen.String,
                (i, tail) => HostilePrefixes[i] + tail),
            Gen.Int[0, HostileNames.Length - 1].Select(i => HostileNames[i]),
            Gen.Int[0, BenignNames.Length - 1].Select(i => BenignNames[i]),
            Gen.String);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ResolveWithinBase_only_throws_ArgumentException_and_confines_what_it_returns() =>
        HostilePathGen.Sample(ResolveTotalityAndConfinement, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void IsWithinBase_never_fails_open_on_arbitrary_candidates() =>
        // The candidate here is an arbitrary (possibly absolute/hostile) full-ish path, exercising the
        // standalone confinement check callers use directly (not only via ResolveWithinBase).
        Gen.OneOf(Gen.String, HostilePathGen.Select(n => BaseDir + "\\" + n))
            .Sample(IsWithinBaseNeverFailsOpen, iter: Fuzz.Iter);

    /// <summary>Oracle for invariant (1)+(2). ResolveWithinBase either:
    /// - throws ArgumentException (the ONLY permitted type; the empty/whitespace-arg and every escape
    ///   shape land here) - a valid, expected fail-closed outcome; or
    /// - returns a non-null path that IsWithinBase confirms is inside the base.
    /// Any OTHER exception type propagates out of Sample and fails the property (totality breach); a
    /// returned path that is NOT within base makes this predicate return false (confinement breach).
    /// ArgumentException is caught NARROWLY (not general Exception) precisely so an unexpected type is
    /// NOT swallowed and the property surfaces it.</summary>
    private static bool ResolveTotalityAndConfinement(string name)
    {
        string resolved;
        try
        {
            resolved = SafePath.ResolveWithinBase(BaseDir, name);
        }
        catch (ArgumentException)
        {
            return true; // documented, expected rejection
        }

        // It RETURNED a path: it must be non-null and provably confined. IsWithinBase is invoked on the
        // guard's own trusted output, which is a canonical full path and therefore total here.
        return resolved is not null && SafePath.IsWithinBase(BaseDir, resolved);
    }

    /// <summary>Oracle for invariant (3). IsWithinBase must never FAIL OPEN: if it returns <c>true</c>,
    /// an independent ground-truth ordinal-prefix check must agree the candidate really is under the base.
    /// It is total only up to ArgumentException (Path.GetFullPath rejects embedded NUL etc.), which is the
    /// documented behaviour, so that single type is treated as an acceptable outcome and any other type
    /// escapes to fail the property.</summary>
    private static bool IsWithinBaseNeverFailsOpen(string candidate)
    {
        if (string.IsNullOrEmpty(candidate))
            return true; // ThrowIfNullOrEmpty guards this; nothing to assert

        bool within;
        try
        {
            within = SafePath.IsWithinBase(BaseDir, candidate);
        }
        catch (ArgumentException)
        {
            return true; // documented total-up-to-ArgumentException behaviour
        }

        if (!within)
            return true; // a false is always safe (fail-closed direction)

        // Claimed WITHIN: verify against an independent oracle so a fail-open can never hide here.
        return IsTrulyInside(candidate);
    }

    /// <summary>Ground-truth confinement oracle, computed independently of SafePath: canonicalize both
    /// paths and require an ordinal prefix (base + separator) or exact equality. Guarded so this helper
    /// itself never throws for a candidate SafePath already accepted.</summary>
    private static bool IsTrulyInside(string candidate)
    {
        string fullBase;
        string fullCandidate;
        try
        {
            fullBase = Path.GetFullPath(BaseDir);
            fullCandidate = Path.GetFullPath(candidate);
        }
        catch (ArgumentException)
        {
            // If SafePath said "within" but canonicalization now throws, that is itself a contradiction;
            // surface it as a failure rather than masking it.
            return false;
        }

        var withSep = fullBase.EndsWith(Path.DirectorySeparatorChar)
            ? fullBase
            : fullBase + Path.DirectorySeparatorChar;
        return fullCandidate.StartsWith(withSep, StringComparison.OrdinalIgnoreCase)
            || string.Equals(fullCandidate, fullBase, StringComparison.OrdinalIgnoreCase);
    }

    // --- Concrete regression anchors (each maps to a specific traversal family). ---

    [Theory]
    [InlineData("..\\..\\Windows\\System32\\evil.dll")] // classic back-traversal
    [InlineData("../secrets.txt")]                       // forward-slash traversal
    [InlineData("sub\\..\\..\\escape.txt")]              // mid-path traversal
    [InlineData("C:\\Windows\\System32\\drivers\\etc\\hosts")] // rooted absolute
    [InlineData("/etc/passwd")]                          // rooted forward
    [InlineData("\\\\server\\share\\file")]              // UNC backslash
    [InlineData("//server/share/file")]                  // UNC forward
    [InlineData("\\\\.\\COM1")]                           // device namespace
    [InlineData("\\\\?\\C:\\Windows")]                    // extended-length namespace
    [InlineData("name:stream")]                          // ADS / drive specifier
    [InlineData("file.txt:$DATA")]                       // ADS $DATA stream
    [InlineData("CON")]                                  // reserved device
    [InlineData("NUL")]
    [InlineData("LPT1")]
    [InlineData("CON.txt")]                              // device with extension
    [InlineData("sub\\CON\\x.txt")]                      // device mid-path
    [InlineData("name\0stream")]                         // embedded NUL
    public void ResolveWithinBase_rejects_every_escape_shape(string hostile) =>
        Assert.Throws<ArgumentException>(() => SafePath.ResolveWithinBase(BaseDir, hostile));

    [Theory]
    [InlineData("dnscrypt-proxy.toml")]
    [InlineData("sub\\file.txt")]
    [InlineData("sub/file.txt")]
    [InlineData("COM0")]   // NOT a reserved device (only COM1-9)
    [InlineData("CONx")]   // not an exact device-name match
    public void ResolveWithinBase_confines_benign_names(string benign)
    {
        var resolved = SafePath.ResolveWithinBase(BaseDir, benign);
        Assert.True(SafePath.IsWithinBase(BaseDir, resolved));
    }
}
