using CsCheck;
using DnsCryptControl.Core.Security;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz + regression properties for <see cref="LogFilePathGuard.ConfineToBase"/> - the fix for the
/// unprivileged-UI ARBITRARY-FILE-READ finding (2026-07-08): the config <c>log_file</c> the Logs and
/// Diagnostics tab tails must be confined to the proxy's ProgramData dir, so a crafted value (UNC, a
/// <c>\\.\</c> device, an NTFS alternate data stream, a traversal, or a sensitive local file) can never be
/// opened and dumped on screen. Security oracle: the guard NEVER returns a path outside the base, and NEVER
/// throws. See the fuzzing design notes.
/// </summary>
public class LogFilePathGuardProperties
{
    private const string Base = @"C:\base";

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ConfineToBase_never_escapes_and_never_throws() =>
        HostilePathGen.Sample(logFile =>
        {
            // The whole security property: either the guard refuses (null), or it returns a real path that
            // is CONFINED to the base. A throw (not caught inside the guard) also fails the property.
            var result = LogFilePathGuard.ConfineToBase(logFile, Base);
            return result is null || SafePath.IsWithinBase(Base, result);
        }, iter: Fuzz.Iter);

    [Theory]
    [InlineData(@"\\attacker\share\x.log")]              // UNC
    [InlineData(@"\\.\PhysicalDrive0")]                  // device namespace
    [InlineData(@"\\.\COM1")]                            // device
    [InlineData(@"\\?\C:\Windows\System32\config\SAM")]  // extended-length device path
    [InlineData(@"C:\Windows\System32\config\SAM")]      // sensitive absolute, outside base
    [InlineData(@"..\..\Windows\System32\config\SAM")]   // traversal out of base
    [InlineData(@"C:\base\query.log:stream")]            // NTFS alternate data stream on an in-base file
    [InlineData("query.log:stream")]                     // relative ADS
    [InlineData("")]                                     // empty
    public void ConfineToBase_refuses_hostile_paths(string logFile) =>
        Assert.Null(LogFilePathGuard.ConfineToBase(logFile, Base));

    [Theory]
    [InlineData("dnscrypt-proxy.log")]                   // relative -> resolves under the base (proxy cwd)
    [InlineData(@"C:\base\dnscrypt-proxy.log")]          // absolute, inside the base (what the app writes)
    [InlineData(@"C:\base\sub\dnscrypt-proxy.log")]      // absolute, nested inside the base
    public void ConfineToBase_allows_in_base_paths(string logFile)
    {
        var result = LogFilePathGuard.ConfineToBase(logFile, Base);
        Assert.NotNull(result);
        Assert.True(SafePath.IsWithinBase(Base, result!));
    }

    /// <summary>Curated hostile path shapes (UNC / device / extended / ADS / traversal / absolute-outside /
    /// reserved) plus a couple of in-base names, so the confinement is fuzzed across the real attack shapes
    /// and their concatenations rather than only random noise.</summary>
    private static readonly string[] HostileConsts =
    {
        @"\\attacker\share\x", @"\\.\PhysicalDrive0", @"\\.\COM1", @"\\?\C:\x",
        @"C:\Windows\System32\config\SAM", @"..\..\etc\passwd", @"C:\base\x:ads", "x:ads",
        @"C:\base\ok.log", "ok.log", @"sub\ok.log", "CON", @"C:\base\a..b.log",
    };

    private static readonly Gen<string> PickHostile =
        Gen.Int[0, HostileConsts.Length - 1].Select(i => HostileConsts[i]);

    /// <summary>Hostile shapes, random text, and their concatenations - so a partially-sanitised path
    /// (e.g. an attack shape glued to random noise) is exercised, not just the clean curated cases.</summary>
    private static readonly Gen<string> HostilePathGen = Gen.OneOf(
        PickHostile,
        Gen.String,
        Gen.Select(PickHostile, Gen.String, (a, b) => a + b),
        Gen.Select(Gen.String, PickHostile, (a, b) => a + b));
}
