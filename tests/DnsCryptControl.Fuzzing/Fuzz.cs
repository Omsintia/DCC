namespace DnsCryptControl.Fuzzing;

/// <summary>
/// Shared fuzzing-harness configuration. The iteration budget defaults to a fast PR-grade pass
/// (so the properties run inside the normal <c>dotnet test</c> without noticeably slowing it) and
/// scales up for the nightly deep pass via the <c>FUZZ_ITER</c> environment variable. Every CsCheck
/// <c>Sample</c> call passes <c>iter: Fuzz.Iter</c> so one knob drives the whole harness.
/// </summary>
internal static class Fuzz
{
    /// <summary>Per-property iteration count. <c>FUZZ_ITER=deep</c> -> 1,000,000; <c>FUZZ_ITER=&lt;n&gt;</c> -> n
    /// (positive int); unset/other -> 10,000.</summary>
    public static int Iter { get; } = Environment.GetEnvironmentVariable("FUZZ_ITER") switch
    {
        "deep" => 1_000_000,
        { } s when int.TryParse(s, out var n) && n > 0 => n,
        _ => 10_000,
    };
}
