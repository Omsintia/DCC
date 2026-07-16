using System;
using System.IO;
using System.Linq;
using System.Text;
using CsCheck;
using DnsCryptControl.Core.Toml;
using DnsCryptControl.Core.Validation;
using DnsCryptControl.Service;
using DnsCryptControl.Service.Windows;

namespace DnsCryptControl.Fuzzing.Oracles;

/// <summary>
/// TWO-PATH cross-check (Phase 6b): the Service kill-switch enable gate
/// (<see cref="TomlProxyConfigSafetyCheck.IsSafeUnderPort53Block"/>, which reads the on-disk config and
/// decides whether arming the port-53 block is safe) must NEVER disagree with the Core rule engine
/// (<see cref="OpsecConfigRules.Evaluate"/>) on whether a config is kill-switch-safe. By design (IC-4) the
/// Service path delegates to Core and returns unsafe on the first <see cref="OpsecConcernSeverity.KillSwitchCritical"/>
/// concern, so they can only diverge if a future refactor gives the Service path its own logic, mis-reduces
/// the concern list, or reads different bytes than Core. This property proves agreement over structured
/// configs that span the KillSwitchCritical rule space AND raw-garbage totality inputs. A divergence would
/// mean the kill switch could arm over a config Core considers unsafe (a leak) or refuse a config Core
/// considers safe (a brick) - either way a real OPSEC bug. See the fuzzing design notes.
/// </summary>
public sealed class TwoPathSafetyOracleTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "DnsCryptFuzzTwoPath_" + Guid.NewGuid().ToString("N"));
    private readonly ProtectedPaths _paths;
    private readonly TomlProxyConfigSafetyCheck _service;
    // CsCheck evaluates the property on multiple threads; the two paths share one on-disk config file, so
    // serialize each write->read->evaluate so threads never contend on the same file (an IO race, not a bug).
    private readonly object _fileLock = new();

    public TwoPathSafetyOracleTests()
    {
        Directory.CreateDirectory(_dir);
        _paths = new ProtectedPaths(_dir);
        _service = new TomlProxyConfigSafetyCheck(_paths);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    // Structured configs spanning the three KillSwitchCritical rules (netprobe_timeout==0,
    // ignore_system_dns==true, no remote :53 bootstrap) so both safe and unsafe verdicts are exercised.
    private static readonly Gen<string> ConfigGen = Gen.Select(
        Gen.Int[0, 2],   // netprobe_timeout: 0=safe(0), 1=nonzero, 2=absent
        Gen.Int[0, 2],   // ignore_system_dns: 0=true, 1=false, 2=absent
        Gen.Int[0, 4],   // bootstrap: 0=absent, 1=loopback:53, 2=remote:53, 3=remote:443, 4=malformed(type)
        (nt, isd, bs) => BuildConfig(nt, isd, bs));

    private static string BuildConfig(int nt, int isd, int bs)
    {
        var sb = new StringBuilder();
        sb.Append(nt switch { 0 => "netprobe_timeout = 0\n", 1 => "netprobe_timeout = 60\n", _ => "" });
        sb.Append(isd switch { 0 => "ignore_system_dns = true\n", 1 => "ignore_system_dns = false\n", _ => "" });
        sb.Append(bs switch
        {
            0 => "",
            1 => "bootstrap_resolvers = ['127.0.0.1:53']\n",
            2 => "bootstrap_resolvers = ['9.9.9.9:53']\n",
            3 => "bootstrap_resolvers = ['9.9.9.9:443']\n",
            _ => "bootstrap_resolvers = 12345\n", // wrong type -> fail closed
        });
        return sb.ToString();
    }

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Service_gate_agrees_with_core_evaluate_on_kill_switch_safety() =>
        Gen.OneOf(ConfigGen, Gen.String).Sample(text =>
        {
            lock (_fileLock)
            {
                File.WriteAllText(_paths.ConfigFile, text);
                // Parse EXACTLY what the Service path reads off disk, so a file-encoding artifact (BOM strip,
                // surrogate replacement) can never masquerade as a logic divergence.
                var doc = TomlConfigDocument.Parse(File.ReadAllText(_paths.ConfigFile));
                var coreSafe = !doc.HasErrors
                    && !OpsecConfigRules.Evaluate(doc).Any(c => c.Severity == OpsecConcernSeverity.KillSwitchCritical);

                var serviceSafe = _service.IsSafeUnderPort53Block().Safe;
                return serviceSafe == coreSafe;
            }
        }, iter: Math.Min(Fuzz.Iter, 3000)); // file I/O per iteration; a wrapper-consistency guard, not a deep fuzz
}
