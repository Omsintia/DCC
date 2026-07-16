using System.Collections.Generic;
using Microsoft.Win32;

namespace DnsCryptControl.Service.Windows.Registry;

/// <summary>Narrow subkey-oriented seam over the HKLM 64-bit registry view. Abstracted so the
/// capture/write/revert/exact-kind logic in RegistryLeakMitigationPolicy, BrowserDohPolicy, and
/// WindowsDiagnosticsProbe is unit-testable against an in-memory fake; the real adapter
/// (Registry64Root) is exercised only by ManualIntegration tests.</summary>
internal interface IRegistryRoot   // always the HKLM 64-bit view
{
    /// <summary>Open an existing subkey. Returns null if the key is absent.</summary>
    IRegistrySubKey? OpenSubKey(string path, bool writable);

    /// <summary>Create-or-open the subkey writable (idempotent).</summary>
    IRegistrySubKey CreateSubKey(string path);

    /// <summary>Delete the subkey tree. If <paramref name="throwIfMissing"/> is false, silently
    /// no-ops when the key does not exist.</summary>
    void DeleteSubKeyTree(string path, bool throwIfMissing);
}

/// <summary>Wraps an open registry subkey. Dispose releases the handle.</summary>
internal interface IRegistrySubKey : System.IDisposable
{
    /// <summary>Returns the raw value, or null if the value is absent.</summary>
    object? GetValue(string name);

    /// <summary>Returns the kind of a value that is known to exist.</summary>
    RegistryValueKind GetValueKind(string name);

    /// <summary>Write (create or overwrite) a value with an explicit kind.</summary>
    void SetValue(string name, object data, RegistryValueKind kind);

    /// <summary>Delete a value. If <paramref name="throwIfMissing"/> is false, silently
    /// no-ops when the value does not exist.</summary>
    void DeleteValue(string name, bool throwIfMissing);

    /// <summary>Enumerate value names in this subkey.</summary>
    IReadOnlyList<string> GetValueNames();

    /// <summary>Enumerate direct child subkey names.</summary>
    IReadOnlyList<string> GetSubKeyNames();
}
