using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace DnsCryptControl.Service.Windows.Registry;

/// <summary>Real HKLM 64-bit-view registry root. Both target keys are non-redirected, but
/// Registry64 is passed explicitly to be view-deterministic even if launched as x86. Runs as
/// SYSTEM in production; ManualIntegration tests require elevation.</summary>
[SupportedOSPlatform("windows")]
internal sealed class Registry64Root : IRegistryRoot
{
    public IRegistrySubKey? OpenSubKey(string path, bool writable)
    {
        var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        var sub = baseKey.OpenSubKey(path, writable);
        if (sub is null) { baseKey.Dispose(); return null; }
        return new RealSubKey(sub, ownedBase: baseKey);
    }

    public IRegistrySubKey CreateSubKey(string path)
    {
        var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        var sub = baseKey.CreateSubKey(path, writable: true)
            ?? throw new InvalidOperationException($"CreateSubKey returned null for path: {path}");
        return new RealSubKey(sub, ownedBase: baseKey);
    }

    public void DeleteSubKeyTree(string path, bool throwIfMissing)
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        if (!throwIfMissing && baseKey.OpenSubKey(path) is null)
            return;
        baseKey.DeleteSubKeyTree(path, throwOnMissingSubKey: throwIfMissing);
    }

    // -----------------------------------------------------------------------

    private sealed class RealSubKey : IRegistrySubKey
    {
        private readonly RegistryKey? _base;   // owned base key, disposed with this subkey
        private readonly RegistryKey _key;

        public RealSubKey(RegistryKey key, RegistryKey? ownedBase = null)
        {
            _key = key;
            _base = ownedBase;
        }

        public object? GetValue(string name) => _key.GetValue(name, defaultValue: null);

        public RegistryValueKind GetValueKind(string name) => _key.GetValueKind(name);

        public void SetValue(string name, object data, RegistryValueKind kind) =>
            _key.SetValue(name, data, kind);

        public void DeleteValue(string name, bool throwIfMissing) =>
            _key.DeleteValue(name, throwIfMissing);

        public IReadOnlyList<string> GetValueNames() => _key.GetValueNames();

        public IReadOnlyList<string> GetSubKeyNames() => _key.GetSubKeyNames();

        public void Dispose() { _key.Dispose(); _base?.Dispose(); }
    }
}
