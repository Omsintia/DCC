using System;
using System.Collections.Generic;
using System.IO;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>A: <see cref="StartupRegistration"/> — HKCU Run-key projection of UiState.StartWithWindows, fail-closed.</summary>
public sealed class StartupRegistrationTests
{
    /// <summary>Dictionary-backed Run-key seam; can be scripted to throw on read/write to prove fail-closed.</summary>
    private sealed class FakeRunKey : IRunKeyAccess
    {
        private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);

        public bool ThrowOnWrite { get; set; }
        public bool ThrowOnRead { get; set; }

        public string? GetValue(string name)
        {
            if (ThrowOnRead) throw new UnauthorizedAccessException();
            return _values.TryGetValue(name, out var v) ? v : null;
        }

        public void SetValue(string name, string value)
        {
            if (ThrowOnWrite) throw new UnauthorizedAccessException();
            _values[name] = value;
        }

        public void DeleteValue(string name)
        {
            if (ThrowOnWrite) throw new IOException();
            _values.Remove(name);
        }

        public string? Peek(string name) => _values.TryGetValue(name, out var v) ? v : null;
    }

    [Fact]
    public void Register_thenIsRegistered_isTrue_andStoresQuotedExePath()
    {
        var fake = new FakeRunKey();
        var reg = new StartupRegistration(fake, exePath: @"C:\Apps\DnsCryptControl.exe");

        Assert.True(reg.Register()); // reports the accepted write

        Assert.True(reg.IsRegistered());
        Assert.Equal("\"C:\\Apps\\DnsCryptControl.exe\"", fake.Peek(StartupRegistration.ValueName));
    }

    [Fact]
    public void Unregister_removesEntry()
    {
        var fake = new FakeRunKey();
        var reg = new StartupRegistration(fake, exePath: @"C:\Apps\DnsCryptControl.exe");
        reg.Register();

        reg.Unregister();

        Assert.False(reg.IsRegistered());
    }

    [Fact]
    public void Register_accessDenied_isSwallowed_andStaysUnregistered()
    {
        var fake = new FakeRunKey { ThrowOnWrite = true };
        var reg = new StartupRegistration(fake, exePath: @"C:\Apps\DnsCryptControl.exe");

        var ok = reg.Register(); // must not throw

        Assert.False(ok);                 // reports the rejected write (so the caller won't persist the intent)
        Assert.False(reg.IsRegistered());
    }

    [Fact]
    public void IsRegistered_readFault_returnsFalse()
    {
        var fake = new FakeRunKey { ThrowOnRead = true };
        var reg = new StartupRegistration(fake, exePath: @"C:\Apps\DnsCryptControl.exe");

        Assert.False(reg.IsRegistered());
    }
}
