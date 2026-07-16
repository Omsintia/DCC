using System;
using System.IO;
using System.Security;
using Microsoft.Win32;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Projects <see cref="Models.UiState.StartWithWindows"/> onto the per-user HKCU Run key so the
/// signed UI launches at logon. <see cref="Models.UiState"/> is the single source of INTENT — this
/// is a write-through projection (the Settings checkbox never reads the registry directly, so the
/// two cannot drift). User-scope only (no elevation); the app merely opening never changes DNS.
/// All hive access is fail-closed to the specific expected exceptions (mirroring
/// <see cref="UiStateStore"/>), so a locked/denied/deleted key can never crash the UI.
/// </summary>
public sealed class StartupRegistration : IStartupRegistration
{
    /// <summary>The Run value name (one entry per app).</summary>
    public const string ValueName = "DnsCryptControl";

    private readonly IRunKeyAccess _runKey;
    private readonly string _exePath;

    /// <param name="runKey">The HKCU Run-key seam (production: <see cref="HkcuRunKeyAccess"/>; tests: a fake).</param>
    /// <param name="exePath">The exe to register; defaults to the current process image.</param>
    public StartupRegistration(IRunKeyAccess runKey, string? exePath = null)
    {
        _runKey = runKey ?? throw new ArgumentNullException(nameof(runKey));
        _exePath = exePath ?? Environment.ProcessPath ?? string.Empty;
    }

    /// <summary>The command written under the Run key: the quoted exe path, asInvoker, no args.</summary>
    private string Command => "\"" + _exePath + "\"";

    public bool IsRegistered()
    {
        try
        {
            return _runKey.GetValue(ValueName) is not null;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
        catch (SecurityException) { return false; }
    }

    public bool Register()
    {
        try
        {
            _runKey.SetValue(ValueName, Command);
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
        catch (SecurityException) { return false; }
    }

    public bool Unregister()
    {
        try
        {
            _runKey.DeleteValue(ValueName);
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
        catch (SecurityException) { return false; }
    }
}

/// <summary>
/// Production HKCU Run-key access (<c>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</c>).
/// The registry is Windows-only; the UI project targets <c>net8.0-windows</c> so this is in-platform.
/// </summary>
public sealed class HkcuRunKeyAccess : IRunKeyAccess
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

    public string? GetValue(string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath);
        return key?.GetValue(name) as string;
    }

    public void SetValue(string name, string value)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKeyPath);
        key.SetValue(name, value, RegistryValueKind.String);
    }

    public void DeleteValue(string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
        key?.DeleteValue(name, throwOnMissingValue: false);
    }
}
