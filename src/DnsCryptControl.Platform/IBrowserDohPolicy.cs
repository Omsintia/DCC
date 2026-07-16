namespace DnsCryptControl.Platform;
/// <summary>Writes/clears the Chrome/Edge/Firefox enterprise policies that force browser-internal DoH
/// off (opt-in). Captures prior values; revert restores prior or deletes only values it created.</summary>
public interface IBrowserDohPolicy
{
    PlatformResult SetBrowserDohPolicy(bool enable);
    bool IsBrowserDohPolicyApplied();
}
