namespace DnsCryptControl.Platform;

/// <summary>Flushes the Windows DNS resolver cache (CIM MSFT_DNSClientCache.Clear; ipconfig fallback).</summary>
public interface IDnsCacheFlusher
{
    PlatformResult Flush();
}
