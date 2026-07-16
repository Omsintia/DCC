namespace DnsCryptControl.Platform;

/// <summary>Lifecycle state of the <c>dnscrypt-proxy</c> Windows service.</summary>
public enum ProxyServiceState { NotInstalled, Stopped, StartPending, Running, StopPending, Unknown }
