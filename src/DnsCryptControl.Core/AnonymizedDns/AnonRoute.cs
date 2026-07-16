namespace DnsCryptControl.Core.AnonymizedDns;

/// <summary>
/// One anonymized-DNS route: a server (or the wildcard <c>*</c>) reached via one or more
/// relays (relay names, the wildcard <c>*</c>, or <c>sdns://</c> relay stamps).
/// </summary>
public readonly record struct AnonRoute(string ServerName, IReadOnlyList<string> Via);
