using System.Collections.Generic;

namespace DnsCryptControl.Service.Windows;

/// <summary>Publisher allow-list of Authenticode certificate thumbprints. A client is only
/// trusted if WinVerifyTrust validates its image AND the signer's thumbprint is on this
/// list. Pure/unit-testable.</summary>
public sealed class SignerAllowList
{
    private readonly HashSet<string> _thumbprints;

    public SignerAllowList(IReadOnlyCollection<string> allowedThumbprints)
    {
        ArgumentNullException.ThrowIfNull(allowedThumbprints);
        _thumbprints = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        foreach (var t in allowedThumbprints)
            if (!string.IsNullOrWhiteSpace(t)) _thumbprints.Add(t.Trim());
    }

    public bool IsAllowed(string? thumbprint) =>
        !string.IsNullOrWhiteSpace(thumbprint) && _thumbprints.Contains(thumbprint.Trim());
}
