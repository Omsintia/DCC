using System.Collections.Generic;

namespace DnsCryptControl.UI.Models;

/// <summary>
/// Per-user, non-roaming UI preferences (favorites, stashed anonymized-DNS routes, sort choice).
/// Persisted to <c>%LOCALAPPDATA%\DnsCryptControl\ui-state.json</c>. NOT trust-bearing — it holds
/// no security state and no secrets, and NEVER latency results (those describe a probing event and
/// stay in memory only). Mutable POCO for source-gen JSON round-tripping.
/// </summary>
public sealed class UiState
{
    /// <summary>Prefixed resolver names the user starred.</summary>
    public List<string> Favorites { get; set; } = new();

    /// <summary>The last anonymized-DNS routes stashed when the AnonDNS toggle was turned off (for re-enable).</summary>
    public List<UiStashedRoute> StashedRoutes { get; set; } = new();

    /// <summary>The Resolvers-list sort preference (opaque key; null = default).</summary>
    public string? ResolverSort { get; set; }

    /// <summary>Theme preference: "Light", "Dark", or null/"System" to follow the OS (Phase 5f).</summary>
    public string? Theme { get; set; }

    /// <summary>Launch DnsCrypt Control at user logon — projected onto the HKCU Run key (Phase 5f).</summary>
    public bool StartWithWindows { get; set; }

    /// <summary>Start hidden to the notification-area tray instead of showing the window (Phase 5f).</summary>
    public bool StartMinimized { get; set; }

    /// <summary>Closing the window hides to the tray (status polling continues) instead of exiting (Phase 5f).</summary>
    public bool MinimizeToTrayOnClose { get; set; }

    /// <summary>Kill-switch opt-in: when protection is enabled, also arm the fail-closed firewall kill
    /// switch. Defaults to <c>true</c> (the recommended secure default) so a fresh install is fail-closed
    /// on the very first Protect; the user's explicit toggle is persisted here and wins on later launches.
    /// A file written by an older build without this field deserializes to the <c>true</c> default.</summary>
    public bool KillSwitchOptIn { get; set; } = true;

    /// <summary>Query Monitor column widths (px), adjusted by dragging the header dividers. Cosmetic
    /// only; the VM clamps on load so a hand-edited file can never push a column off-screen.</summary>
    public UiQueryMonitorColumns QueryMonitorColumns { get; set; } = new();
}

/// <summary>Pixel widths for the Query Monitor's six fixed columns (the Name column is star-sized
/// and absorbs the remainder). Defaults match the shipped layout; Server is wide enough for the
/// long public resolver names (e.g. <c>quad9-dnscrypt-ip4-filter-pri</c>) out of the box. A file
/// written by a pre-App build deserializes App to its default (the VM clamps on load anyway).</summary>
public sealed class UiQueryMonitorColumns
{
    public double Time { get; set; } = 150;

    public double Type { get; set; } = 52;

    public double Action { get; set; } = 82;

    public double Latency { get; set; } = 64;

    public double Server { get; set; } = 220;

    /// <summary>The originating-app column (v1.3.0 per-app attribution), between Server and Name.</summary>
    public double App { get; set; } = 110;
}

/// <summary>A serializable anonymized-DNS route (mirrors <c>Core.AnonymizedDns.AnonRoute</c>).</summary>
public sealed class UiStashedRoute
{
    public string ServerName { get; set; } = "";

    public List<string> Via { get; set; } = new();
}
