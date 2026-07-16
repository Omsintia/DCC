namespace DnsCryptControl.UI.Services;

/// <summary>
/// Builds status-tinted tray <see cref="System.Drawing.Icon"/>s for the notification area (Phase 5f) by
/// recolouring the application's own DCC shield icon: green when protection is verified, amber on a
/// leak/partial state, neutral grey otherwise. Reusing the real app-icon art (gradient, bevel, the "DCC"
/// mark) keeps the brand identity while the hue conveys status. Rendering is GDI+ and fail-safe: any
/// error yields <c>null</c> so the caller keeps the unmodified branded icon rather than crashing.
/// Windows-only (the whole UI project targets net8.0-windows), and each produced icon OWNS its own
/// unmanaged memory, so the caller can <c>Dispose</c> it without leaking the transient HICON.
/// </summary>
public static class TrayIconFactory
{
    /// <summary>Which protection state the tray glyph should convey.</summary>
    public enum TrayStatus
    {
        /// <summary>Protection verified — green.</summary>
        Protected,

        /// <summary>Leak / partial protection — amber.</summary>
        Warning,

        /// <summary>Not protected / indeterminate — grey.</summary>
        Neutral,
    }

    /// <summary>
    /// Recolour the application's DCC shield icon to convey <paramref name="status"/> (green / amber /
    /// grey), keeping the shield art and the "DCC" mark. Returns <c>null</c> on any GDI failure so
    /// startup never crashes (the caller then keeps the unmodified branded icon).
    /// </summary>
    /// <param name="status">The protection state the tint should signal.</param>
    public static System.Drawing.Icon? ForStatus(TrayStatus status)
    {
        try
        {
            // Source art = the app's OWN icon (the DCC shield embedded in this exe), so the tray reuses
            // the real branding instead of a hand-drawn approximation.
            var path = System.Environment.ProcessPath;
            if (string.IsNullOrEmpty(path)) { return null; }

            using var source = System.Drawing.Icon.ExtractAssociatedIcon(path);
            if (source is null) { return null; }
            using var src = source.ToBitmap();

            using var tinted = new System.Drawing.Bitmap(
                src.Width, src.Height, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
            using (var g = System.Drawing.Graphics.FromImage(tinted))
            using (var attrs = new System.Drawing.Imaging.ImageAttributes())
            {
                g.Clear(System.Drawing.Color.Transparent);
                attrs.SetColorMatrix(MatrixFor(status));
                var rect = new System.Drawing.Rectangle(0, 0, src.Width, src.Height);
                g.DrawImage(
                    src, rect, 0, 0, src.Width, src.Height, System.Drawing.GraphicsUnit.Pixel, attrs);
            }

            // Convert to a MANAGED, owns-its-own-memory icon: FromHandle does NOT own the HICON, so clone
            // it (the clone allocates its own copy), dispose the non-owning wrapper, then free the
            // transient HICON. The returned clone is safe to Dispose later without leaking.
            var h = tinted.GetHicon();
            using var tmp = System.Drawing.Icon.FromHandle(h);
            var icon = (System.Drawing.Icon)tmp.Clone();
            DestroyIcon(h);
            return icon;
        }
        catch (System.Exception)
        {
            // Fail-safe (CA1031): GDI can throw on exotic display / handle-exhaustion states, and
            // ExtractAssociatedIcon can throw on an unusual host process path. The tray must never take
            // down startup, so any failure yields null and the caller keeps the unmodified branded icon.
            return null;
        }
    }

    // The DCC shield's blue sits near hue 217 degrees. Protected/Warning are luminance-preserving hue
    // rotations of that art (so the white "DCC" and the bevel survive untouched); Neutral desaturates.
    // Warning also lifts brightness so amber reads as amber, not brown, at the source blue's luminance.
    private static System.Drawing.Imaging.ColorMatrix MatrixFor(TrayStatus status) => status switch
    {
        TrayStatus.Protected => HueRotation(-75f, 1f),
        TrayStatus.Warning => HueRotation(178f, 1.28f),
        _ => Desaturate(),
    };

    /// <summary>Luminance-preserving hue rotation (SVG feColorMatrix), optionally brightened, returned as
    /// a GDI <see cref="System.Drawing.Imaging.ColorMatrix"/> (transposed for GDI's row-vector convention).</summary>
    private static System.Drawing.Imaging.ColorMatrix HueRotation(float degrees, float brightness)
    {
        var a = degrees * System.MathF.PI / 180f;
        var c = System.MathF.Cos(a);
        var s = System.MathF.Sin(a);
        const float lr = 0.213f, lg = 0.715f, lb = 0.072f;

        // SVG hue-rotate rows (out = M * in). Placed TRANSPOSED into the GDI matrix (GDI is in * M).
        var a00 = lr + c * (1 - lr) + s * (-lr);
        var a01 = lg + c * (-lg) + s * (-lg);
        var a02 = lb + c * (-lb) + s * (1 - lb);
        var a10 = lr + c * (-lr) + s * 0.143f;
        var a11 = lg + c * (1 - lg) + s * 0.140f;
        var a12 = lb + c * (-lb) + s * (-0.283f);
        var a20 = lr + c * (-lr) + s * (-(1 - lr));
        var a21 = lg + c * (-lg) + s * lg;
        var a22 = lb + c * (1 - lb) + s * lb;

        return new System.Drawing.Imaging.ColorMatrix
        {
            Matrix00 = a00 * brightness,
            Matrix10 = a01 * brightness,
            Matrix20 = a02 * brightness,
            Matrix01 = a10 * brightness,
            Matrix11 = a11 * brightness,
            Matrix21 = a12 * brightness,
            Matrix02 = a20 * brightness,
            Matrix12 = a21 * brightness,
            Matrix22 = a22 * brightness,
            Matrix33 = 1f,
            Matrix44 = 1f,
        };
    }

    /// <summary>A grayscale (luminance) <see cref="System.Drawing.Imaging.ColorMatrix"/> for the neutral state.</summary>
    private static System.Drawing.Imaging.ColorMatrix Desaturate()
    {
        const float lr = 0.213f, lg = 0.715f, lb = 0.072f;
        return new System.Drawing.Imaging.ColorMatrix
        {
            Matrix00 = lr,
            Matrix10 = lg,
            Matrix20 = lb,
            Matrix01 = lr,
            Matrix11 = lg,
            Matrix21 = lb,
            Matrix02 = lr,
            Matrix12 = lg,
            Matrix22 = lb,
            Matrix33 = 1f,
            Matrix44 = 1f,
        };
    }

    // DllImport (not the source-generated LibraryImport): a bool-returning LibraryImport needs
    // AllowUnsafeBlocks, which this project does not enable. System32-only search path satisfies CA5392.
    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = false)]
    [System.Runtime.InteropServices.DefaultDllImportSearchPaths(
        System.Runtime.InteropServices.DllImportSearchPath.System32)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool DestroyIcon(System.IntPtr handle);
}
