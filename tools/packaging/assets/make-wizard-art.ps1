#requires -Version 5.1
<#
  Generates the two WiX UI bitmaps (blue->teal, branded with the DCC shield) that replace the stock
  red WiX artwork, plus PNG previews for eyeballing. Run once when the art changes; the BMPs are
  committed and referenced by Product.wxs (WixUIDialogBmp 493x312, WixUIBannerBmp 493x58).
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$dir = $PSScriptRoot
$cBlue = [System.Drawing.Color]::FromArgb(11, 77, 162)   # #0B4DA2
$cTeal = [System.Drawing.Color]::FromArgb(23, 162, 184)  # #17A2B8

function New-Shield {
    param([single]$x, [single]$y, [single]$w, [single]$h)
    # Shield outline as a closed path in the box (x,y,w,h). y grows down.
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $pts = @(
        [System.Drawing.PointF]::new($x + 0.15 * $w, $y + 0.06 * $h),
        [System.Drawing.PointF]::new($x + 0.85 * $w, $y + 0.06 * $h),
        [System.Drawing.PointF]::new($x + 0.85 * $w, $y + 0.55 * $h),
        [System.Drawing.PointF]::new($x + 0.50 * $w, $y + 0.96 * $h),
        [System.Drawing.PointF]::new($x + 0.15 * $w, $y + 0.55 * $h)
    )
    $p.AddPolygon($pts)
    $p.CloseFigure()
    return $p
}

function Draw-ShieldGlyph {
    param($g, [single]$x, [single]$y, [single]$w, [single]$h, $fill, $stroke, $check)
    $shield = New-Shield $x $y $w $h
    $fb = New-Object System.Drawing.SolidBrush $fill
    $g.FillPath($fb, $shield)
    $sp = New-Object System.Drawing.Pen($stroke, [single]([Math]::Max(1.5, $w * 0.03)))
    $g.DrawPath($sp, $shield)
    # checkmark
    $cp = New-Object System.Drawing.Pen($check, [single]([Math]::Max(2.0, $w * 0.09)))
    $cp.StartCap = 'Round'; $cp.EndCap = 'Round'; $cp.LineJoin = 'Round'
    $g.DrawLines($cp, @(
        [System.Drawing.PointF]::new($x + 0.32 * $w, $y + 0.50 * $h),
        [System.Drawing.PointF]::new($x + 0.45 * $w, $y + 0.64 * $h),
        [System.Drawing.PointF]::new($x + 0.70 * $w, $y + 0.34 * $h)
    ))
    $fb.Dispose(); $sp.Dispose(); $cp.Dispose(); $shield.Dispose()
}

function New-Bmp {
    param([int]$w, [int]$h, [string]$baseName, [scriptblock]$draw)
    $bmp = New-Object System.Drawing.Bitmap($w, $h, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
    $g.Clear([System.Drawing.Color]::White)
    & $draw $g $w $h
    $g.Dispose()
    $bmp.Save((Join-Path $dir "$baseName.bmp"), [System.Drawing.Imaging.ImageFormat]::Bmp)
    $bmp.Save((Join-Path $dir "$baseName.preview.png"), [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "wrote $baseName.bmp (+ preview)"
}

# ---- Dialog bitmap: 493 x 312 (Welcome / Exit background) --------------------------------------
New-Bmp 493 312 'WixUIDialogBmp' {
    param($g, $w, $h)
    $billboard = 164
    $rect = New-Object System.Drawing.Rectangle(0, 0, $billboard, $h)
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $cBlue, $cTeal, 90.0)
    $g.FillRectangle($grad, $rect)
    $grad.Dispose()
    Draw-ShieldGlyph $g ([single]42) ([single]96) ([single]80) ([single]92) `
        ([System.Drawing.Color]::FromArgb(235, 255, 255, 255)) `
        ([System.Drawing.Color]::FromArgb(120, 255, 255, 255)) `
        $cTeal
    $font = New-Object System.Drawing.Font('Segoe UI Semibold', 11, [System.Drawing.FontStyle]::Bold)
    $sf = New-Object System.Drawing.StringFormat; $sf.Alignment = 'Center'
    $wb = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $g.DrawString('DnsCryptControl', $font, $wb, (New-Object System.Drawing.RectangleF(0, 205, $billboard, 24)), $sf)
    $font2 = New-Object System.Drawing.Font('Segoe UI', 8)
    $wb2 = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(220, 255, 255, 255))
    $g.DrawString('Encrypted DNS', $font2, $wb2, (New-Object System.Drawing.RectangleF(0, 228, $billboard, 18)), $sf)
    $font.Dispose(); $font2.Dispose(); $wb.Dispose(); $wb2.Dispose(); $sf.Dispose()
}

# ---- Banner bitmap: 493 x 58 (interior dialogs) ------------------------------------------------
New-Bmp 493 58 'WixUIBannerBmp' {
    param($g, $w, $h)
    $block = 58
    $rect = New-Object System.Drawing.Rectangle(($w - $block), 0, $block, $h)
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $cBlue, $cTeal, 90.0)
    $g.FillRectangle($grad, $rect)
    $grad.Dispose()
    Draw-ShieldGlyph $g ([single]($w - 44)) ([single]11) ([single]30) ([single]36) `
        ([System.Drawing.Color]::FromArgb(235, 255, 255, 255)) `
        ([System.Drawing.Color]::FromArgb(120, 255, 255, 255)) `
        $cTeal
}

Write-Host "done -> $dir"
