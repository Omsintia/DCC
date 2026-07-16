using System.Collections.Generic;
using System.IO;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>B2: <see cref="UiStateStore"/> — per-user favorites/stashed-routes/sort, fail-closed reads, atomic writes.</summary>
public sealed class UiStateStoreTests
{
    private static string TempPath() =>
        Path.Combine(Path.GetTempPath(), "uistate-" + Path.GetRandomFileName(), "ui-state.json");

    [Fact]
    public void Load_missingFile_returnsDefaults()
    {
        var store = new UiStateStore(TempPath());
        var state = store.Load();
        Assert.Empty(state.Favorites);
        Assert.Empty(state.StashedRoutes);
        Assert.Null(state.ResolverSort);
    }

    [Fact]
    public void Save_thenLoad_roundTrips()
    {
        var path = TempPath();
        try
        {
            var store = new UiStateStore(path);
            store.Save(new UiState
            {
                Favorites = new List<string> { "cloudflare", "quad9" },
                ResolverSort = "latency",
                StashedRoutes = new List<UiStashedRoute>
                {
                    new() { ServerName = "cloudflare", Via = new List<string> { "anon-cs-fr" } },
                },
            });

            var loaded = new UiStateStore(path).Load();
            Assert.Equal(new[] { "cloudflare", "quad9" }, loaded.Favorites);
            Assert.Equal("latency", loaded.ResolverSort);
            var route = Assert.Single(loaded.StashedRoutes);
            Assert.Equal("cloudflare", route.ServerName);
            Assert.Equal(new[] { "anon-cs-fr" }, route.Via);
        }
        finally { TryCleanup(path); }
    }

    [Fact]
    public void Load_corruptFile_returnsDefaults()
    {
        var path = TempPath();
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, "{ this is not valid json ]");
            var state = new UiStateStore(path).Load();
            Assert.Empty(state.Favorites);
        }
        finally { TryCleanup(path); }
    }

    [Fact]
    public void Save_overExistingFile_replacesAtomically()
    {
        var path = TempPath();
        try
        {
            var store = new UiStateStore(path);
            store.Save(new UiState { ResolverSort = "first" });
            store.Save(new UiState { ResolverSort = "second" });
            Assert.Equal("second", new UiStateStore(path).Load().ResolverSort);
            Assert.False(File.Exists(path + ".tmp")); // temp cleaned up
        }
        finally { TryCleanup(path); }
    }

    [Fact]
    public void Save_thenLoad_roundTrips_newPrefs()
    {
        var path = TempPath();
        try
        {
            new UiStateStore(path).Save(new UiState
            {
                Theme = "Dark",
                StartWithWindows = true,
                StartMinimized = true,
                MinimizeToTrayOnClose = true,
            });

            var loaded = new UiStateStore(path).Load();
            Assert.Equal("Dark", loaded.Theme);
            Assert.True(loaded.StartWithWindows);
            Assert.True(loaded.StartMinimized);
            Assert.True(loaded.MinimizeToTrayOnClose);
        }
        finally { TryCleanup(path); }
    }

    [Fact]
    public void Load_missingFile_returnsPrefDefaults()
    {
        var state = new UiStateStore(TempPath()).Load();
        Assert.Null(state.Theme);
        Assert.False(state.StartWithWindows);
        Assert.False(state.StartMinimized);
        Assert.False(state.MinimizeToTrayOnClose);
    }

    private static void TryCleanup(string path)
    {
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (dir is not null && Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
        catch (IOException) { }
    }
}
