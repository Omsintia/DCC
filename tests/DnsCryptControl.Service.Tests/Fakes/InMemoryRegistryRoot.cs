using System;
using System.Collections.Generic;
using System.Linq;
using DnsCryptControl.Service.Windows.Registry;
using Microsoft.Win32;

namespace DnsCryptControl.Service.Tests.Fakes;

/// <summary>
/// Reusable in-memory registry seam for unit tests. Supports nested subkeys, values with
/// explicit kinds, value/subkey enumeration, delete, and create-or-open semantics.
/// Designed for use by all groups (C2, E2, G2, I3) that consume IRegistryRoot.
/// </summary>
internal sealed class InMemoryRegistryRoot : IRegistryRoot
{
    // The tree is stored as a dictionary keyed by normalized path (OrdinalIgnoreCase).
    // Each node holds its own values and tracks whether the node itself was explicitly created
    // (as opposed to only existing as a parent implied by a deeper path).
    private readonly InMemorySubKeyNode _root = new();

    // --- Fluent builder helpers for test setup ---

    /// <summary>Ensure the subkey path exists (as if CreateSubKey was called).</summary>
    public InMemoryRegistryRoot WithSubKey(string path)
    {
        _ = GetOrCreateNode(path);
        return this;
    }

    /// <summary>Pre-populate a value so tests can start with an already-existing entry.</summary>
    public InMemoryRegistryRoot WithValue(string path, string valueName, object data, RegistryValueKind kind)
    {
        var node = GetOrCreateNode(path);
        node.SetValue(valueName, data, kind);
        return this;
    }

    // --- IRegistryRoot ---

    public IRegistrySubKey? OpenSubKey(string path, bool writable)
    {
        var node = FindNode(path);
        return node is null ? null : new InMemorySubKeyHandle(node);
    }

    public IRegistrySubKey CreateSubKey(string path)
    {
        var node = GetOrCreateNode(path);
        return new InMemorySubKeyHandle(node);
    }

    public void DeleteSubKeyTree(string path, bool throwIfMissing)
    {
        var segments = Split(path);
        if (segments.Length == 0) return;

        // Walk to parent, then remove the child.
        var parent = _root;
        for (int i = 0; i < segments.Length - 1; i++)
        {
            if (!parent.Children.TryGetValue(segments[i], out var next))
            {
                if (throwIfMissing)
                    throw new System.IO.IOException($"Registry key not found: {path}");
                return;
            }
            parent = next;
        }

        var leaf = segments[^1];
        if (!parent.Children.ContainsKey(leaf))
        {
            if (throwIfMissing)
                throw new System.IO.IOException($"Registry key not found: {path}");
            return;
        }
        parent.Children.Remove(leaf);
    }

    // --- Internal helpers ---

    private InMemorySubKeyNode GetOrCreateNode(string path)
    {
        var segments = Split(path);
        var current = _root;
        foreach (var seg in segments)
        {
            if (!current.Children.TryGetValue(seg, out var child))
            {
                child = new InMemorySubKeyNode();
                current.Children[seg] = child;
            }
            current = child;
        }
        return current;
    }

    private InMemorySubKeyNode? FindNode(string path)
    {
        var segments = Split(path);
        var current = _root;
        foreach (var seg in segments)
        {
            if (!current.Children.TryGetValue(seg, out var child))
                return null;
            current = child;
        }
        return current;
    }

    private static string[] Split(string path) =>
        path.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);

    // -----------------------------------------------------------------------

    /// <summary>A node in the in-memory key tree.</summary>
    private sealed class InMemorySubKeyNode
    {
        // Case-insensitive like the real registry.
        public Dictionary<string, InMemorySubKeyNode> Children { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        private readonly Dictionary<string, (object Data, RegistryValueKind Kind)> _values =
            new(StringComparer.OrdinalIgnoreCase);

        public object? GetValue(string name) =>
            _values.TryGetValue(name, out var cell) ? cell.Data : null;

        public RegistryValueKind GetValueKind(string name) =>
            _values.TryGetValue(name, out var cell)
                ? cell.Kind
                : throw new System.IO.IOException($"Registry value '{name}' not found.");

        public void SetValue(string name, object data, RegistryValueKind kind) =>
            _values[name] = (data, kind);

        public void DeleteValue(string name, bool throwIfMissing)
        {
            if (!_values.Remove(name) && throwIfMissing)
                throw new System.IO.IOException($"Registry value '{name}' not found.");
        }

        public List<string> GetValueNames() => _values.Keys.ToList();
        public List<string> GetSubKeyNames() => Children.Keys.ToList();
    }

    // -----------------------------------------------------------------------

    /// <summary>Wraps a node as IRegistrySubKey.</summary>
    private sealed class InMemorySubKeyHandle : IRegistrySubKey
    {
        private readonly InMemorySubKeyNode _node;

        public InMemorySubKeyHandle(InMemorySubKeyNode node) => _node = node;

        public object? GetValue(string name) => _node.GetValue(name);
        public RegistryValueKind GetValueKind(string name) => _node.GetValueKind(name);
        public void SetValue(string name, object data, RegistryValueKind kind) => _node.SetValue(name, data, kind);
        public void DeleteValue(string name, bool throwIfMissing) => _node.DeleteValue(name, throwIfMissing);
        public IReadOnlyList<string> GetValueNames() => _node.GetValueNames();
        public IReadOnlyList<string> GetSubKeyNames() => _node.GetSubKeyNames();

        public void Dispose() { /* no real handle to release */ }
    }
}
