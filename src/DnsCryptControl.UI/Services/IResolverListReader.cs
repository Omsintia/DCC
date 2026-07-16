using System.Collections.Generic;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Reads the proxy's cached resolver/relay lists off disk (the split-privilege read path — the
/// UI reads directly; only writes go through the helper). Discovers sources from the config's
/// <c>[sources.*]</c> tables; never throws.
/// </summary>
public interface IResolverListReader
{
    /// <summary>Reads every configured source's list, returning one snapshot per source (empty when the config has no sources).</summary>
    IReadOnlyList<ResolverListSnapshot> ReadAll();
}
