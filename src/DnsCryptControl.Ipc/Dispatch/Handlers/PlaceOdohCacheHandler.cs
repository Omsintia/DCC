using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Ipc.Dispatch.Handlers;

/// <summary>
/// PlaceOdohCache: writes the helper's OWN bundled, minisign-signed ODoH source-list cache
/// files into the proxy's protected dir (byte-exact, atomic). No payload — the content is the
/// store's trusted embedded copy, never caller-supplied, so an unprivileged caller cannot use
/// this to inject a resolver list (and the proxy re-verifies the .md against the pinned
/// minisign key regardless). Placing a valid cache BEFORE the odoh-* sources are referenced in
/// the config lets the proxy load ODoH from cache instead of the boot-time download that
/// dnscrypt-proxy treats as FATAL when the list URL can't be resolved yet — the sole cause of
/// the "adding ODoH bricks all DNS" failure. Non-generic <see cref="Result"/> response.
/// </summary>
public sealed class PlaceOdohCacheHandler : ICommandHandler
{
    private readonly IConfigStore _store;

    public PlaceOdohCacheHandler(IConfigStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _store = store;
    }

    public IpcCommandType Command => IpcCommandType.PlaceOdohCache;

    public string Handle(IpcRequest request)
    {
        var place = _store.PlaceOdohSourceCaches();
        return place.Success
            ? IpcSerializer.SerializePayload(Result.Ok())
            : IpcSerializer.SerializePayload(
                Result.Fail(PlatformResultMapping.ToIpc(place.Error), place.Message ?? "could not place ODoH source caches"));
    }
}
