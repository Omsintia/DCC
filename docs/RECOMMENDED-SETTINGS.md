# Recommended settings for DnsCrypt Control

*A practical setup guide for people who value their privacy and don't want to trade away speed to get it.*

## Who this is for

If you torrent, stream shows and movies, game online, or build and run software — and you'd like your DNS private, un-tracked, and un-censored **without** your connection feeling slower — this guide is for you. It walks through a sensible default setup in about five minutes, then explains the handful of settings actually worth touching.

---

## Read this first: what encrypted DNS does — and does *not* — do

This is the most important part, so it's at the top.

**DnsCrypt Control encrypts and protects your *DNS lookups*** — the step where "example.com" becomes an IP address. That's genuinely valuable:

- ✅ Your ISP / network / public Wi-Fi can no longer **see or log which domains you look up**.
- ✅ DNS-based **tracking and profiling** is cut off.
- ✅ DNS-level **censorship and hijacking** (redirecting or blocking you at the resolver) stops working.
- ✅ You can **block ads and trackers** at the DNS level, for every app at once.

**It does *not* hide your actual traffic.** This is the part people get wrong:

- ❌ Your ISP still sees the **IP addresses** you connect to (and can often infer the site from that alone).
- ❌ Your downloads, streams, game sessions, and uploads are **not anonymized** by encrypting DNS.
- ❌ **Torrent traffic is not hidden.** Your IP is still visible to peers and trackers.

> **If you need your *traffic* private — not just your DNS — you need a VPN or Tor.**
> Encrypted DNS and a VPN solve *different* problems, and they work well **together**: the VPN hides your traffic, and DnsCrypt Control makes sure your DNS doesn't quietly leak *outside* the tunnel. Think of this app as one solid layer, not the whole stack.

With that honesty out of the way — here's how to set it up well.

---

## The 5-minute recommended setup

The **kill switch ships on by default** (recommended — it's *fail-closed*: if the proxy ever stops, DNS is **blocked** rather than silently falling back to your ISP's unencrypted DNS). So on the **Dashboard**, first run is just two clicks:

1. **Turn the main switch ON.** This routes your device's DNS through the encrypted proxy — and because the kill switch is already on, nothing can quietly fall back to unencrypted DNS if the proxy ever stops. The status badge turns green **"You're protected"** only after a live leak check actually passes — not just because the switch is on. The **first time you turn protection on**, Windows recommends a **one-time reboot** to finish a related leak fix (Smart Multi-Homed Name Resolution) — that reboot comes from *enabling protection* and is about the Windows leak fix; your encrypted DNS and the kill switch are already active before you reboot.
2. **Set Browser DoH to "blocked."** Chrome, Edge, and Firefox can run their *own* DNS-over-HTTPS and quietly bypass this app. "Blocked" keeps those three on your protected DNS. (This toggle is available once protection is on; other apps aren't affected by it.)

> Prefer the kill switch **off**? It's a toggle on the Dashboard — turn it off *before* the main switch. (It arms at the moment protection is enabled, so flipping it after you're already protected takes effect on the next off-then-on cycle.)

That's the core. Everything below is tuning by goal.

---

## Tuning by goal

### 🔒 Maximum privacy (don't let anyone profile your lookups)

| Setting | Recommendation | Why |
|---|---|---|
| **require_nolog** | On *(default)* | Only use resolvers that declare they keep no logs. |
| **Browser DoH** | Blocked | Stops browsers bypassing the proxy. |
| **Kill switch** | On | No silent fallback to unprotected DNS. |
| **Anonymized DNS (relays)** | Turn on + add a route | Your query travels through a **relay**, so the DNS server that answers never sees *who* asked — it sees the relay. No single party sees both your identity **and** your queries. Costs a little latency. |
| **ODoH** *(advanced)* | Optional | Oblivious DoH is the DoH-protocol version of the same idea. It needs the ODoH server + relay lists (use the **"Add ODoH server lists"** button in the Resolvers tab) **and** a route pairing a target with a relay — an ODoH target only works *through* a relay. Keep one plain DNSCrypt server in the pool, unrouted, as the bootstrap anchor. |

> **A relay vs. a server:** a *server* (resolver) answers your query and normally sees your IP. A *relay* forwards your encrypted query to the server but can't read it, and the server sees the relay's address instead of yours. That split is the whole point of Anonymized DNS.

> **If a route won't resolve (some VMs / NATs / strict firewalls):** a few networks silently drop the larger UDP packets that anonymized DNSCrypt uses — the route can pass its latency and handshake checks but still never actually resolve (the app shows an amber *"DNS not resolving through this route"* notice when this happens). The fix is **Always use TCP** (`force_tcp`) in **Configuration → Connection**: it sends queries over TCP, which these networks pass fine. Two caveats: (1) it slightly increases latency, and (2) turn it **off** for **ODoH** — ODoH rides HTTPS and doesn't need it, and `force_tcp` can break the direct DNSCrypt *anchor* that ODoH uses to bootstrap. On an ordinary home network you won't need `force_tcp` at all.

### ⚡ Speed & comfort (don't slow anything down)

| Setting | Recommendation | Why |
|---|---|---|
| **cache** | On *(default)* | Repeated lookups are answered instantly from memory. |
| **lb_estimator** | On *(default)* | Keeps re-measuring server speed so you stay on the fastest one. *(In Configuration it shows "on (default)" — that means it's already on; you don't need to touch it.)* |
| **require_dnssec** | On *(our default)* | We ship it **on** so every answer is cryptographically validated and forged replies are rejected. It can trim the usable server pool a little once you switch to the full pool — turn it **off** if you'd rather keep the widest, fastest set of servers. |
| **block_ipv6** | On *if you have no working IPv6* | Skips slow AAAA lookups that would time out. Leave **off** if you actually use IPv6. |

### 🧹 Filtering (fewer ads/trackers = faster, cleaner, more private)

| Setting | Recommendation | Why |
|---|---|---|
| **Blocked names** (a blocklist) | Enable one | Blocks ad/tracker domains for every app at once — less noise, less profiling, slightly faster pages. |
| **block_undelegated** | On *(default)* | Names that can't exist on the public internet (e.g. `.local`) never leak out. Safe. |
| **block_unqualified** | On *(default)* | Bare device names (e.g. `printer`) stop leaking to the internet. Safe. |

### 🎮 For torrenting / streaming / gaming specifically

- Encrypted DNS **helps**: your ISP can't log the trackers/mirrors/CDNs you resolve, and DNS-level blocks on them stop working.
- But (see the top of this page) your **traffic itself isn't hidden**. For that, run a **VPN alongside** this app. The combination is strong: the VPN encrypts your traffic, and DnsCrypt Control's kill switch guarantees your DNS never leaks around it.
- Keep the **kill switch on** so a mid-download proxy hiccup can't silently drop you back onto your ISP's DNS.

---

## Settings you can safely leave alone

Most of the ~118 settings in the **Configuration** tab are internal `dnscrypt-proxy` knobs (timeouts, TLS options, cache sizes) that already ship with good defaults. The editor shows a small **"(default)"** marker next to any setting you haven't explicitly changed — if it says *(default)*, the proxy is already using its recommended value. Don't tweak these unless you have a specific reason.

## How to confirm it's actually working

- **Dashboard** shows the green **"You're protected"** badge — which only appears after a live leak check passes (not just because the switch is on). Right after you enable it you may briefly see **"Verifying…"** while the proxy warms up; that's normal and clears in a few seconds.
- **Query Monitor** (opt-in — it's your browsing history, so it's off by default) shows your lookups in real time: `PASS`, `REJECT` (blocked), `CLOAK`, `SYNTH`.
- **Kill-switch test:** with it armed, a plaintext DNS query to a public server (e.g. `8.8.8.8`) is blocked, while your normal browsing keeps working through the proxy.

---

*DnsCrypt Control makes zero outbound network connections of its own — no update checks, no telemetry — and this is enforced at build time. It relies on the `dnscrypt-proxy` service to fetch and cryptographically verify its server lists.*
