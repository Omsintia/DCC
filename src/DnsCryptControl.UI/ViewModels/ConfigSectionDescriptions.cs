namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// 5g-3: plain-language explainers for the Configuration tab's curated section groups,
/// keyed by the EXACT A4 group name (<c>SettingDescriptor.Group</c> / the section nav's
/// display name). <see cref="ConfigurationViewModel"/> looks a group up when building
/// its <see cref="ConfigSectionViewModel"/>; groups without an entry get a null
/// <see cref="ConfigSectionViewModel.Description"/> and show no caption.
/// WP3 seeded "Local DoH"; WP4 authored the remaining 13 groups, so every catalog
/// group now has an explainer (test-enforced). Every factual claim must stay exactly
/// true against dnscrypt-proxy 2.1.16 semantics and this app's actual behaviour.
/// </summary>
internal static class ConfigSectionDescriptions
{
    /// <summary>Group name → section explainer (plain language first, technical tail).</summary>
    internal static IReadOnlyDictionary<string, string> All { get; } =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["General"] =
                "The basics of how the proxy runs on this PC: where it listens for DNS " +
                "requests, how many programs it serves at once, and — optionally — a " +
                "hand-picked list of servers to use or names to always avoid. Technical: " +
                "when server_names is set, the require_* filters in Server selection are " +
                "ignored, but the protocol and IPv4/IPv6 toggles still apply.",

            ["Server selection"] =
                "Decides which kinds of servers the proxy may pick from: which internet " +
                "address families they use, which encryption protocols they speak, and " +
                "which operator promises (no logging, no filtering, signed answers) they " +
                "must make. Stricter choices mean fewer, but more carefully vetted, " +
                "servers. Technical: the require_* switches apply only when server_names " +
                "in General is empty; the protocol and address-family switches apply even " +
                "to hand-picked servers.",

            ["Connection"] =
                "How the proxy reaches the servers it has picked: the transport to use, " +
                "an optional outside proxy such as Tor, how long to wait for answers, and how " +
                "queries are spread across servers. The defaults suit most home " +
                "connections. Technical: this group also sets the reply a blocked lookup " +
                "receives and holds workarounds for a few servers with known-broken " +
                "implementations.",

            ["Logging"] =
                "Controls what dnscrypt-proxy writes down about its own activity: its " +
                "diagnostic messages, plus optional records of every DNS lookup and of " +
                "lookups for names that don't exist. Those lookup records amount to a " +
                "browsing history, so they stay off until you point them at a file — and " +
                "the address-scrambling options can mask which device made each request. " +
                "Technical: the query and no-such-name logs support tsv/ltsv formats, and " +
                "the IPCrypt options encrypt client IP addresses inside those logs.",

            ["Certificates & TLS"] =
                "How dnscrypt-proxy maintains and secures its encrypted connections to " +
                "DNS servers: how often server credentials are refreshed, plus privacy " +
                "and compatibility tweaks. The defaults suit almost everyone, and the " +
                "debugging options here can weaken privacy if left on. Technical: covers " +
                "DNSCrypt certificate refresh, TLS session and cipher behaviour for DoH, " +
                "and optional client certificates for private DoH servers.",

            ["Connectivity"] =
                "How dnscrypt-proxy first gets online and copes with unusual networks: " +
                "the plain DNS servers it may use briefly at startup, the " +
                "network-availability check, offline behaviour, and helpers for Wi-Fi " +
                "sign-in pages and IPv6-only networks. Your regular lookups are never " +
                "sent to the plain startup servers — those handle only the proxy's own " +
                "bootstrap chores. Technical: bootstrap resolvers speak plain DNS and are " +
                "generally not needed once resolver lists are cached and server addresses " +
                "are embedded in their stamps.",

            ["Filters & rules"] =
                "Decides what gets blocked, allowed or rewritten before a lookup is " +
                "answered: lists of names and addresses to block or always allow, custom " +
                "answers for chosen names, and rules that send certain domains to " +
                "specific servers. These settings mostly point at plain text rule files — " +
                "the Filtering tab gives you a guided editor for those files. Technical: " +
                "name rules support exact and wildcard patterns, a blocked-name rule may " +
                "end with @ plus a schedule name to block only at certain times, and " +
                "address rules match the addresses inside answers.",

            ["Cache"] =
                "Keeps recent DNS answers on this PC so repeated lookups are answered " +
                "instantly instead of asking a server every time — faster browsing and " +
                "fewer queries leaving your machine. The settings below tune how many " +
                "answers are kept and for how long, with separate limits for 'this name " +
                "does not exist' answers. Technical: a server's own expiry times are " +
                "clamped between the configured minimum and maximum values.",

            ["Schedules"] =
                "Named weekly time windows — days of the week with start and end times, " +
                "using this PC's local clock — that name rules can reference, for example " +
                "to block game sites only on school nights. A window does nothing by " +
                "itself; a rule opts in by ending with @ followed by the window's name. " +
                "Technical: this section is edited as raw TOML here; each window is a " +
                "[schedules.<name>] table listing days with after/before times.",

            ["Static servers"] =
                "Adds DNS servers by hand — ones you run yourself or that are not in the " +
                "downloaded server lists. Each server is described by a stamp: one " +
                "sdns:// text string, usually copied from the server operator, that packs " +
                "the address and connection details together. Technical: entries are " +
                "[static.<name>] tables edited as raw TOML here, each holding a stamp " +
                "value.",

            ["Sources"] =
                "Where dnscrypt-proxy gets its lists of available DNS servers and relays. " +
                "The proxy downloads these lists itself on a schedule, checks their " +
                "digital signature, and keeps a local copy so it can start even without a " +
                "working network — this app never downloads anything, it only writes " +
                "these settings. Technical: each source is a [sources.<name>] table " +
                "needing its own cache_file; lists are minisign-verified; refresh_delay " +
                "is clamped to 25-169 hours.",

            ["Anonymized DNS"] =
                "Splits knowledge between two parties so neither sees the whole picture: " +
                "your DNS questions travel through a relay, so a routed server does not " +
                "see your address and the relay cannot read your questions. Works with " +
                "DNSCrypt servers (via DNSCrypt relays) and Oblivious DoH servers (via " +
                "ODoH relays) — ordinary DoH servers cannot be relayed. Servers without " +
                "a working route are still contacted directly unless 'skip incompatible' " +
                "is on. The Anonymized DNS tab is the friendlier place to manage this; " +
                "these are the same underlying settings.",

            ["Monitoring"] =
                "An optional live status page served by dnscrypt-proxy itself: open it in " +
                "a browser to watch queries, server performance and totals as they " +
                "happen. It is off by default and, at the default address, reachable only " +
                "from this PC; nothing on it is collected or sent anywhere by this app. " +
                "Technical: protected by HTTP basic-auth defaulting to admin/changeme " +
                "(change it before enabling); a Prometheus metrics endpoint can be " +
                "exposed separately.",

            ["Local DoH"] =
                "Runs a small DNS-over-HTTPS server on this PC, so a browser that insists on " +
                "encrypted DNS can be pointed at this machine (instead of Cloudflare or Google) " +
                "and still travel your protected resolver chain. Most people should leave this " +
                "off: the simpler tool is the Dashboard's \"Browser DoH: blocked\" switch, which " +
                "tells Chrome, Edge and Firefox to stop using their own DoH (which would bypass " +
                "DnsCrypt entirely). Technical: requires listen_addresses " +
                "plus a locally trusted certificate (cert_file / cert_key_file); the HTTP path " +
                "defaults to /dns-query; the app applies no extra validation to these keys.",
        };
}
