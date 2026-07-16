using System.Collections.Generic;
using System.Linq;

namespace DnsCryptControl.Core.Schema;

/// <summary>
/// The complete catalog of dnscrypt-proxy configuration keys (v2.1.16 / master),
/// transcribed from the design spec's Appendix A. The structured editor and the
/// validator are both generated from this single source of truth so they cannot
/// drift from the real binary.
/// The comment banners below are the source of truth for the curated display
/// <see cref="SettingDescriptor.Group"/> values the Configuration tab's section
/// nav is built from: each banner leads with its group name; where one group
/// spans several banner blocks the banner reads "Group: sub-topic". Dynamic
/// sections group under their own name (Sources, Schedules, Static servers).
/// </summary>
public static class ConfigCatalog
{
    private static readonly SettingDescriptor[] _all =
    {
        // ---- General (top-level / global) ----
        new("server_names", "", SettingValueType.StringArray, "unset", "Explicit list of servers to use; when set, require_* filters are ignored.", "General",
            Friendly: "Pick the exact servers to use, by name. When this list is filled in, only those servers are used and the three 'only use servers that…' requirements under Server selection no longer apply."),
        new("disabled_server_names", "", SettingValueType.StringArray, "[]", "Server names to never use even if they match all criteria.", "General",
            Friendly: "Servers named here are never used, even if they pass every other check or you picked them by hand. Handy for banning one misbehaving server without touching anything else."),
        new("listen_addresses", "", SettingValueType.StringArray, "['127.0.0.1:53']", "Local IP:port pairs to listen on for DNS queries.", "General",
            Friendly: "Where on this PC the proxy listens for DNS requests (IP address and port). Keep the standard 127.0.0.1:53 entry — this app's protection points Windows at it — and be aware that adding other addresses can expose the service to the rest of your network."),
        new("max_clients", "", SettingValueType.Long, "250", "Maximum number of simultaneous client connections.", "General",
            Friendly: "How many DNS questions the proxy will handle at the same time. The default of 250 is plenty for one PC; raise it only if this machine handles DNS for many other devices."),
        new("user_name", "", SettingValueType.String, "unset", "Drop privileges to this system user after binding sockets (not supported on Windows).", "General",
            Friendly: "After starting, the proxy can switch to a less-privileged system account to limit damage if it were ever compromised. This is not supported on Windows, so leave it unset here."),

        // ---- Server selection ----
        new("ipv4_servers", "", SettingValueType.Bool, "true", "Use servers reachable over IPv4.", "Server selection",
            Friendly: "Allow servers reached over regular IPv4 internet addresses. Leave this on unless your network is IPv6-only."),
        new("ipv6_servers", "", SettingValueType.Bool, "false", "Use servers reachable over IPv6.", "Server selection",
            Friendly: "Allow servers reached over IPv6 internet addresses. Only turn this on if your connection really has IPv6, otherwise those servers are unreachable and only waste time."),
        new("dnscrypt_servers", "", SettingValueType.Bool, "true", "Use DNSCrypt-protocol servers.", "Server selection",
            Friendly: "Allow servers that encrypt your DNS traffic with the DNSCrypt method. Keeping both this kind and the DNS-over-HTTPS kind switched on gives the proxy the widest choice of servers."),
        new("doh_servers", "", SettingValueType.Bool, "true", "Use DNS-over-HTTPS servers.", "Server selection",
            Friendly: "Allow servers that encrypt your DNS inside ordinary secure web traffic (HTTPS). Because it looks like normal browsing, it often keeps working on networks that interfere with other kinds of DNS."),
        new("odoh_servers", "", SettingValueType.Bool, "false", "Use Oblivious DoH servers.", "Server selection",
            Friendly: "Allow servers reached through an extra relay, so the server answering your question cannot also see who asked it. Turning this on by itself does nothing — matching relay sources and a relay route must be configured too."),
        new("require_dnssec", "", SettingValueType.Bool, "false", "Only use servers that support DNSSEC.", "Server selection",
            Friendly: "Only use servers that can return cryptographically signed DNS answers, so forged replies can be detected. Turning this on shrinks the pool of usable servers."),
        new("require_nolog", "", SettingValueType.Bool, "true", "Only use servers that declare they don't log.", "Server selection",
            Friendly: "Only use servers whose operators declare they keep no record of what you look up. A privacy gain, but it rests on the operator's own promise."),
        new("require_nofilter", "", SettingValueType.Bool, "true", "Only use servers that don't enforce their own blocklist.", "Server selection",
            Friendly: "Only use servers that promise to answer everything rather than censor some names with their own blocklist. Turn it off on purpose if you want a filtering server, such as a family-safe one."),

        // ---- Connection ----
        new("force_tcp", "", SettingValueType.Bool, "false", "Always use TCP for upstream queries (useful behind some firewalls).", "Connection",
            Friendly: "Always talk to servers over TCP, a slower but firewall-friendlier connection style, instead of quick single-packet messages. Turn this on if your network drops UDP — some VMs, NATs, and strict firewalls do, which can make anonymized DNS complete its handshake but never actually resolve — or when routing through an outside proxy such as Tor so no query slips around it."),
        new("http3", "", SettingValueType.Bool, "false", "Enable HTTP/3 (QUIC) for DoH servers that support it.", "Connection",
            Friendly: "Lets DNS-over-HTTPS servers answer over a newer, often quicker web transport (HTTP/3) when they support it. Worth a try, but some networks block that transport."),
        new("http3_probe", "", SettingValueType.Bool, "false", "Probe DoH servers for HTTP/3 support and remember the result.", "Connection",
            Friendly: "When the HTTP/3 option is on, tries that newer transport first with each DNS-over-HTTPS server, remembers which ones can use it, and quietly falls back when one cannot. Does nothing while HTTP/3 is switched off."),
        new("proxy", "", SettingValueType.String, "unset", "SOCKS proxy address (e.g. for Tor) for all upstream connections.", "Connection",
            Friendly: "Passes the proxy's server connections through an outside SOCKS proxy you choose (for example Tor), hiding your real address from the DNS servers; if that outside proxy is down, lookups stop. It only carries TCP connections, so also switch on the always-use-TCP option above to make sure every query goes through it."),
        new("http_proxy", "", SettingValueType.String, "unset", "HTTP proxy for DoH connections only.", "Connection",
            Friendly: "Routes only the DNS-over-HTTPS traffic through a web proxy; servers using other protocols are not affected. Useful on networks where the only way out is through such a proxy."),
        new("timeout", "", SettingValueType.Long, "5000", "Query timeout in milliseconds before trying another server.", "Connection",
            Friendly: "How long to wait for a server's answer, in milliseconds, before giving up and trying another server. Lower values recover faster from a dead server but can cut off slow-yet-healthy ones."),
        new("keepalive", "", SettingValueType.Long, "30", "Keep-alive period in seconds for long-lived connections.", "Connection",
            Friendly: "How long, in seconds, to keep an idle secure-web (HTTPS) connection to a server open so the next question can reuse it. Reusing connections makes repeated lookups faster."),
        new("edns_client_subnet", "", SettingValueType.StringArray, "unset", "EDNS client subnet to send to upstream servers.", "Connection",
            Friendly: "Attaches a network range of your choosing to outgoing questions so large content providers can steer you toward nearby servers; it does not have to be your real network. Whatever range you list is shown to the DNS servers, so privacy-minded users usually leave it unset."),
        new("blocked_query_response", "", SettingValueType.String, "hinfo", "Response to blocked queries: refused, hinfo, or a:<IPv4>,aaaa:<IPv6>.", "Connection",
            Friendly: "What a blocked lookup gets as its answer: an outright refusal, a small informational record explaining the block, or a fixed address you choose. A fixed address lets you point blocked names at, say, a local block page."),
        new("refused_code_in_responses", "", SettingValueType.Bool, "false", "Return REFUSED for blocked queries instead of the synthetic informational answer (struct only, not in example).", "Connection",
            Friendly: "Answers blocked lookups with a standard 'refused' error code instead of the small informational answer chosen above. An old low-level switch that is rarely needed — the setting above is the normal way to control what blocked lookups receive."),

        // ---- Connection: load balancing & performance ----
        new("lb_strategy", "", SettingValueType.String, "wp2", "Load-balancing strategy: wp2, p2, ph, p<n>, first, or random.", "Connection",
            Friendly: "How a server is chosen for each question: always the fastest, one of the fastest few, or at random. The default leans toward the quickest servers while still spreading queries around."),
        new("lb_estimator", "", SettingValueType.Bool, "true", "Continuously measure server latency to improve load-balancing decisions.", "Connection",
            Friendly: "Keeps re-measuring how quickly each server answers while running, so the choice of server stays based on fresh speed data. Best left on."),
        new("timeout_load_reduction", "", SettingValueType.Float, "0.75", "Dynamically shrink query timeout as concurrent connections approach max_clients.", "Connection",
            Friendly: "When the proxy nears its simultaneous-connection limit, it gives slow servers less time to answer so it can keep up. This number (between 0 and 1) tunes how strong that shortening is."),
        new("enable_hot_reload", "", SettingValueType.Bool, "false", "Reload the configuration file without restarting the proxy.", "Connection",
            Friendly: "Picks up edits to the configuration and its rule files while the proxy keeps running, so changes apply without a restart. Leaving it off saves a little processor time and memory."),

        // ---- Logging (app/system) ----
        new("log_level", "", SettingValueType.Long, "2", "Log verbosity level: 0=verbose through 6=fatal.", "Logging",
            Friendly: "How much detail the proxy writes to its own diagnostic log, from 0 (record everything) to 6 (only fatal problems). Lower numbers give more detail but bigger log files."),
        new("log_file", "", SettingValueType.String, "unset", "Path to the application log file; unset = stderr.", "Logging",
            Friendly: "The file where the proxy saves its own status and error messages — useful when troubleshooting. If left unset, these messages are not kept in a file on disk."),
        new("log_file_latest", "", SettingValueType.Bool, "true", "Keep a symlink/copy pointing to the latest log file.", "Logging",
            Friendly: "Keeps the log file focused on the proxy's most recent run, so the newest entries are always easy to find. Turn it off to let entries from earlier runs accumulate in the same place."),
        new("use_syslog", "", SettingValueType.Bool, "false", "Send application logs to the system syslog/event log.", "Logging",
            Friendly: "Sends the proxy's status messages to the operating system's own log (on Windows, the Event Log) instead of a separate file. Handy if you already review system logs in one place."),
        new("log_files_max_size", "", SettingValueType.Long, "10", "Maximum size of each log file in MB before rotation.", "Logging",
            Friendly: "The size limit for each log file, in megabytes. When a file reaches this size the proxy starts a fresh one, so no single file grows without bound."),
        new("log_files_max_age", "", SettingValueType.Long, "7", "Maximum age in days before log files are deleted.", "Logging",
            Friendly: "How many days old log files are kept before being deleted automatically. Stops old logs from slowly filling the disk."),
        new("log_files_max_backups", "", SettingValueType.Long, "1", "Maximum number of rotated log file backups to retain.", "Logging",
            Friendly: "How many older log files to keep alongside the current one; anything beyond this number is deleted. Setting it to 0 keeps them all."),

        // ---- Certificates & TLS ----
        new("cert_refresh_concurrency", "", SettingValueType.Long, "10", "Number of certificates refreshed concurrently.", "Certificates & TLS",
            Friendly: "How many servers have their certificates refreshed at the same time. The default is fine for a PC; lowering it only helps on very low-powered hardware."),
        new("cert_refresh_delay", "", SettingValueType.Long, "240", "How often to refresh server certificates, in minutes.", "Certificates & TLS",
            Friendly: "How often, in minutes, the proxy re-fetches each server's certificate so connections keep working smoothly. The default of 240 minutes (4 hours) suits almost everyone."),
        new("cert_ignore_timestamp", "", SettingValueType.Bool, "false", "Ignore certificate timestamp validation (debug only).", "Certificates & TLS",
            Friendly: "Skips checking the validity dates on server certificates — meant only for devices whose clock may be wrong at startup. Leave this off: the date check helps protect you from stale or replayed credentials."),
        new("dnscrypt_ephemeral_keys", "", SettingValueType.Bool, "false", "Generate a new keypair for every DNSCrypt query.", "Certificates & TLS",
            Friendly: "Uses a brand-new encryption key for every single query sent to DNSCrypt servers, so separate queries cannot be linked together by the key. Better privacy, but noticeably more processor work."),
        new("tls_disable_session_tickets", "", SettingValueType.Bool, "false", "Disable TLS session tickets for better forward secrecy.", "Certificates & TLS",
            Friendly: "Makes every secure connection to a DNS-over-HTTPS server start completely fresh instead of resuming from saved session data, so separate connections are harder to link to you. Slightly better privacy, slightly slower reconnections."),
        new("tls_prefer_rsa", "", SettingValueType.Bool, "false", "Prefer RSA cipher suites over ECDSA.", "Certificates & TLS",
            Friendly: "Prefers an older, widely supported style of encryption key when securing connections. Rarely needed — it can ease the load on very slow devices, but it may not work with every server."),
        new("tls_cipher_suite", "", SettingValueType.StringArray, "unset", "Explicit list of TLS 1.3 cipher suite IDs (struct only, not in example).", "Certificates & TLS",
            Friendly: "Restricts which encryption methods the proxy will agree to when securing connections, listed by numeric ID. Advanced and rarely needed — leave unset and the proxy picks safe options automatically."),
        new("tls_key_log_file", "", SettingValueType.String, "unset", "Log TLS session keys for Wireshark decryption (debug only — never in production).", "Certificates & TLS",
            Friendly: "Saves the secret keys of encrypted connections to a file so a debugging tool can decode the captured traffic. Anyone who obtains that file can read your DNS traffic — leave it unset outside of short debugging sessions."),

        // ---- Connectivity: startup & network ----
        new("bootstrap_resolvers", "", SettingValueType.StringArray, "['9.9.9.11:53','8.8.8.8:53']", "Plaintext DNS resolvers used to bootstrap before encrypted DNS is available.", "Connectivity",
            Friendly: "Ordinary DNS servers used only for a few startup chores — such as finding hostname-based encrypted servers (like ODoH) in the first place — never for your normal lookups. To make those work with the kill switch on, this app uses a single loopback entry (127.0.0.1:53) so the lookup goes through the proxy itself and stays encrypted. The app flags only entries pointing at a REMOTE server on the unencrypted port (53), because the kill switch blocks plain DNS there and the proxy would get stranded; a loopback (127.0.0.1) entry is fine."),
        new("ignore_system_dns", "", SettingValueType.Bool, "true", "Ignore the system DNS resolvers and only use bootstrap_resolvers for bootstrapping. (example default true; code default false)", "Connectivity",
            Friendly: "Stops the proxy from ever falling back to the DNS servers the network handed out for its own internal startup lookups, keeping even those on servers you chose. This app expects it to stay on: turned off, those lookups could travel unencrypted through servers you never picked."),
        new("netprobe_address", "", SettingValueType.String, "'9.9.9.9:53'", "Address probed at startup to check network connectivity.", "Connectivity",
            Friendly: "An address the proxy briefly contacts at startup just to confirm the network is up — nothing meaningful is sent to it. Avoid pointing it at an address on your own machine."),
        new("netprobe_timeout", "", SettingValueType.Long, "60", "Timeout in seconds for the network probe at startup.", "Connectivity",
            Friendly: "How long, in seconds, to wait at startup for the network to come up before carrying on anyway; 0 skips the check entirely. This app expects 0, because the check sends a plain unencrypted test packet that the app's optional kill switch blocks — which would leave the proxy stuck waiting."),
        new("offline_mode", "", SettingValueType.Bool, "false", "Operate in offline mode, only serving from cache without any upstream queries.", "Connectivity",
            Friendly: "Stops using the remote encrypted servers entirely; only answers the proxy can produce on its own — such as previously remembered answers or specially mapped names — still work. Everything else fails until this is turned off."),
        new("query_meta", "", SettingValueType.StringArray, "unset", "Extra metadata strings attached to every outgoing query.", "Connectivity",
            Friendly: "Extra text tags added to the queries the proxy sends out, which a few specially configured servers use for things like access control. Leave unset unless the operator of your server asked for it — the tags are visible to the servers."),

        // ---- Filters & rules ----
        new("block_ipv6", "", SettingValueType.Bool, "false", "Return empty AAAA responses to prevent IPv6 DNS lookups.", "Filters & rules",
            Friendly: "Answers every request for an IPv6 address with an empty result, so programs fall back to IPv4. Useful when your connection has no working IPv6; it breaks anything reachable only over IPv6."),
        new("block_unqualified", "", SettingValueType.Bool, "true", "Block unqualified (single-label) domain names.", "Filters & rules",
            Friendly: "Blocks lookups for bare one-word names with no dot in them, like a computer's local name. Such lookups can never succeed on the public internet, and sending them out would only leak your local machine names."),
        new("block_undelegated", "", SettingValueType.Bool, "true", "Block queries for undelegated TLDs.", "Filters & rules",
            Friendly: "Blocks lookups for name endings that are not part of the public internet, such as ones used only inside home or office networks. This avoids leaking private names and skips lookups that could never succeed anyway."),
        new("reject_ttl", "", SettingValueType.Long, "10", "TTL in seconds for synthetic NXDOMAIN responses from blocking rules.", "Filters & rules",
            Friendly: "How long (in seconds) a program is told to remember a blocked answer before it may ask again. Lower means changes to your blocklists take effect sooner; higher means fewer repeated lookups for blocked names."),

        // ---- Filters & rules: cloaking / forwarding ----
        new("forwarding_rules", "", SettingValueType.String, "unset", "Path to a file mapping domains to specific upstream resolvers.", "Filters & rules",
            Friendly: "Points to a text file that sends chosen domains to specific DNS servers of your choosing — for example, your workplace's internal names to the office server. Lookups matched here skip the encrypted resolvers and go to the listed servers as ordinary unencrypted DNS."),
        new("cloaking_rules", "", SettingValueType.String, "unset", "Path to a file mapping domains to synthetic IP addresses.", "Filters & rules",
            Friendly: "Points to a text file that lets you hand out your own answers for chosen names — like a supercharged hosts file. You can map a name to a fixed address, or make one name act as an alias for another."),
        new("cloak_ttl", "", SettingValueType.Long, "600", "TTL in seconds for cloaked responses.", "Filters & rules",
            Friendly: "How long (in seconds) programs are told to remember an answer that came from your custom cloaking rules. Longer means fewer repeat lookups, but changes you make to a rule take longer to be noticed."),
        new("cloak_ptr", "", SettingValueType.Bool, "false", "Respond to PTR lookups for cloaked addresses.", "Filters & rules",
            Friendly: "Also answers reverse lookups — 'which name belongs to this address?' — for addresses you defined in cloaking rules. Leave off unless something on your network relies on those reverse answers."),

        // ---- Cache ----
        new("cache", "", SettingValueType.Bool, "true", "Enable the built-in DNS cache.", "Cache",
            Friendly: "Keeps recent DNS answers on this PC so repeat lookups are answered instantly without asking a server again. Leave on for faster browsing and fewer queries leaving your machine."),
        new("cache_size", "", SettingValueType.Long, "4096", "Maximum number of DNS response entries to cache.", "Cache",
            Friendly: "How many recent answers to keep at once. Bigger remembers more sites at the cost of a little memory; when full, answers that have not been needed recently are dropped to make room for new ones."),
        new("cache_min_ttl", "", SettingValueType.Long, "2400", "Minimum TTL in seconds for cached responses (example value).", "Cache",
            Friendly: "The shortest time (in seconds) an answer is remembered, even if the server asked for less. Raising it cuts repeat lookups, but a site that changes its address may take longer to reach you at the new one."),
        new("cache_max_ttl", "", SettingValueType.Long, "86400", "Maximum TTL in seconds for cached responses.", "Cache",
            Friendly: "The longest time (in seconds) an answer may be remembered, even if the server allowed more. The default of 86400 seconds is one day."),
        new("cache_neg_min_ttl", "", SettingValueType.Long, "60", "Minimum TTL in seconds for negative (NXDOMAIN/NODATA) cached responses.", "Cache",
            Friendly: "The shortest time (in seconds) a 'this name does not exist' answer is remembered. Keeping it short means a name that comes online shortly afterwards is noticed quickly."),
        new("cache_neg_max_ttl", "", SettingValueType.Long, "600", "Maximum TTL in seconds for negative (NXDOMAIN/NODATA) cached responses.", "Cache",
            Friendly: "The longest time (in seconds) a 'this name does not exist' answer is remembered. The default of 600 seconds is ten minutes."),

        // ---- Connectivity: [captive_portals] ----
        new("captive_portals.map_file", "captive_portals", SettingValueType.String, "unset", "Path to a file mapping captive portal hostnames to bypass addresses.", "Connectivity",
            Friendly: "A file listing the special check-in addresses that Wi-Fi sign-in pages (hotels, airports, cafes) depend on, with fixed answers for them. This lets such networks' login screens appear even before encrypted DNS is up and running."),

        // ---- Local DoH: [local_doh] ----
        new("local_doh.listen_addresses", "local_doh", SettingValueType.StringArray, "unset", "Local IP:port pairs for the built-in DoH server.", "Local DoH",
            Friendly: "Where on this PC the local DoH server accepts connections (IP and port). Leave unset to keep the local DoH server off."),
        new("local_doh.path", "local_doh", SettingValueType.String, "/dns-query", "HTTP path the local DoH server listens on.", "Local DoH",
            Friendly: "The web address path a browser must use to reach the local DoH server. Keep the default /dns-query unless the browser asks for something else."),
        new("local_doh.cert_file", "local_doh", SettingValueType.String, "unset", "Path to the TLS certificate file for the local DoH server.", "Local DoH",
            Friendly: "The certificate the local DoH server uses to prove its identity. The browser must trust that certificate (for most browsers that means this PC's certificate store) or it will refuse the connection."),
        new("local_doh.cert_key_file", "local_doh", SettingValueType.String, "unset", "Path to the TLS private key file for the local DoH server.", "Local DoH",
            Friendly: "The private key that pairs with the certificate above; the local DoH server needs both files to serve encrypted connections."),

        // ---- Logging: [query_log] ----
        new("query_log.file", "query_log", SettingValueType.String, "unset", "Path to the query log file.", "Logging",
            Friendly: "Where to save a record of every DNS lookup made through the proxy — effectively a browsing history for every device using it. Leave unset (the default) to keep no such record."),
        new("query_log.format", "query_log", SettingValueType.String, "tsv", "Query log format: tsv or ltsv.", "Logging",
            Friendly: "How each line of the lookup record is laid out: plain tab-separated columns, or columns with a label in front of each value. Only matters to tools that will read the file later."),
        new("query_log.ignored_qtypes", "query_log", SettingValueType.StringArray, "[]", "Query types to omit from the query log.", "Logging",
            Friendly: "Kinds of lookups to leave out of the record — useful for skipping routine technical queries that would otherwise clutter it."),

        // ---- Logging: [nx_log] ----
        new("nx_log.file", "nx_log", SettingValueType.String, "unset", "Path to the NXDOMAIN log file.", "Logging",
            Friendly: "Where to save a record of lookups for names that turned out not to exist. Useful for spotting typos or misbehaving software; leave unset to keep no such record."),
        new("nx_log.format", "nx_log", SettingValueType.String, "tsv", "NXDOMAIN log format: tsv or ltsv.", "Logging",
            Friendly: "How each line of that record is laid out: plain tab-separated columns, or columns with a label in front of each value."),

        // ---- Filters & rules: [blocked_names] ----
        new("blocked_names.blocked_names_file", "blocked_names", SettingValueType.String, "unset", "Path to the file containing blocked domain name rules.", "Filters & rules",
            Friendly: "Points to the text file listing domain names to block, one rule per line (wildcards allowed). Anything matching the list gets a blocked answer instead of the real one."),
        new("blocked_names.log_file", "blocked_names", SettingValueType.String, "unset", "Path to the log file for blocked name events.", "Filters & rules",
            Friendly: "If set, a line is written to this file every time a name is blocked, so you can see what the blocklist is catching. Leave unset to keep no such record."),
        new("blocked_names.log_format", "blocked_names", SettingValueType.String, "tsv", "Log format for blocked name events: tsv or ltsv.", "Filters & rules",
            Friendly: "Chooses the layout of each line in the log of blocked names: plain tab-separated columns (tsv) or fields with labels (ltsv). Only matters if another program will read the file."),

        // ---- Filters & rules: [blocked_ips] ----
        new("blocked_ips.blocked_ips_file", "blocked_ips", SettingValueType.String, "unset", "Path to the file containing blocked IP address rules.", "Filters & rules",
            Friendly: "Points to the text file listing server addresses to block. Any answer that would hand a program one of these addresses is stopped, even if the name itself is not on any blocklist."),
        new("blocked_ips.log_file", "blocked_ips", SettingValueType.String, "unset", "Path to the log file for blocked IP events.", "Filters & rules",
            Friendly: "If set, a line is written to this file every time an answer is stopped for containing a blocked address. Leave unset to keep no such record."),
        new("blocked_ips.log_format", "blocked_ips", SettingValueType.String, "tsv", "Log format for blocked IP events: tsv or ltsv.", "Filters & rules",
            Friendly: "Chooses the layout of each line in the log of blocked addresses: plain tab-separated columns (tsv) or fields with labels (ltsv). Only matters if another program will read the file."),

        // ---- Filters & rules: [allowed_names] ----
        new("allowed_names.allowed_names_file", "allowed_names", SettingValueType.String, "unset", "Path to the file containing allowed (whitelist) domain name rules.", "Filters & rules",
            Friendly: "Points to the text file listing names that must never be blocked. A match here wins over the name blocklist, so a trusted site keeps working even when a broad blocking rule would have caught it."),
        new("allowed_names.log_file", "allowed_names", SettingValueType.String, "unset", "Path to the log file for allowed name events.", "Filters & rules",
            Friendly: "If set, a line is written to this file every time a name matches this always-allow list, so you can see it at work. Leave unset to keep no such record."),
        new("allowed_names.log_format", "allowed_names", SettingValueType.String, "tsv", "Log format for allowed name events: tsv or ltsv.", "Filters & rules",
            Friendly: "Chooses the layout of each line in the log of allowed names: plain tab-separated columns (tsv) or fields with labels (ltsv). Only matters if another program will read the file."),

        // ---- Filters & rules: [allowed_ips] ----
        new("allowed_ips.allowed_ips_file", "allowed_ips", SettingValueType.String, "unset", "Path to the file containing allowed (whitelist) IP address rules.", "Filters & rules",
            Friendly: "Points to the text file listing server addresses that must never be blocked. A match here wins over the address blocklist, so answers containing these addresses always get through."),
        new("allowed_ips.log_file", "allowed_ips", SettingValueType.String, "unset", "Path to the log file for allowed IP events.", "Filters & rules",
            Friendly: "If set, a line is written to this file every time an answer matches this always-allow address list. Leave unset to keep no such record."),
        new("allowed_ips.log_format", "allowed_ips", SettingValueType.String, "tsv", "Log format for allowed IP events: tsv or ltsv.", "Filters & rules",
            Friendly: "Chooses the layout of each line in the log of allowed addresses: plain tab-separated columns (tsv) or fields with labels (ltsv). Only matters if another program will read the file."),

        // ---- Schedules: [schedules] (dynamic section — groups under its own name) ----
        // Whole dynamic table-of-tables sections: modeled as one Table entry where KeyPath == Section (no fixed sub-keys; the structured editor special-cases these).
        new("schedules", "schedules", SettingValueType.Table, "unset", "Named time-of-day schedules used by @schedule annotations in blocking rules.", "Schedules",
            Friendly: "Defines named weekly time windows — days of the week with start and end times — that name-blocking rules can refer to, so a rule only blocks during those hours. A blocked-names rule opts in by ending with @ followed by the window's name."),

        // ---- Sources: [sources] (dynamic section — groups under its own name) ----
        new("sources.urls", "sources", SettingValueType.StringArray, "unset", "Mirror URLs for downloading the resolver/relay list.", "Sources",
            Friendly: "The web addresses the proxy downloads its list of usable DNS servers or relays from. Giving several mirror addresses lets the download still succeed when one of them is unreachable."),
        new("sources.url", "sources", SettingValueType.String, "unset", "Legacy single-URL field for a source (use urls instead).", "Sources", Deprecated: true, ReplacedBy: "sources.urls",
            Friendly: "The old way of giving just one download address for a list. It has been replaced by the setting that takes a whole list of mirror addresses — put the address there instead."),
        new("sources.cache_file", "sources", SettingValueType.String, "unset", "Local path where the downloaded source list is cached.", "Sources",
            Friendly: "Where on this PC the proxy saves its copy of the downloaded server list, so it can still start when the network or the download is unavailable. Every source needs its own separate file."),
        new("sources.minisign_key", "sources", SettingValueType.String, "unset", "Minisign public key used to verify the downloaded source list.", "Sources",
            Friendly: "The public key the proxy uses to check the digital signature on the downloaded list, so a tampered or counterfeit list is rejected before it is ever used."),
        new("sources.format", "sources", SettingValueType.String, "unset", "Format of the source list (v2).", "Sources",
            Friendly: "Tells the proxy how the downloaded list file is laid out. The standard public lists use the v2 layout, and there is normally no reason to change this."),
        new("sources.refresh_delay", "sources", SettingValueType.Long, "73", "How often to refresh the source list in hours (the proxy clamps to 25..169).", "Sources",
            Friendly: "How many hours the proxy waits between fresh downloads of the list. Values are pulled into the range the proxy accepts — from 25 hours (roughly daily) to 169 hours (weekly)."),
        new("sources.cache_ttl", "sources", SettingValueType.Long, "168", "Maximum age in hours before the cached source list is considered stale.", "Sources",
            Friendly: "How old, in hours, the saved copy of the list may get before the proxy tries to download a fresh one at startup. If that download fails, the old copy is still used anyway."),
        new("sources.prefix", "sources", SettingValueType.String, "unset", "Optional prefix to prepend to server names from this source.", "Sources",
            Friendly: "Text added to the front of every server name that comes from this list, so names from different lists cannot collide. If you set it, any server names you type elsewhere must include this text too."),

        // ---- Connection: [broken_implementations] ----
        new("broken_implementations.fragments_blocked", "broken_implementations", SettingValueType.StringArray, "['cisco*','cleanbrowsing-*']", "Server name patterns known to block DNS fragmentation; the proxy avoids fragmented queries to these.", "Connection",
            Friendly: "Name patterns of servers known to mishandle DNS messages that arrive split into pieces; the proxy avoids anything that would need splitting when talking to them. The default list covers the known offenders and rarely needs editing."),
        new("broken_implementations.broken_query_padding", "broken_implementations", SettingValueType.StringArray, "unset", "Server name patterns with broken EDNS padding support (struct only, not in example).", "Connection",
            Friendly: "Name patterns of servers that mishandle the padding used to disguise how big your questions are; the proxy adjusts its behaviour for them. An advanced workaround that is almost never needed."),

        // ---- Certificates & TLS: [doh_client_x509_auth] (legacy alias: [tls_client_auth]) ----
        new("doh_client_x509_auth.creds", "doh_client_x509_auth", SettingValueType.TableArray, "unset", "Array of client certificate credentials for mutual TLS with DoH servers (server_name, client_cert, client_key, root_ca?).", "Certificates & TLS",
            Friendly: "Sign-in certificates the proxy presents to private DNS-over-HTTPS servers that require clients to prove who they are. Only needed for private servers; each entry names the server plus the certificate and key files to use."),

        // ---- Anonymized DNS: [anonymized_dns] ----
        // routes is an ARRAY of inline tables ([ { server_name=.., via=[..] } ]) — TableArray, not Table.
        // (Live VM run: typed Table, the helper's ConfigValidator rejected every AnonDNS save as invalid.)
        new("anonymized_dns.routes", "anonymized_dns", SettingValueType.TableArray, "unset", "Route map: each entry specifies a server_name (or '*') and via[] relays to use.", "Anonymized DNS",
            Friendly: "Rules that send your DNS questions through a relay on the way to the chosen server, so no single party on that route sees both who you are and what you asked. Each rule names one server (or all of them) and the relays to pass through; servers without a working route are still contacted directly unless the skip setting below is on."),
        new("anonymized_dns.skip_incompatible", "anonymized_dns", SettingValueType.Bool, "false", "Skip resolvers incompatible with anonymization rather than using them directly.", "Anonymized DNS",
            Friendly: "When a chosen server cannot work through a relay, skip that server entirely instead of quietly contacting it directly. Turning this on keeps your address from leaking to such servers, at the cost of fewer usable servers."),
        new("anonymized_dns.direct_cert_fallback", "anonymized_dns", SettingValueType.Bool, "true", "Fall back to a direct connection when retrieving certificates if all relays fail. (code default true; example default false)", "Anonymized DNS",
            Friendly: "If a server's identity data cannot be fetched through any relay, allow one direct connection just to fetch it; your actual DNS questions still travel through the relays. Turning this off is stricter but can leave some servers unusable."),

        // ---- Connectivity: [dns64] ----
        new("dns64.prefix", "dns64", SettingValueType.StringArray, "unset", "NAT64 prefix(es) to synthesize AAAA records (e.g. 64:ff9b::/96).", "Connectivity",
            Friendly: "For networks that only speak the newer IPv6 addressing: the special address block used to build IPv6 answers for sites that only exist at older IPv4 addresses. Leave unset on ordinary home networks."),
        new("dns64.resolver", "dns64", SettingValueType.StringArray, "unset", "Resolvers to use for discovering the NAT64 prefix automatically.", "Connectivity",
            Friendly: "Servers the proxy can ask to discover that special IPv6 translation prefix automatically instead of entering one by hand. If a prefix is also set manually, the manual one wins."),

        // ---- Logging: [ip_encryption] (obfuscates client IPs in query logs) ----
        new("ip_encryption.algorithm", "ip_encryption", SettingValueType.String, "none", "IPCrypt algorithm: none, ipcrypt-deterministic, ipcrypt-nd, ipcrypt-ndx, or ipcrypt-pfx.", "Logging",
            Friendly: "Scrambles the addresses of the computers making requests before they are written to the lookup logs, so the logs no longer show exactly which device asked. Pick 'none' to log addresses as they are; every other choice scrambles them and needs a matching secret key."),
        new("ip_encryption.key", "ip_encryption", SettingValueType.String, "unset", "Hex-encoded encryption key for IPCrypt client IP obfuscation in query logs.", "Logging",
            Friendly: "The secret key used to scramble device addresses in the logs, written as a string of hex characters (digits and letters a to f). Required whenever a scrambling method is selected; some methods need a 16-byte key and others a 32-byte key."),

        // ---- Monitoring: [monitoring_ui] ----
        new("monitoring_ui.enabled", "monitoring_ui", SettingValueType.Bool, "false", "Enable the built-in web-based monitoring UI.", "Monitoring",
            Friendly: "Turns on a small live status page, served by the proxy itself, that you can open in a browser to watch DNS activity. Leaving it off means one less thing running and listening on this PC."),
        new("monitoring_ui.listen_address", "monitoring_ui", SettingValueType.String, "127.0.0.1:8080", "IP:port for the monitoring UI to listen on.", "Monitoring",
            Friendly: "The IP address and port where the status page answers a browser. Keep the 127.0.0.1 default so only this PC can open it; other addresses can expose the page to your whole network."),
        new("monitoring_ui.username", "monitoring_ui", SettingValueType.String, "admin", "Username for monitoring UI HTTP basic authentication.", "Monitoring",
            Friendly: "The sign-in name a browser must enter before the status page opens. Leaving both this and the password empty removes the sign-in step entirely."),
        new("monitoring_ui.password", "monitoring_ui", SettingValueType.String, "changeme", "Password for monitoring UI HTTP basic authentication.", "Monitoring",
            Friendly: "The password that guards the status page. Change it from the shipped default, because anyone who can reach the page could otherwise sign straight in."),
        new("monitoring_ui.tls_certificate", "monitoring_ui", SettingValueType.String, "unset", "Path to the TLS certificate file for the monitoring UI.", "Monitoring",
            Friendly: "A certificate file that lets the status page be served over an encrypted connection (https). Left unset, the page is served unencrypted, which is acceptable while only this PC can reach it."),
        new("monitoring_ui.tls_key", "monitoring_ui", SettingValueType.String, "unset", "Path to the TLS private key file for the monitoring UI.", "Monitoring",
            Friendly: "The private key that pairs with the certificate above; the status page needs both files before it can serve encrypted connections."),
        new("monitoring_ui.enable_query_log", "monitoring_ui", SettingValueType.Bool, "false", "Enable query logging in the monitoring UI (code default false; example default true).", "Monitoring",
            Friendly: "Shows a list of recent DNS lookups on the status page. Anyone who can open that page then sees what was looked up, so weigh the convenience against the privacy cost."),
        new("monitoring_ui.privacy_level", "monitoring_ui", SettingValueType.Long, "2", "Query log privacy level: 0=all, 1=anonymize IPs, 2=aggregate only (code default 2; example default 1).", "Monitoring",
            Friendly: "How much lookup detail the status page reveals: 0 shows everything including which device asked, 1 hides the device addresses, and 2 shows only overall totals. Higher numbers give more privacy."),
        new("monitoring_ui.max_query_log_entries", "monitoring_ui", SettingValueType.Long, "100", "Maximum number of query log entries kept in the monitoring UI.", "Monitoring",
            Friendly: "How many recent lookups the status page keeps in memory at once; the oldest entries are dropped as new ones arrive."),
        new("monitoring_ui.max_memory_mb", "monitoring_ui", SettingValueType.Long, "1", "Maximum memory in MB the monitoring UI may use for log storage.", "Monitoring",
            Friendly: "A ceiling, in megabytes of memory, for the status page's stored lookup history; older entries are cleared automatically once the limit is reached."),
        new("monitoring_ui.prometheus_enabled", "monitoring_ui", SettingValueType.Bool, "false", "Expose a Prometheus metrics endpoint from the monitoring UI.", "Monitoring",
            Friendly: "Also publishes raw counters (queries answered, timings and so on) in a machine-readable form that monitoring software such as Prometheus can collect. Only useful if you actually run such software."),
        new("monitoring_ui.prometheus_path", "monitoring_ui", SettingValueType.String, "/metrics", "HTTP path for the Prometheus metrics endpoint.", "Monitoring",
            Friendly: "The web address path where those machine-readable counters are published. The default of /metrics is what most collection tools expect."),

        // ---- Static servers: [static] (dynamic section — groups under its own name) ----
        // Whole dynamic table-of-tables sections: modeled as one Table entry where KeyPath == Section (no fixed sub-keys; the structured editor special-cases these).
        new("static", "static", SettingValueType.Table, "unset", "Inline server definitions: each [static.<name>] entry contains a stamp (sdns://...).", "Static servers",
            Friendly: "Lets you add DNS servers by hand instead of relying on the downloaded server lists. Each entry needs the server's stamp: a single piece of text starting with sdns:// that packs the address and connection details into one line."),

        // ---- Deprecated / legacy (still parsed; warn + migrate — grouped beside their replacements) ----
        new("fallback_resolvers", "", SettingValueType.StringArray, "deprecated", "Legacy alias for bootstrap_resolvers.", "Connectivity", Deprecated: true, ReplacedBy: "bootstrap_resolvers",
            Friendly: "This is the old name for the list of plain startup DNS servers, kept only so older config files still work. It has been replaced by bootstrap_resolvers — set that instead."),
        new("cache_neg_ttl", "", SettingValueType.Long, "deprecated", "Legacy single-value negative TTL; replaced by cache_neg_min_ttl and cache_neg_max_ttl.", "Cache", Deprecated: true, ReplacedBy: "cache_neg_min_ttl",
            Friendly: "This is the old name for the single 'remember that a name does not exist' time, kept only for older configuration files. Use the newer pair instead: cache_neg_min_ttl and cache_neg_max_ttl."),
    };

    public static IReadOnlyList<SettingDescriptor> All => _all;

    private static readonly Dictionary<string, SettingDescriptor> _byPath =
        _all.ToDictionary(d => d.KeyPath, System.StringComparer.Ordinal);

    public static SettingDescriptor? Find(string keyPath) =>
        _byPath.TryGetValue(keyPath, out var d) ? d : null;

    // Cached once, mirroring _byPath - ConfigValidator probes Sections per top-level key.
    private static readonly string[] _sections =
        _all.Where(d => d.Section.Length > 0).Select(d => d.Section).Distinct().ToArray();

    public static IReadOnlyList<string> Sections => _sections;
}
