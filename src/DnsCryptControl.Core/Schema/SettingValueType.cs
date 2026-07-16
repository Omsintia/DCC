namespace DnsCryptControl.Core.Schema;

// TableArray = an array of inline tables (e.g. anonymized_dns.routes = [ { server_name=.., via=[..] } ]),
// modeled by Tomlyn as a TomlArray, or the [[section.key]] array-of-tables form modeled as a TomlTableArray.
// Distinct from Table (a single [table]). Added in Phase 5c after the live VM run found the helper's
// ConfigValidator rejecting every AnonDNS routes write (typed Table, but the value is a TomlArray).
public enum SettingValueType { Bool, Long, Float, String, StringArray, Table, TableArray }
