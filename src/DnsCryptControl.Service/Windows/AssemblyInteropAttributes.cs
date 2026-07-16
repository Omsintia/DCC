// One assembly-level search-path declaration covers EVERY p/invoke (LibraryImport- and
// DllImport-generated) in the Service assembly and clears CA5392/CA5393 globally. System32
// is on CA5393's SAFE list (iphlpapi/kernel32/wintrust are KnownDLLs in System32).
[assembly: System.Runtime.InteropServices.DefaultDllImportSearchPaths(
    System.Runtime.InteropServices.DllImportSearchPath.System32)]
