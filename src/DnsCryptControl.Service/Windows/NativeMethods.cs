using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using DnsCryptControl.Ipc.Security;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// The isolated, audited Windows P/Invoke surface for caller verification: resolve the
/// connected pipe client's image, validate its Authenticode signature with WinVerifyTrust,
/// and extract the signer thumbprint. This is the only file with native interop in Phase 2.
///
/// Revocation note: fdwRevocationChecks is set to WTD_REVOKE_NONE. This is a deliberate
/// offline-tradeoff: online revocation checks (WTD_REVOKE_WHOLECHAIN) introduce a network
/// dependency that can stall the privileged Windows service helper in air-gapped or restricted
/// environments. The allow-list (SignerAllowList) is the primary trust control; operators
/// must rotate the allow-list if a signing certificate is compromised.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class NativeMethods
{
    private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    // ---- kernel32 ----
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(nint pipe, out uint clientProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint OpenProcess(int access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageName(nint process, int flags, [Out] char[] exeName, ref int size);

    // ---- wintrust ----
    [LibraryImport("wintrust.dll", SetLastError = false)]
    private static partial int WinVerifyTrust(nint hwnd, ref Guid action, nint data);

    // ERROR_INSUFFICIENT_BUFFER (122): the path buffer was too small; regrow and retry.
    private const int ERROR_INSUFFICIENT_BUFFER = 122;

    // Hard upper cap for buffer regrow: NT path limit is 32767 UTF-16 chars.
    private const int MaxPathBuffer = 32767;

    /// <summary>Resolves the connected client's PID + image path; null on any failure.</summary>
    public static CallerIdentity? ResolveClient(SafePipeHandle pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (!GetNamedPipeClientProcessId(pipe.DangerousGetHandle(), out var pid)) return null;

        var process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == nint.Zero) return null;
        try
        {
            // Start with a 1024-char buffer and regrow (up to 32767) on
            // ERROR_INSUFFICIENT_BUFFER (122) so callers installed at very deep
            // paths are not wrongly denied. Fail closed (return null) if the path
            // still cannot be read after two regrow attempts.
            var buffer = new char[1024];
            for (var attempt = 0; attempt < 3; attempt++)
            {
                var size = buffer.Length;
                if (QueryFullProcessImageName(process, 0, buffer, ref size))
                {
                    var path = new string(buffer, 0, size);
                    return string.IsNullOrEmpty(path) ? null : new CallerIdentity((int)pid, path);
                }

                if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
                    return null; // any other failure: fail closed immediately

                var next = buffer.Length * 2;
                if (next > MaxPathBuffer) return null; // already at cap: fail closed
                buffer = new char[next];
            }

            return null; // exhausted retries: fail closed
        }
        finally
        {
            CloseHandle(process);
        }
    }

    /// <summary>True if the file has a valid Authenticode signature (WinVerifyTrust ==
    /// ERROR_SUCCESS). Validity ONLY — signer identity is extracted separately.</summary>
    public static bool VerifyAuthenticode(string imagePath)
    {
        if (string.IsNullOrEmpty(imagePath)) return false;

        const uint WTD_UI_NONE = 2;
        const uint WTD_REVOKE_NONE = 0;        // headless service: no online revocation dependency (see file-level doc)
        const uint WTD_CHOICE_FILE = 1;
        const uint WTD_STATEACTION_VERIFY = 1;
        const uint WTD_STATEACTION_CLOSE = 2;
        const uint WTD_SAFER_FLAG = 0x100;

        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = imagePath,
            hFile = nint.Zero,
            pgKnownSubject = nint.Zero,
        };
        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        var dataPtr = nint.Zero;
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_SAFER_FLAG,
            };
            dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(data, dataPtr, false);

            var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            var result = WinVerifyTrust(nint.Zero, ref action, dataPtr);

            // Always close the WinVerifyTrust state, regardless of the verify result,
            // to free internal provider state (WINTRUST_DATA.hWVTStateData).
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(data, dataPtr, true);
            WinVerifyTrust(nint.Zero, ref action, dataPtr);

            return result == 0; // ERROR_SUCCESS
        }
        finally
        {
            if (dataPtr != nint.Zero) Marshal.FreeHGlobal(dataPtr);
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    /// <summary>Extracts the embedded Authenticode signer certificate's thumbprint from a
    /// validly-signed file. Returns null if no signature can be read.
    ///
    /// DELIBERATE SAFE USE: CreateFromSignedFile is used here ONLY to READ the signer identity
    /// (thumbprint) AFTER VerifyAuthenticode (WinVerifyTrust) has already proven the file is
    /// validly signed. This is NOT the documented Authenticode pitfall. The pitfall is using
    /// CreateFromSignedFile + .Verify() to DECIDE validity — which reports tampered/unsigned
    /// files as signed. We never call .Verify(); WinVerifyTrust is the sole validity oracle.
    /// Do not "fix" this by replacing CreateFromSignedFile — that would break signer extraction.
    /// </summary>
    public static string? ExtractSignerThumbprint(string imagePath)
    {
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(imagePath));
            return cert.Thumbprint;
        }
        catch (System.Security.Cryptography.CryptographicException) { return null; }
        catch (ArgumentException) { return null; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public nint hFile;
        public nint pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public nint pPolicyCallbackData;
        public nint pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public nint pFile;
        public uint dwStateAction;
        public nint hWVTStateData;
        public nint pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public nint pSignatureSettings;
    }
}
