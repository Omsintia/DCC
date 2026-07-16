using System;
using DnsCryptControl.Ipc.Security;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

[Trait("Category", "ManualIntegration")]
public class WinVerifyTrustCallerVerifierTests
{
    [Fact]
    public void SignedWindowsBinary_passesValidity_butFailsUnlessOnAllowList()
    {
        if (!OperatingSystem.IsWindows()) return;
        // notepad.exe is Microsoft-signed: WinVerifyTrust validity should be TRUE,
        // but its signer is NOT on our allow-list, so IsTrusted must be FALSE.
        var verifier = new WinVerifyTrustCallerVerifier(new SignerAllowList(new[] { "OUR_OWN_THUMBPRINT_PLACEHOLDER" }));
        var caller = new CallerIdentity(0, Environment.SystemDirectory + "\\notepad.exe");
        Assert.False(verifier.IsTrusted(caller)); // valid signature, wrong signer
    }

    [Fact]
    public void UnsignedOrMissingFile_isNotTrusted()
    {
        if (!OperatingSystem.IsWindows()) return;
        var verifier = new WinVerifyTrustCallerVerifier(new SignerAllowList(new[] { "AABB" }));
        Assert.False(verifier.IsTrusted(new CallerIdentity(0, @"C:\does\not\exist.exe")));
    }

    // The POSITIVE real-crypto branch (valid signature AND on the allow-list => trusted) cannot be
    // proven hermetically — it needs a real signed binary + the OS trust chain. The two tests below
    // are armed ONLY by tools/manual-integration/Invoke-ManualIntegration.ps1 -SelfSignForCallerGate,
    // which (inside the throwaway VM) generates a trusted self-signed code-signing cert, signs a
    // binary with it, and sets DNSCC_SELFSIGN_EXE + DNSCC_SELFSIGN_THUMBPRINT. They skip (and so do
    // not assert) whenever those env vars are absent, i.e. in every normal/CI/headless run.

    [Fact]
    public void OurSignedBinary_onAllowList_isTrusted()
    {
        if (!OperatingSystem.IsWindows()) return;
        var exe = Environment.GetEnvironmentVariable("DNSCC_SELFSIGN_EXE");
        var thumbprint = Environment.GetEnvironmentVariable("DNSCC_SELFSIGN_THUMBPRINT");
        if (string.IsNullOrEmpty(exe) || string.IsNullOrEmpty(thumbprint) || !System.IO.File.Exists(exe))
            return; // self-sign step not run => skip

        var verifier = new WinVerifyTrustCallerVerifier(new SignerAllowList(new[] { thumbprint }));
        Assert.True(verifier.IsTrusted(new CallerIdentity(0, exe))); // valid signature AND on allow-list => trusted
    }

    [Fact]
    public void OurSignedBinary_notOnAllowList_isNotTrusted()
    {
        if (!OperatingSystem.IsWindows()) return;
        var exe = Environment.GetEnvironmentVariable("DNSCC_SELFSIGN_EXE");
        var thumbprint = Environment.GetEnvironmentVariable("DNSCC_SELFSIGN_THUMBPRINT");
        if (string.IsNullOrEmpty(exe) || string.IsNullOrEmpty(thumbprint) || !System.IO.File.Exists(exe))
            return; // self-sign step not run => skip

        // Same validly-signed binary, but an allow-list WITHOUT its thumbprint => valid signature, wrong signer.
        var verifier = new WinVerifyTrustCallerVerifier(
            new SignerAllowList(new[] { "0000000000000000000000000000000000000000" }));
        Assert.False(verifier.IsTrusted(new CallerIdentity(0, exe)));
    }
}
