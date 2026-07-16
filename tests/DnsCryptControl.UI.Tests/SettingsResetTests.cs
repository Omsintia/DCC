using System;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.Tests.Fakes;
using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// G/E: the two-tier reset. Soft = <c>DisableProtection</c> only. Full = soft FIRST, then
/// <c>UninstallProxyService</c> — gated on a typed "REMOVE" confirmation AND a confirmed-successful soft
/// reset. A failed OR UNKNOWN (null) soft reset must NEVER reach the uninstall (fail-closed teardown
/// ordering — never remove the service while DNS might still point at the proxy).
/// </summary>
public sealed class SettingsResetTests
{
    private sealed class SyncDispatcher : IUiDispatcher
    {
        public void Post(Action action) => action();
    }

    private sealed class NullStore : IUiStateStore
    {
        public UiState Load() => new();
        public void Save(UiState state) { }
    }

    private sealed class NullStartup : IStartupRegistration
    {
        public bool IsRegistered() => false;
        public bool Register() => true;
        public bool Unregister() => true;
    }

    private sealed class NullTheme : IThemeApplier
    {
        public void Apply(string? theme) { }
        public void AttachWindow(object window) { }
        public void Prime() { }
    }

    private sealed class NullIntegrity : IExeIntegrityReader
    {
        public ExeIntegrityInfo Read(string exePath) => new(exePath, null, null, false);
    }

    private static SettingsViewModel MakeSut(FakeHelperClient helper) =>
        new(new NullStore(), new NullStartup(), new NullTheme(), new NullIntegrity(), helper, new SyncDispatcher());

    [Fact]
    public async Task SoftReset_callsDisableProtection_only()
    {
        var helper = new FakeHelperClient();
        var vm = MakeSut(helper);

        await vm.SoftResetCommand.ExecuteAsync(null);

        Assert.Equal(1, helper.DisableCalls);
        Assert.Equal(0, helper.UninstallProxyServiceCalls);
        Assert.Empty(helper.SetBrowserDohCalls);
    }

    [Fact]
    public async Task FullReset_callsDisableThenUninstall_inOrder()
    {
        var helper = new FakeHelperClient();
        var vm = MakeSut(helper);
        vm.RemoveConfirmText = "REMOVE";

        await vm.RemoveProxyCommand.ExecuteAsync(null);

        Assert.Equal(new[] { "Disable", "Uninstall" }, helper.CallOrder);
    }

    [Fact]
    public async Task FullReset_softResetFails_doesNotUninstall()
    {
        var helper = new FakeHelperClient
        {
            DisableHandler = _ => Task.FromResult<Result<ProtectionResponse>?>(
                Result<ProtectionResponse>.Fail(IpcErrorCode.OperationFailed, "teardown failed")),
        };
        var vm = MakeSut(helper);
        vm.RemoveConfirmText = "REMOVE";

        await vm.RemoveProxyCommand.ExecuteAsync(null);

        Assert.Equal(1, helper.DisableCalls);
        Assert.Equal(0, helper.UninstallProxyServiceCalls);
    }

    [Fact]
    public async Task FullReset_softResetNull_doesNotUninstall()
    {
        var helper = new FakeHelperClient
        {
            DisableHandler = _ => Task.FromResult<Result<ProtectionResponse>?>(null),
        };
        var vm = MakeSut(helper);
        vm.RemoveConfirmText = "REMOVE";

        await vm.RemoveProxyCommand.ExecuteAsync(null);

        Assert.Equal(0, helper.UninstallProxyServiceCalls);
    }

    [Fact]
    public async Task FullReset_bodyInvokedWithoutTypedConfirm_doesNothing()
    {
        // Belt-and-suspenders for the irreversible uninstall: even when the command BODY is invoked
        // directly (keybinding / UI-Automation / programmatic — paths that bypass CanExecute's button
        // gating), the missing "REMOVE" confirmation must block BOTH the disable and the uninstall.
        var helper = new FakeHelperClient();
        var vm = MakeSut(helper);
        // RemoveConfirmText is left empty.

        await vm.RemoveProxyCommand.ExecuteAsync(null);

        Assert.Equal(0, helper.DisableCalls);
        Assert.Equal(0, helper.UninstallProxyServiceCalls);
    }

    [Fact]
    public void FullReset_withoutExactTypedConfirm_cannotExecute()
    {
        var vm = MakeSut(new FakeHelperClient());

        Assert.False(vm.RemoveProxyCommand.CanExecute(null));

        vm.RemoveConfirmText = "remove"; // wrong case — must be exact
        Assert.False(vm.RemoveProxyCommand.CanExecute(null));

        vm.RemoveConfirmText = "REMOVE";
        Assert.True(vm.RemoveProxyCommand.CanExecute(null));
    }

    [Fact]
    public async Task SoftReset_nullReply_isNotTreatedAsSuccess()
    {
        var helper = new FakeHelperClient
        {
            DisableHandler = _ => Task.FromResult<Result<ProtectionResponse>?>(null),
        };
        var vm = MakeSut(helper);

        await vm.SoftResetCommand.ExecuteAsync(null);

        Assert.NotNull(vm.ResetStatus);
        Assert.Contains("Couldn't confirm", vm.ResetStatus);
    }
}
