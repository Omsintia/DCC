using System;
using System.Collections.Generic;
using System.Linq;
using CsCheck;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch;
using DnsCryptControl.Ipc.Serialization;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz properties for the privileged request router (<see cref="CommandDispatcher.Dispatch"/>) - the
/// single funnel every untrusted IPC frame passes through in the LocalSystem helper. The headline
/// invariants: (1) TOTALITY - Dispatch never throws for ANY request string, and always returns a
/// non-null, deserializable Result envelope; (2) FAIL-CLOSED ROUTING - an undefined Command number
/// (!Enum.IsDefined) or an unmapped verb yields an Unsupported error, never a wrong handler;
/// (3) FAULT CONTAINMENT - a handler that throws is contained as an OperationFailed result so a bad
/// request can never crash the SYSTEM helper; (4) FROZEN ENUM WIRE - the numeric IpcCommandType /
/// IpcErrorCode assignments are pinned so a mid-enum insertion (which would silently renumber every
/// later verb/code on the wire) is caught.
///
/// Scope note (net8.0 harness): the real <c>HandlerRegistry.Build</c> needs DnsCryptControl.Platform
/// seam interfaces that are out of scope at net8.0 and NOT referenced here, so this file builds the
/// dispatcher from Core+Ipc-only fake handlers (echo + fault-injecting). That is sufficient to prove
/// every dispatcher-level invariant above; the real-registry wiring is covered by the example-based
/// AdversarialBoundaryTests in DnsCryptControl.Ipc.Tests.
/// See the fuzzing design notes.
/// </summary>
public class CommandDispatcherProperties
{
    // A dispatcher with a benign echo handler for every defined verb: exercises the deserialize
    // guard, the Enum.IsDefined / verb-routing guard, and the happy dispatch path.
    private static readonly CommandDispatcher EchoDispatcher =
        new(Enum.GetValues<IpcCommandType>().Select(c => (ICommandHandler)new EchoHandler(c)));

    // Same coverage, but GetStatus is served by a handler that always throws: exercises the
    // catch-all fault-containment path (a handler fault must never escape Dispatch).
    private static readonly CommandDispatcher FaultDispatcher =
        new(Enum.GetValues<IpcCommandType>()
            .Where(c => c != IpcCommandType.GetStatus)
            .Select(c => (ICommandHandler)new EchoHandler(c))
            .Append(new AlwaysThrowsHandler(IpcCommandType.GetStatus)));

    // Hoisted so no property builds an inline constant array (CA1861). NOTE: these must stay OUTSIDE
    // the defined enum range — 19 left this list when VerifyResolution (protocol v4) claimed it.
    private static readonly int[] UndefinedCommandNumbers = { -1, 20, 21, 99, 999, int.MaxValue, int.MinValue };

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Dispatch_never_throws_on_arbitrary_text() =>
        // Mostly non-JSON text: exercises the deserialize fail-closed guard (malformed -> ValidationFailed).
        Gen.String.Sample(s => NeverThrowsWithResult(EchoDispatcher, s), iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Dispatch_never_throws_on_structured_request_frames() =>
        // Well-formed {"Command":n,"PayloadJson":p} frames spanning the full command-number space
        // (defined AND undefined) crossed with structured/garbage payloads: this is the routing core
        // - the code that must fail closed on an undefined number and never mis-route a verb.
        RequestFrameGen.Sample(frame => NeverThrowsWithResult(EchoDispatcher, frame), iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Dispatch_undefined_command_number_always_routes_to_Unsupported() =>
        // Any command number outside the enum must be rejected as Unsupported (never dispatched to a
        // handler that happens to share the integer). Fails closed, never mis-routes.
        Gen.Int.Where(n => !Enum.IsDefined(typeof(IpcCommandType), n))
            .Sample(n =>
            {
                var frame = $"{{\"Command\":{n},\"PayloadJson\":null}}";
                var result = DispatchAndDeserialize(EchoDispatcher, frame);
                return result is { Success: false, Code: IpcErrorCode.Unsupported };
            }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Dispatch_defined_verb_never_throws_and_returns_deserializable_result() =>
        // Every DEFINED verb, crossed with structured/garbage/null payloads, must route and return a
        // non-null deserializable Result (the echo handler always succeeds; the point is totality +
        // a valid envelope on the mapped path).
        DefinedVerbFrameGen.Sample(frame =>
        {
            var result = DispatchAndDeserialize(EchoDispatcher, frame);
            return result is not null;
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Dispatch_contains_a_faulting_handler_as_OperationFailed() =>
        // A handler that throws for the routed verb must be contained as OperationFailed - the helper
        // must survive any bad request. Any OTHER (echo) verb still succeeds; an undefined number is
        // Unsupported. The invariant: Dispatch returns a valid Result and NEVER throws.
        RequestFrameGen.Sample(frame => NeverThrowsWithResult(FaultDispatcher, frame), iter: Fuzz.Iter);

    // ---- Concrete regression anchors ----

    [Theory]
    [InlineData("}{ not json")]                       // garbage -> ValidationFailed
    [InlineData("")]                                  // empty -> ValidationFailed
    [InlineData("null")]                              // JSON null request -> ValidationFailed
    [InlineData("{\"Command\":0,\"PayloadJson\":null}")] // valid GetStatus frame -> echo Ok
    public void Dispatch_known_frames_never_throw(string frame) =>
        Assert.True(NeverThrowsWithResult(EchoDispatcher, frame));

    [Theory]
    [InlineData(999)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public void Dispatch_out_of_range_command_is_Unsupported(int command)
    {
        var result = DispatchAndDeserialize(EchoDispatcher, $"{{\"Command\":{command},\"PayloadJson\":null}}");
        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.Unsupported, result.Code);
    }

    [Fact]
    public void Dispatch_faulting_handler_yields_OperationFailed()
    {
        var frame = "{\"Command\":0,\"PayloadJson\":null}"; // GetStatus -> AlwaysThrowsHandler
        var result = DispatchAndDeserialize(FaultDispatcher, frame);
        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.OperationFailed, result.Code);
    }

    // ---- Frozen-wire golden snapshots: a mid-enum insertion renumbers the wire and is caught here. ----

    [Theory]
    [InlineData(IpcCommandType.GetStatus, 0)]
    [InlineData(IpcCommandType.InstallProxyService, 1)]
    [InlineData(IpcCommandType.UninstallProxyService, 2)]
    [InlineData(IpcCommandType.StartProxy, 3)]
    [InlineData(IpcCommandType.StopProxy, 4)]
    [InlineData(IpcCommandType.RestartProxy, 5)]
    [InlineData(IpcCommandType.WriteConfig, 6)]
    [InlineData(IpcCommandType.WriteRuleFile, 7)]
    [InlineData(IpcCommandType.ApplyDnsToAllAdapters, 8)]
    [InlineData(IpcCommandType.RestoreDns, 9)]
    [InlineData(IpcCommandType.SetLeakMitigations, 10)]
    [InlineData(IpcCommandType.SetKillSwitch, 11)]
    [InlineData(IpcCommandType.SetBrowserDohPolicy, 12)]
    [InlineData(IpcCommandType.FlushDnsCache, 13)]
    [InlineData(IpcCommandType.VerifyAndInstallBinary, 14)]
    [InlineData(IpcCommandType.RunDiagnostics, 15)]
    [InlineData(IpcCommandType.EnableProtection, 16)]
    [InlineData(IpcCommandType.DisableProtection, 17)]
    [InlineData(IpcCommandType.PlaceOdohCache, 18)]
    [InlineData(IpcCommandType.VerifyResolution, 19)]
    public void IpcCommandType_numeric_values_are_frozen(IpcCommandType verb, int wireValue) =>
        Assert.Equal(wireValue, (int)verb);

    [Fact]
    public void IpcCommandType_has_exactly_the_snapshotted_membership() =>
        // If a member is added/removed the count changes here even if no InlineData row does - a tripwire
        // that forces the golden [Theory] above to be updated in lockstep with the wire contract.
        Assert.Equal(20, Enum.GetValues<IpcCommandType>().Length);

    [Theory]
    [InlineData(IpcErrorCode.None, 0)]
    [InlineData(IpcErrorCode.ValidationFailed, 1)]
    [InlineData(IpcErrorCode.NotAuthorized, 2)]
    [InlineData(IpcErrorCode.NotFound, 3)]
    [InlineData(IpcErrorCode.OperationFailed, 4)]
    [InlineData(IpcErrorCode.Unsupported, 5)]
    [InlineData(IpcErrorCode.Conflict, 6)]
    public void IpcErrorCode_numeric_values_are_frozen(IpcErrorCode code, int wireValue) =>
        Assert.Equal(wireValue, (int)code);

    [Fact]
    public void IpcErrorCode_has_exactly_the_snapshotted_membership() =>
        Assert.Equal(7, Enum.GetValues<IpcErrorCode>().Length);

    // ---- Oracles ----

    /// <summary>Totality + envelope oracle: Dispatch must not throw for any input, and its output must
    /// deserialize to a non-null Result. A throw fails the property (that is how the never-throw
    /// invariant is asserted); a null / non-deserializable envelope also fails it.</summary>
    private static bool NeverThrowsWithResult(CommandDispatcher dispatcher, string request) =>
        DispatchAndDeserialize(dispatcher, request) is not null;

    private static Result? DispatchAndDeserialize(CommandDispatcher dispatcher, string request) =>
        IpcSerializer.DeserializePayload<Result>(dispatcher.Dispatch(request));

    // ---- Generators ----
    // Composed generators are expression-bodied properties (evaluated on access) so there is no
    // static-field initialization-order nullability concern when one generator references another.

    private static Gen<int> DefinedCommandNumberGen =>
        Gen.Int[0, Enum.GetValues<IpcCommandType>().Length - 1];

    private static Gen<int> CommandNumberGen =>
        Gen.OneOf(DefinedCommandNumberGen, Gen.OneOfConst(UndefinedCommandNumbers));

    // PayloadJson slot: a JSON null, a JSON-escaped structured inner payload, or JSON-escaped garbage.
    private static Gen<string> PayloadJsonGen =>
        Gen.OneOf(
            Gen.Const("null"),
            Gen.String.Select(s => JsonQuote("{\"TomlText\":" + JsonQuote(s) + ",\"BaseSha256\":\"\"}")),
            Gen.String.Select(JsonQuote));

    /// <summary>A structured request frame over the FULL command-number space (defined verbs AND the
    /// hoisted undefined numbers) crossed with a structured object payload, garbage text, or JSON null.
    /// PayloadJson is the wire-shape inner string, JSON-escaped so the outer frame stays well-formed.</summary>
    private static Gen<string> RequestFrameGen =>
        Gen.Select(CommandNumberGen, PayloadJsonGen,
            (command, payload) => $"{{\"Command\":{command},\"PayloadJson\":{payload}}}");

    /// <summary>Structured frames restricted to DEFINED verbs (so the mapped-handler path is exercised),
    /// crossed with the same payload variety.</summary>
    private static Gen<string> DefinedVerbFrameGen =>
        Gen.Select(DefinedCommandNumberGen, PayloadJsonGen,
            (command, payload) => $"{{\"Command\":{command},\"PayloadJson\":{payload}}}");

    /// <summary>Minimal JSON string encoder for embedding an arbitrary (possibly non-ASCII, control-char)
    /// generated string as a JSON string literal, so the outer frame is always well-formed and the fuzz
    /// stresses the deserializer's content path rather than trivially failing the outer parse.</summary>
    private static string JsonQuote(string s)
    {
        var sb = new System.Text.StringBuilder(s.Length + 2);
        sb.Append('"');
        foreach (var ch in s)
        {
            switch (ch)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (ch < ' ')
                        sb.Append("\\u").Append(((int)ch).ToString("x4", System.Globalization.CultureInfo.InvariantCulture));
                    else
                        sb.Append(ch);
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }

    // ---- Fake handlers (Core+Ipc only; no Platform seam needed) ----

    private sealed class EchoHandler : ICommandHandler
    {
        public EchoHandler(IpcCommandType command) => Command = command;
        public IpcCommandType Command { get; }
        public string Handle(IpcRequest request) => IpcSerializer.SerializePayload(Result.Ok());
    }

    private sealed class AlwaysThrowsHandler : ICommandHandler
    {
        public AlwaysThrowsHandler(IpcCommandType command) => Command = command;
        public IpcCommandType Command { get; }
        public string Handle(IpcRequest request) => throw new InvalidOperationException("injected handler fault");
    }
}
