using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;

namespace XINSkan.UnitTests.Core;

public class InvestigationRunnerTests
{
    private readonly ManualTimeProvider _time = new(Samples.T0);
    private readonly InMemorySink _sink = new();
    private readonly Ulid _inv = Ulid.NewUlid(Samples.T0);

    private InvestigationRunner Runner(params Capability[] available) =>
        new(_sink, new PermissionManager(new FakeProbe(available), _time).Snapshot(), _time);

    [Fact]
    public async Task Failing_module_is_isolated_and_the_next_module_still_runs()
    {
        var modules = new IAnalyzer[]
        {
            new DelegateAnalyzer("first", async (ctx, ct) => await ctx.Writer.AddEvidenceAsync(Samples.Evidence(ctx), ct)),
            new DelegateAnalyzer("broken", (_, _) => throw new IOException("disk read failed")),
            new DelegateAnalyzer("third", async (ctx, ct) => await ctx.Writer.AddEvidenceAsync(Samples.Evidence(ctx), ct)),
        };

        var result = await Runner().RunAsync(_inv, modules, CancellationToken.None);

        Assert.Equal(new[] { ModuleState.Completed, ModuleState.Failed, ModuleState.Completed }, result.Modules.Select(m => m.State));
        var broken = result.Modules[1];
        Assert.Contains("IOException", broken.Reason, StringComparison.Ordinal);
        Assert.Contains(broken.Errors, e => e.Message == "disk read failed");
        Assert.Equal(2, _sink.Evidence.Count);
        Assert.False(result.Cancelled);
    }

    [Fact]
    public async Task Every_module_is_checkpointed_after_it_finishes()
    {
        var modules = new IAnalyzer[]
        {
            new DelegateAnalyzer("alpha", async (ctx, ct) => { for (var i = 0; i < 3; i++) { await ctx.Writer.AddEvidenceAsync(Samples.Evidence(ctx), ct); } }),
            new DelegateAnalyzer("beta", async (ctx, ct) => await ctx.Writer.AddEvidenceAsync(Samples.Evidence(ctx), ct)),
        };

        await Runner().RunAsync(_inv, modules, CancellationToken.None);

        Assert.Equal(new[] { "alpha", "beta" }, _sink.Checkpoints.Select(c => c.ModuleId));
        Assert.Equal(new[] { 3, 4 }, _sink.EvidenceAtCheckpoint);
        Assert.Equal(3, _sink.Checkpoints[0].EvidenceCount);
    }

    [Fact]
    public async Task Cancellation_keeps_collected_records_and_marks_remaining_modules()
    {
        using var cts = new CancellationTokenSource();
        var modules = new IAnalyzer[]
        {
            new DelegateAnalyzer("collector", async (ctx, ct) =>
            {
                await ctx.Writer.AddEvidenceAsync(Samples.Evidence(ctx, "a.jar"), ct);
                await ctx.Writer.AddEvidenceAsync(Samples.Evidence(ctx, "b.jar"), ct);
                await cts.CancelAsync();
                ct.ThrowIfCancellationRequested();
                await ctx.Writer.AddEvidenceAsync(Samples.Evidence(ctx, "never.jar"), ct);
            }),
            new DelegateAnalyzer("later", (_, _) => throw new InvalidOperationException("must not run")),
        };

        var result = await Runner().RunAsync(_inv, modules, cts.Token);

        Assert.True(result.Cancelled);
        Assert.Equal(ModuleState.Cancelled, result.Modules[0].State);
        Assert.Equal(2, result.Modules[0].EvidenceCount);
        Assert.Equal(ModuleState.Cancelled, result.Modules[1].State);
        Assert.Contains("before this module started", result.Modules[1].Reason, StringComparison.Ordinal);
        Assert.Equal(new[] { "a.jar", "b.jar" }, _sink.Evidence.Select(e => e.Target.FileName));
        Assert.Equal(2, _sink.Checkpoints.Count);
        Assert.False(_sink.CheckpointTokenWasCancellable, "Checkpoints must not be cancellable, or a cancelled run would lose data.");
    }

    [Fact]
    public async Task Module_with_unmet_requirements_is_skipped_with_reason()
    {
        var ran = false;
        var needsAdmin = new DelegateAnalyzer(
            "history",
            (_, _) => { ran = true; return Task.CompletedTask; },
            new AnalyzerRequirements { RequiredCapabilities = [Capability.RawVolumeRead] });

        var result = await Runner().RunAsync(_inv, [needsAdmin], CancellationToken.None);

        Assert.False(ran);
        Assert.Equal(ModuleState.Skipped, result.Modules[0].State);
        Assert.Contains("RawVolumeRead", result.Modules[0].Reason, StringComparison.Ordinal);
        Assert.Single(_sink.Checkpoints);
    }

    [Fact]
    public async Task Module_requiring_consent_is_skipped_until_consent_is_given()
    {
        var network = new DelegateAnalyzer("network", (_, _) => Task.CompletedTask, new AnalyzerRequirements { RequiredConsents = [Consent.NetworkMonitoring] });
        var pm = new PermissionManager(new FakeProbe(), _time);

        var without = await new InvestigationRunner(_sink, pm.Snapshot(), _time).RunAsync(_inv, [network], CancellationToken.None);
        Assert.Equal(ModuleState.Skipped, without.Modules[0].State);

        pm.Grant(Consent.NetworkMonitoring, "Device owner", "I agree to monitoring of network connections for this check.");
        var with = await new InvestigationRunner(_sink, pm.Snapshot(), _time).RunAsync(_inv, [network], CancellationToken.None);
        Assert.Equal(ModuleState.Completed, with.Modules[0].State);
    }

    [Fact]
    public async Task Invalid_evidence_stops_only_that_module()
    {
        var modules = new IAnalyzer[]
        {
            new DelegateAnalyzer("bad", async (ctx, ct) =>
                await ctx.Writer.AddEvidenceAsync(Samples.Evidence(ctx) with { Confidence = Confidence.High }, ct)),
            new DelegateAnalyzer("good", async (ctx, ct) => await ctx.Writer.AddEvidenceAsync(Samples.Evidence(ctx), ct)),
        };

        var result = await Runner().RunAsync(_inv, modules, CancellationToken.None);

        Assert.Equal(ModuleState.Failed, result.Modules[0].State);
        Assert.Contains(result.Modules[0].Errors, e => e.ExceptionType == nameof(InvalidEvidenceException));
        Assert.Equal(ModuleState.Completed, result.Modules[1].State);
        Assert.Single(_sink.Evidence);
    }

    [Fact]
    public async Task Module_cannot_write_records_under_another_module_or_investigation()
    {
        var other = Ulid.NewUlid(Samples.T0);
        var modules = new IAnalyzer[]
        {
            new DelegateAnalyzer("impostor", async (ctx, ct) =>
                await ctx.Writer.AddEvidenceAsync(Samples.Evidence(ctx) with { ModuleId = "someone-else" }, ct)),
            new DelegateAnalyzer("foreign", async (ctx, ct) =>
                await ctx.Writer.AddEvidenceAsync(Samples.Evidence(ctx) with { InvestigationId = other }, ct)),
        };

        var result = await Runner().RunAsync(_inv, modules, CancellationToken.None);

        Assert.All(result.Modules, m => Assert.Equal(ModuleState.Failed, m.State));
        Assert.Empty(_sink.Evidence);
    }

    [Fact]
    public async Task Writes_after_the_module_finished_are_refused()
    {
        IEvidenceWriter? leaked = null;
        AnalyzerContext? leakedCtx = null;
        var modules = new IAnalyzer[]
        {
            new DelegateAnalyzer("leaky", (ctx, _) => { leaked = ctx.Writer; leakedCtx = ctx; return Task.CompletedTask; }),
        };

        await Runner().RunAsync(_inv, modules, CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await leaked!.AddEvidenceAsync(Samples.Evidence(leakedCtx!), CancellationToken.None));
        Assert.Empty(_sink.Evidence);
    }

    [Fact]
    public async Task Reported_errors_mark_the_module_completed_with_errors()
    {
        var modules = new IAnalyzer[]
        {
            new DelegateAnalyzer("partial", async (ctx, ct) =>
            {
                await ctx.Writer.AddEvidenceAsync(Samples.Evidence(ctx), ct);
                await ctx.Writer.AddErrorAsync(new ModuleError("Access denied", "UnauthorizedAccessException", @"C:\Users\other\NTUSER.DAT"), ct);
                await ctx.Writer.AddCoverageAsync(Samples.Coverage(ctx), ct);
            }),
        };

        var result = await Runner().RunAsync(_inv, modules, CancellationToken.None);

        Assert.Equal(ModuleState.CompletedWithErrors, result.Modules[0].State);
        Assert.Single(result.Modules[0].Errors);
        Assert.Equal(1, result.Modules[0].CoverageCount);
        Assert.Single(_sink.Errors);
    }

    [Theory]
    [InlineData("File Hunter")]
    [InlineData("FileHunter")]
    [InlineData("x")]
    [InlineData("1abc")]
    public async Task Invalid_module_ids_are_rejected(string id)
    {
        var a = new DelegateAnalyzer(id, (_, _) => Task.CompletedTask);
        await Assert.ThrowsAsync<ArgumentException>(() => Runner().RunAsync(_inv, [a], CancellationToken.None));
    }

    [Fact]
    public async Task Duplicate_module_ids_are_rejected()
    {
        var a = new DelegateAnalyzer("same", (_, _) => Task.CompletedTask);
        var b = new DelegateAnalyzer("same", (_, _) => Task.CompletedTask);
        await Assert.ThrowsAsync<ArgumentException>(() => Runner().RunAsync(_inv, [a, b], CancellationToken.None));
    }

    [Fact]
    public async Task Timing_is_recorded_from_the_injected_clock()
    {
        var modules = new IAnalyzer[]
        {
            new DelegateAnalyzer("slow", (_, _) => { _time.Advance(TimeSpan.FromMinutes(3)); return Task.CompletedTask; }),
        };

        var result = await Runner().RunAsync(_inv, modules, CancellationToken.None);

        Assert.Equal(Samples.T0, result.Modules[0].StartedUtc);
        Assert.Equal(Samples.T0.AddMinutes(3), result.Modules[0].FinishedUtc);
    }
}

public class PermissionManagerTests
{
    private readonly ManualTimeProvider _time = new(Samples.T0);

    [Fact]
    public void Nothing_is_consented_by_default()
    {
        var snap = new PermissionManager(new FakeProbe(), _time).Snapshot();
        Assert.All(Enum.GetValues<Consent>(), c => Assert.False(snap.Has(c)));
    }

    [Fact]
    public void Consent_records_who_when_and_what_was_agreed()
    {
        var pm = new PermissionManager(new FakeProbe(), _time);
        var r = pm.Grant(Consent.BrowserDownloadHistory, "Owner", "Download history only.");
        Assert.Equal(Samples.T0, r.GrantedAtUtc);
        Assert.True(pm.Snapshot().Has(Consent.BrowserDownloadHistory));

        pm.Revoke(Consent.BrowserDownloadHistory);
        Assert.False(pm.Snapshot().Has(Consent.BrowserDownloadHistory));
    }

    [Fact]
    public void Consent_without_statement_is_refused()
    {
        var pm = new PermissionManager(new FakeProbe(), _time);
        Assert.Throws<ArgumentException>(() => pm.Grant(Consent.NetworkMonitoring, "Owner", ""));
    }

    [Fact]
    public void Throwing_probe_is_reported_as_unavailable_not_fatal()
    {
        var pm = new PermissionManager(new ThrowingProbe(), _time);
        var snap = pm.Snapshot();
        Assert.All(Enum.GetValues<Capability>(), c =>
        {
            Assert.False(snap.Has(c));
            Assert.Contains("Probe failed", snap.Get(c).Reason, StringComparison.Ordinal);
        });
    }

    [Fact]
    public void Missing_optional_capabilities_are_listed_with_reasons()
    {
        var snap = new PermissionManager(new FakeProbe(Capability.Administrator), _time).Snapshot();
        var req = new AnalyzerRequirements { OptionalCapabilities = [Capability.Administrator, Capability.OtherUserProfiles] };
        var missing = snap.MissingOptional(req);
        Assert.Equal(new[] { Capability.OtherUserProfiles }, missing.Select(m => m.Capability));
        Assert.Null(snap.Unmet(req));
    }

    private sealed class ThrowingProbe : ICapabilityProbe
    {
        public CapabilityState Probe(Capability capability) => throw new UnauthorizedAccessException("denied");
    }
}
