using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;

namespace XINSkan.UnitTests;

internal sealed class ManualTimeProvider : TimeProvider
{
    private DateTimeOffset _now;

    public ManualTimeProvider(DateTimeOffset start) => _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>Records everything and lets tests inspect what was checkpointed.</summary>
internal sealed class InMemorySink : IInvestigationSink
{
    private readonly Lock _gate = new();

    public List<Evidence> Evidence { get; } = [];

    public List<SourceCoverage> Coverage { get; } = [];

    public List<(string Module, ModuleError Error)> Errors { get; } = [];

    public List<ModuleResult> Checkpoints { get; } = [];

    /// <summary>Evidence count at the moment of each checkpoint, to prove records were saved before the next module ran.</summary>
    public List<int> EvidenceAtCheckpoint { get; } = [];

    public bool CheckpointTokenWasCancellable { get; private set; }

    /// <summary>When set, adding evidence fails as a full or removed output drive would.</summary>
    public Exception? EvidenceFailure { get; set; }

    public ValueTask AddEvidenceAsync(Evidence evidence, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (EvidenceFailure is not null)
            {
                throw EvidenceFailure;
            }

            Evidence.Add(evidence);
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask AddCoverageAsync(SourceCoverage coverage, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            Coverage.Add(coverage);
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask AddErrorAsync(string moduleId, ModuleError moduleError, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            Errors.Add((moduleId, moduleError));
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask CheckpointAsync(ModuleResult result, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            CheckpointTokenWasCancellable |= cancellationToken.CanBeCanceled;
            Checkpoints.Add(result);
            EvidenceAtCheckpoint.Add(Evidence.Count);
        }

        return ValueTask.CompletedTask;
    }
}

internal sealed class FakeProbe : ICapabilityProbe
{
    private readonly HashSet<Capability> _available;

    public FakeProbe(params Capability[] available) => _available = [.. available];

    public CapabilityState Probe(Capability capability) =>
        _available.Contains(capability)
            ? new CapabilityState(capability, true, "Available.")
            : new CapabilityState(capability, false, $"{capability} is not available in this test.");
}

/// <summary>A test analyzer driven by a delegate.</summary>
internal sealed class DelegateAnalyzer : IAnalyzer
{
    private readonly Func<AnalyzerContext, CancellationToken, Task> _run;

    public DelegateAnalyzer(string id, Func<AnalyzerContext, CancellationToken, Task> run, AnalyzerRequirements? requirements = null)
    {
        Id = id;
        _run = run;
        Requirements = requirements ?? AnalyzerRequirements.None;
    }

    public string Id { get; }

    public string DisplayName => Id;

    public AnalyzerRequirements Requirements { get; }

    public Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken) => _run(context, cancellationToken);
}

internal static class Samples
{
    public static readonly DateTimeOffset T0 = new(2026, 11, 8, 12, 0, 0, TimeSpan.Zero);

    public static Evidence Evidence(AnalyzerContext ctx, string name = "client.jar") => Evidence(ctx.InvestigationId, ctx.ModuleId, ctx.NewEvidenceId(), name);

    public static Evidence Evidence(Ulid investigation, string module, Ulid id, string name = "client.jar") => new()
    {
        EvidenceId = id,
        InvestigationId = investigation,
        ModuleId = module,
        Source = new SourceRef(EvidenceSourceKind.FileSystem, @"C:\Users\p\.minecraft\mods", "test", "1"),
        Locator = @"C:\Users\p\.minecraft\mods\" + name,
        EventType = EvidenceEventType.Existed,
        Target = new ObjectRef { RecordedPath = @"C:\Users\p\.minecraft\mods\" + name, FileName = name },
        Confidence = Confidence.Informational,
        Rationale = "The file exists; existence alone says nothing about use.",
        CollectionStatus = CollectionStatus.Collected,
        Description = "File present in the mods folder.",
        CollectedAtUtc = T0,
    };

    public static SourceCoverage Coverage(AnalyzerContext ctx) => new()
    {
        InvestigationId = ctx.InvestigationId,
        ModuleId = ctx.ModuleId,
        Source = EvidenceSourceKind.FileSystem,
        Scope = "C:",
        Status = CollectionStatus.Collected,
        ItemsRead = 1,
    };
}
