using XINSkan.Core.Permissions;
using XINSkan.Models;

namespace XINSkan.Core.Pipeline;

/// <summary>
/// One analysis module (File Hunter, History Engine, ...). Analyzers only read the investigated system and hand
/// their findings to <see cref="IEvidenceWriter"/>; they never persist anything themselves.
/// </summary>
public interface IAnalyzer
{
    /// <summary>Stable identifier used in storage and reports, for example "file-hunter".</summary>
    string Id { get; }

    string DisplayName { get; }

    AnalyzerRequirements Requirements { get; }

    Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken);
}

/// <summary>The only output channel an analyzer has.</summary>
public interface IEvidenceWriter
{
    ValueTask AddEvidenceAsync(Evidence evidence, CancellationToken cancellationToken);

    ValueTask AddCoverageAsync(SourceCoverage coverage, CancellationToken cancellationToken);

    /// <summary>A problem that did not stop the module but must reach the report (unreadable file, parse error, ...).</summary>
    ValueTask AddErrorAsync(ModuleError moduleError, CancellationToken cancellationToken);
}

/// <summary>
/// Durable destination of an investigation (SQLite in XINSkan.Storage). Must keep everything accepted before
/// <see cref="CheckpointAsync"/> even if the investigation is cancelled or a later module fails.
/// </summary>
public interface IInvestigationSink
{
    ValueTask AddEvidenceAsync(Evidence evidence, CancellationToken cancellationToken);

    ValueTask AddCoverageAsync(SourceCoverage coverage, CancellationToken cancellationToken);

    ValueTask AddErrorAsync(string moduleId, ModuleError moduleError, CancellationToken cancellationToken);

    /// <summary>Persists the module result and makes all of the module's records durable.</summary>
    ValueTask CheckpointAsync(ModuleResult result, CancellationToken cancellationToken);
}

/// <summary>A sink that can also keep the correlation of the investigation (objects and findings).</summary>
public interface ICorrelationSink
{
    ValueTask AddCorrelationAsync(CorrelationResult result, long evidenceRead, CancellationToken cancellationToken);
}

public sealed record AnalyzerContext(
    Ulid InvestigationId,
    string ModuleId,
    IEvidenceWriter Writer,
    PermissionSnapshot Permissions,
    TimeProvider Time,
    IProgress<ModuleProgress> Progress)
{
    /// <summary>Creates a new evidence ID stamped with the current time.</summary>
    public Ulid NewEvidenceId() => Ulid.NewUlid(Time.GetUtcNow());
}

public enum ModuleState
{
    Pending,
    Running,
    Completed,
    CompletedWithErrors,
    Skipped,
    Failed,
    Cancelled,
}

public sealed record ModuleError(string Message, string? ExceptionType = null, string? Location = null);

public sealed record ModuleProgress(string ModuleId, ModuleState State, string? Message = null, double? Fraction = null);

public sealed record ModuleResult
{
    public required string ModuleId { get; init; }

    public required ModuleState State { get; init; }

    public DateTimeOffset? StartedUtc { get; init; }

    public DateTimeOffset? FinishedUtc { get; init; }

    public long EvidenceCount { get; init; }

    public long CoverageCount { get; init; }

    public IReadOnlyList<ModuleError> Errors { get; init; } = [];

    /// <summary>Why the module did not run or stopped early; set for Skipped, Failed and Cancelled.</summary>
    public string? Reason { get; init; }
}

public sealed record InvestigationRunResult(
    Ulid InvestigationId,
    DateTimeOffset StartedUtc,
    DateTimeOffset FinishedUtc,
    bool Cancelled,
    IReadOnlyList<ModuleResult> Modules);
