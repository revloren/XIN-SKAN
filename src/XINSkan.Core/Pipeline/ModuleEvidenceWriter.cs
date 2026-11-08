using XINSkan.Models;

namespace XINSkan.Core.Pipeline;

/// <summary>
/// The writer handed to one analyzer for one run. It validates every record, stamps nothing on the analyzer's
/// behalf, counts what was accepted, and refuses writes after the module has finished so that a stray
/// background task cannot attach records to the wrong stage.
/// </summary>
internal sealed class ModuleEvidenceWriter : IEvidenceWriter
{
    private readonly IInvestigationSink _sink;
    private readonly Ulid _investigationId;
    private readonly string _moduleId;
    private readonly List<ModuleError> _errors = [];
    private readonly Lock _gate = new();
    private long _evidence;
    private long _coverage;
    private volatile bool _closed;

    public ModuleEvidenceWriter(IInvestigationSink sink, Ulid investigationId, string moduleId)
    {
        _sink = sink;
        _investigationId = investigationId;
        _moduleId = moduleId;
    }

    public long EvidenceCount => Interlocked.Read(ref _evidence);

    public long CoverageCount => Interlocked.Read(ref _coverage);

    public IReadOnlyList<ModuleError> Errors
    {
        get
        {
            lock (_gate)
            {
                return [.. _errors];
            }
        }
    }

    public void Close() => _closed = true;

    public async ValueTask AddEvidenceAsync(Evidence evidence, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        EnsureOpen();
        if (evidence.InvestigationId != _investigationId)
        {
            throw new InvalidEvidenceException($"Evidence {evidence.EvidenceId} belongs to investigation {evidence.InvestigationId}, not {_investigationId}.");
        }

        if (!string.Equals(evidence.ModuleId, _moduleId, StringComparison.Ordinal))
        {
            throw new InvalidEvidenceException($"Evidence {evidence.EvidenceId} claims module '{evidence.ModuleId}' but was written by '{_moduleId}'.");
        }

        var problems = evidence.Validate();
        if (problems.Count > 0)
        {
            throw new InvalidEvidenceException($"Evidence {evidence.EvidenceId} is invalid: {string.Join(" ", problems)}");
        }

        await _sink.AddEvidenceAsync(evidence, cancellationToken).ConfigureAwait(false);
        Interlocked.Increment(ref _evidence);
    }

    public async ValueTask AddCoverageAsync(SourceCoverage coverage, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(coverage);
        EnsureOpen();
        if (coverage.InvestigationId != _investigationId || !string.Equals(coverage.ModuleId, _moduleId, StringComparison.Ordinal))
        {
            throw new InvalidEvidenceException($"Coverage for {coverage.Source} does not belong to module '{_moduleId}' of this investigation.");
        }

        var problems = coverage.Validate();
        if (problems.Count > 0)
        {
            throw new InvalidEvidenceException($"Coverage for {coverage.Source} is invalid: {string.Join(" ", problems)}");
        }

        await _sink.AddCoverageAsync(coverage, cancellationToken).ConfigureAwait(false);
        Interlocked.Increment(ref _coverage);
    }

    public async ValueTask AddErrorAsync(ModuleError moduleError, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(moduleError);
        EnsureOpen();
        lock (_gate)
        {
            _errors.Add(moduleError);
        }

        await _sink.AddErrorAsync(_moduleId, moduleError, cancellationToken).ConfigureAwait(false);
    }

    private void EnsureOpen()
    {
        if (_closed)
        {
            throw new InvalidOperationException($"Module '{_moduleId}' has finished; it can no longer write records.");
        }
    }
}

/// <summary>An analyzer produced a record that violates the evidence schema. This is a bug in the analyzer.</summary>
public sealed class InvalidEvidenceException : Exception
{
    public InvalidEvidenceException()
    {
    }

    public InvalidEvidenceException(string message)
        : base(message)
    {
    }

    public InvalidEvidenceException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
