namespace XINSkan.Models;

/// <summary>
/// The window a source can actually see. Reports use it to say "not observable before X" instead of
/// "nothing found": absence of a record is never evidence that an event did not happen.
/// </summary>
public sealed record SourceCoverage
{
    public required Ulid InvestigationId { get; init; }

    public required string ModuleId { get; init; }

    public required EvidenceSourceKind Source { get; init; }

    /// <summary>What was covered: a volume ("C:"), a profile, a folder, a log name.</summary>
    public required string Scope { get; init; }

    public required CollectionStatus Status { get; init; }

    /// <summary>Earliest moment the source holds records for, when known.</summary>
    public DateTimeOffset? EarliestUtc { get; init; }

    /// <summary>Latest moment the source holds records for, when known.</summary>
    public DateTimeOffset? LatestUtc { get; init; }

    /// <summary>Number of items read (records, files, entries), when meaningful.</summary>
    public long? ItemsRead { get; init; }

    public IReadOnlyList<Limitation> Limitations { get; init; } = [];

    public IReadOnlyList<string> Validate()
    {
        var problems = new List<string>();
        if (InvestigationId.IsEmpty)
        {
            problems.Add("InvestigationId is empty.");
        }

        if (string.IsNullOrWhiteSpace(ModuleId) || string.IsNullOrWhiteSpace(Scope))
        {
            problems.Add("ModuleId and Scope are required.");
        }

        if (Status != CollectionStatus.Collected && Limitations.Count == 0)
        {
            problems.Add($"Coverage with status {Status} must state its limitations.");
        }

        if (EarliestUtc is { } e && LatestUtc is { } l && e > l)
        {
            problems.Add("EarliestUtc is after LatestUtc.");
        }

        return problems;
    }
}
