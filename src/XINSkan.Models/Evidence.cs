namespace XINSkan.Models;

/// <summary>
/// One observation taken from one artifact (schema v1, see docs/EVIDENCE_SCHEMA.md). Evidence is immutable and is
/// never upgraded in place: correlation produces separate records that reference evidence by ID.
/// </summary>
public sealed record Evidence
{
    public const int SchemaVersion = 1;

    /// <summary>Highest confidence a single record may carry. "High" is reserved for correlation of independent sources.</summary>
    public const Confidence MaxSingleRecordConfidence = Confidence.Medium;

    private static readonly HashSet<EvidenceSourceKind> NonExecutionSources =
    [
        EvidenceSourceKind.FileSystem,
        EvidenceSourceKind.Mft,
        EvidenceSourceKind.UsnJournal,
        EvidenceSourceKind.RecycleBin,
        EvidenceSourceKind.ZoneIdentifier,
        EvidenceSourceKind.ShadowCopy,
    ];

    public required Ulid EvidenceId { get; init; }

    public required Ulid InvestigationId { get; init; }

    /// <summary>The analyzer that produced the record, for example "file-hunter".</summary>
    public required string ModuleId { get; init; }

    public required SourceRef Source { get; init; }

    /// <summary>Where inside the source: "MFT entry 1234/5", "USN 0x1F0A2B", "offset 0x400", a registry key path.</summary>
    public required string Locator { get; init; }

    public required EvidenceEventType EventType { get; init; }

    /// <summary>When the event happened according to the source; null when the source does not record it.</summary>
    public EvidenceTimestamp? Timestamp { get; init; }

    /// <summary>Other timestamps the source holds for the same object (for example all eight MFT times).</summary>
    public IReadOnlyList<EvidenceTimestamp> OtherTimestamps { get; init; } = [];

    public required ObjectRef Target { get; init; }

    /// <summary>Hash of the investigated file itself; only when the file exists and was read in full.</summary>
    public Sha256Hash? ObjectSha256 { get; init; }

    /// <summary>Hash of the raw artifact record the conclusion was drawn from (MFT record bytes, USN record bytes, ...).</summary>
    public Sha256Hash? ArtifactSha256 { get; init; }

    public required Confidence Confidence { get; init; }

    /// <summary>Why this confidence: written for the reader of the report.</summary>
    public required string Rationale { get; init; }

    public required CollectionStatus CollectionStatus { get; init; }

    public required string Description { get; init; }

    public IReadOnlyList<Limitation> Limitations { get; init; } = [];

    /// <summary>Security identifier of the profile the artifact belongs to, when it is per-user.</summary>
    public string? UserSid { get; init; }

    /// <summary>Source-specific facts that do not fit the common fields (old name of a rename, USN reason flags, ...).</summary>
    public IReadOnlyDictionary<string, string> Attributes { get; init; } = new Dictionary<string, string>();

    public required DateTimeOffset CollectedAtUtc { get; init; }

    /// <summary>Checks the invariants every record must satisfy before it can be stored.</summary>
    public IReadOnlyList<string> Validate()
    {
        var problems = new List<string>();

        if (EvidenceId.IsEmpty)
        {
            problems.Add("EvidenceId is empty.");
        }

        if (InvestigationId.IsEmpty)
        {
            problems.Add("InvestigationId is empty.");
        }

        if (string.IsNullOrWhiteSpace(ModuleId))
        {
            problems.Add("ModuleId is empty.");
        }

        if (string.IsNullOrWhiteSpace(Locator))
        {
            problems.Add("Locator is empty: every record must say where in the source it came from.");
        }

        if (string.IsNullOrWhiteSpace(Description))
        {
            problems.Add("Description is empty.");
        }

        if (string.IsNullOrWhiteSpace(Rationale))
        {
            problems.Add("Rationale is empty: every confidence level needs an explanation.");
        }

        if (Confidence > MaxSingleRecordConfidence && Confidence != Confidence.Inconclusive)
        {
            problems.Add($"Confidence {Confidence} cannot be assigned to a single record; only correlation of independent sources can reach it.");
        }

        if (CollectionStatus != CollectionStatus.Collected && Limitations.Count == 0)
        {
            problems.Add($"CollectionStatus {CollectionStatus} requires at least one limitation explaining what is missing.");
        }

        if (EventType == EvidenceEventType.Executed && NonExecutionSources.Contains(Source.Kind))
        {
            problems.Add($"Source {Source.Kind} cannot prove execution; use Existed, Created or ExecutedLikely with a rationale.");
        }

        if (Target.RecordedPath is null && Target.NormalizedPath is null && Target.FileName is null && !Target.HasMftReference)
        {
            problems.Add("Target has no path, name or MFT reference.");
        }

        if (CollectedAtUtc.Offset != TimeSpan.Zero)
        {
            problems.Add("CollectedAtUtc must be UTC.");
        }

        return problems;
    }
}
