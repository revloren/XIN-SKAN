namespace XINSkan.Models;

/// <summary>How a record was linked to a correlated object.</summary>
public enum LinkKind
{
    /// <summary>The same NTFS file reference (volume, MFT entry and sequence number).</summary>
    MftReference,

    /// <summary>The same normalised path, with no contradicting MFT reference.</summary>
    Path,
}

/// <summary>A record that belongs to a correlated object, and by which key.</summary>
public sealed record ObjectMember(Ulid EvidenceId, LinkKind Link);

/// <summary>
/// One file (or folder) as seen by several sources: the records that describe the same object, linked by its MFT
/// reference or path. Records are never changed; the object only lists them.
/// </summary>
public sealed record CorrelatedObject
{
    public required Ulid ObjectId { get; init; }

    public required Ulid InvestigationId { get; init; }

    /// <summary>The path as most records show it (for the reader); the comparison form is <see cref="NormalizedPath"/>.</summary>
    public string? DisplayPath { get; init; }

    public string? NormalizedPath { get; init; }

    public string? FileName { get; init; }

    /// <summary>Drive letter ("C:") or volume serial the MFT reference belongs to.</summary>
    public string? Volume { get; init; }

    public ulong? MftEntry { get; init; }

    public ushort? MftSequence { get; init; }

    /// <summary>Content hash when a source read the file.</summary>
    public Sha256Hash? Sha256 { get; init; }

    /// <summary>Other paths the object had (renames, moves, short names).</summary>
    public IReadOnlyList<string> OtherPaths { get; init; } = [];

    public DateTimeOffset? FirstUtc { get; init; }

    public DateTimeOffset? LastUtc { get; init; }

    /// <summary>Independent source families that describe the object (see docs/CORRELATION.md).</summary>
    public required IReadOnlyList<string> SourceFamilies { get; init; }

    public required IReadOnlyList<ObjectMember> Members { get; init; }
}

/// <summary>A record a finding is based on, and its role in it.</summary>
/// <param name="Role">"basis" — counted toward the finding; "context" — shown for the reader, not counted.</param>
public sealed record FindingMember(Ulid EvidenceId, string Role);

/// <summary>
/// A conclusion drawn from several records by a published rule (docs/CORRELATION.md). Its confidence follows the
/// rule and the number of independent source families behind it; it never replaces the records themselves.
/// </summary>
public sealed record Finding
{
    /// <summary>Medium and above need this many independent source families.</summary>
    public const int MinFamiliesForMedium = 2;

    /// <summary>High needs this many, and a verified identification of the object (stage 9), which correlation alone never has.</summary>
    public const int MinFamiliesForHigh = 3;

    public required Ulid FindingId { get; init; }

    public required Ulid InvestigationId { get; init; }

    /// <summary>Stable rule identifier, for example "TIMESTOMP_CONFIRMED".</summary>
    public required string RuleId { get; init; }

    public required Confidence Confidence { get; init; }

    public required string Title { get; init; }

    public required string Description { get; init; }

    /// <summary>Why this confidence, including innocent explanations.</summary>
    public required string Rationale { get; init; }

    public IReadOnlyList<Limitation> Limitations { get; init; } = [];

    public DateTimeOffset? FirstUtc { get; init; }

    public DateTimeOffset? LastUtc { get; init; }

    /// <summary>The object the finding is about, when it is about one object.</summary>
    public Ulid? ObjectId { get; init; }

    /// <summary>Independent source families of the "basis" records.</summary>
    public required IReadOnlyList<string> IndependentFamilies { get; init; }

    /// <summary>Whether the object was identified against verified signatures (stage 9). Required for High.</summary>
    public bool VerifiedIdentification { get; init; }

    /// <summary>For signature findings: how the object matched the signature database.</summary>
    public SignatureMatchKind? MatchKind { get; init; }

    /// <summary>For signature findings: the database entry (client, tool) it matched.</summary>
    public string? ClientId { get; init; }

    public required IReadOnlyList<FindingMember> Members { get; init; }

    public IReadOnlyList<string> Validate()
    {
        var problems = new List<string>();
        if (string.IsNullOrWhiteSpace(RuleId) || string.IsNullOrWhiteSpace(Title) || string.IsNullOrWhiteSpace(Description))
        {
            problems.Add("RuleId, Title and Description are required.");
        }

        if (string.IsNullOrWhiteSpace(Rationale))
        {
            problems.Add("Rationale is empty: every confidence level needs an explanation.");
        }

        if (!Members.Any(m => m.Role == "basis"))
        {
            problems.Add("A finding needs at least one basis record.");
        }

        var families = IndependentFamilies.Distinct(StringComparer.Ordinal).Count();

        // A direct identification of one object (its exact hash, or a component confirmed from the project's own
        // source) may be Medium on its own; everything else needs two independent families for Medium.
        var directIdentification = MatchKind is SignatureMatchKind.ExactHashMatch or SignatureMatchKind.VerifiedComponentMatch;
        if (Confidence == Confidence.Medium && families < MinFamiliesForMedium && !directIdentification)
        {
            problems.Add($"Medium needs {MinFamiliesForMedium} independent source families, got {families}.");
        }

        if (Confidence == Confidence.High && (families < MinFamiliesForHigh || !VerifiedIdentification))
        {
            problems.Add($"High needs {MinFamiliesForHigh} independent source families and a verified identification.");
        }

        if (FirstUtc is { } f && LastUtc is { } l && l < f)
        {
            problems.Add("LastUtc is before FirstUtc.");
        }

        return problems;
    }
}

/// <summary>A record that matched the signature database (stage 9), before correlation places it on an object.</summary>
public sealed record SignatureMatch(
    Ulid EvidenceId,
    string ClientId,
    string ClientName,
    string ClientKind,
    string EntryStatus,
    SignatureMatchKind Kind,
    string Matched,
    string Detail);

/// <summary>Which signature database an investigation used.</summary>
public sealed record SignatureDatabaseInfo(
    string Version,
    string Origin,
    string ManifestSha256,
    string? KeyId,
    int Clients,
    int VerifiedClients,
    int Hashes,
    IReadOnlyList<string> Problems);

/// <summary>Everything correlation produced for one investigation.</summary>
public sealed record CorrelationResult(IReadOnlyList<CorrelatedObject> Objects, IReadOnlyList<Finding> Findings, IReadOnlyList<Limitation> Limitations)
{
    /// <summary>The signature database the matches came from; null when none was loaded.</summary>
    public SignatureDatabaseInfo? Database { get; init; }
}
