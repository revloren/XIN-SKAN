namespace XINSkan.Models;

/// <summary>Identity and context of one investigation, stored once at its start.</summary>
public sealed record InvestigationInfo
{
    public required Ulid InvestigationId { get; init; }

    public required DateTimeOffset StartedUtc { get; init; }

    public required string ToolVersion { get; init; }

    /// <summary>Who ran the investigation (as entered by the operator).</summary>
    public string? Operator { get; init; }

    public string? MachineName { get; init; }

    /// <summary>Operating system as reported by the investigated machine, for example "Windows 11 26100".</summary>
    public string? OsDescription { get; init; }

    /// <summary>Time zone of the investigated machine (IANA or Windows ID), to explain local-time artifacts.</summary>
    public string? TimeZoneId { get; init; }
}
