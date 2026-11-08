namespace XINSkan.Models;

/// <summary>
/// The file-system object an evidence record is about. Every field is optional because artifacts know different
/// things: an MFT record knows its entry and sequence but maybe not its full path; a Prefetch record knows a
/// device path but not the MFT entry. Correlation decides how strongly two references point to the same object.
/// </summary>
public sealed record ObjectRef
{
    /// <summary>The path exactly as the artifact recorded it (may be a device path, 8.3 name or partial).</summary>
    public string? RecordedPath { get; init; }

    /// <summary>Canonical path for comparison (see PathNormalizer in XINSkan.Core). Null if not derivable.</summary>
    public string? NormalizedPath { get; init; }

    public string? FileName { get; init; }

    /// <summary>NTFS volume serial number, when the artifact records it.</summary>
    public ulong? VolumeSerial { get; init; }

    /// <summary>MFT entry number (the low 48 bits of a file reference).</summary>
    public ulong? MftEntry { get; init; }

    /// <summary>MFT sequence number. An entry without a sequence cannot be safely matched across time.</summary>
    public ushort? MftSequence { get; init; }

    public long? Size { get; init; }

    public bool HasMftReference => MftEntry.HasValue && MftSequence.HasValue;
}
