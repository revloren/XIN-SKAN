using XINSkan.Core.Paths;
using XINSkan.Models;

namespace XINSkan.Correlation;

/// <summary>
/// What correlation needs from one record — a few hundred bytes instead of the whole record, so an investigation
/// with hundreds of thousands of records is correlated in memory.
/// </summary>
public sealed record EvidenceFacts(
    Ulid Id,
    string Module,
    EvidenceSourceKind Source,
    EvidenceEventType Type,
    DateTimeOffset? Time,
    string? RecordedPath,
    string? NormalizedPath,
    string? FileName,
    ulong? VolumeSerial,
    ulong? MftEntry,
    ushort? MftSequence,
    Sha256Hash? Sha256,
    Confidence Confidence,
    IReadOnlyDictionary<string, string> Attributes)
{
    /// <summary>The attributes the rules read; everything else stays in the database.</summary>
    internal static readonly string[] KeptAttributes =
    [
        "Mft.TimeAnomaly", "Usn.BasicInfoChanges", "Usn.ExtensionChanged", "Usn.OldPath",
        "Defender.Threat", "Defender.ExclusionType", "Defender.Change",
        "EventLog.EventId", "EventLog.Channel", "EventLog.ClearedChannel",
        "Volume.Serial", "Lnk.DriveSerial", "Lnk.DriveType", "Lnk.VolumeLabel", "MinecraftRoot",
        "Jvm.Flag", "Jvm.Where", "Sha1.Actual", "Version.Id",
    ];

    public string? Attr(string name) => Attributes.TryGetValue(name, out var v) && v.Length > 0 ? v : null;

    public static EvidenceFacts From(Evidence e)
    {
        ArgumentNullException.ThrowIfNull(e);
        Dictionary<string, string>? attrs = null;
        foreach (var k in KeptAttributes)
        {
            if (e.Attributes.TryGetValue(k, out var v))
            {
                (attrs ??= new Dictionary<string, string>(StringComparer.Ordinal))[k] = v;
            }
        }

        return new EvidenceFacts(
            e.EvidenceId, e.ModuleId, e.Source.Kind, e.EventType, e.Timestamp?.ValueUtc,
            e.Target.RecordedPath, e.Target.NormalizedPath ?? PathNormalizer.Normalize(PathOnly(e.Target.RecordedPath)), e.Target.FileName,
            e.Target.VolumeSerial, e.Target.MftEntry, e.Target.MftSequence, e.ObjectSha256, e.Confidence,
            (IReadOnlyDictionary<string, string>?)attrs ?? EmptyAttributes);
    }

    private static readonly Dictionary<string, string> EmptyAttributes = new(StringComparer.Ordinal);

    /// <summary>Only real file paths are normalised for matching ("C:\…", "\\server\…").</summary>
    internal static string? PathOnly(string? path) =>
        path is { Length: > 2 } && ((path[1] == ':' && path[2] == '\\') || path.StartsWith(@"\\", StringComparison.Ordinal)) ? path : null;
}
