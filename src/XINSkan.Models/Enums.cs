namespace XINSkan.Models;

/// <summary>Kind of artifact an evidence record was derived from.</summary>
public enum EvidenceSourceKind
{
    FileSystem,
    Mft,
    UsnJournal,
    RecycleBin,
    Lnk,
    JumpList,
    ShellBags,
    Prefetch,
    Amcache,
    Bam,
    Srum,
    EventLog,
    MinecraftLog,
    ShadowCopy,
    ZoneIdentifier,
    Launcher,
    Browser,
    Network,
    Other,

    /// <summary>UserAssist counters in a user's registry (programs started from Explorer). Added in stage 6.</summary>
    UserAssist,
}

/// <summary>
/// What the source says happened to the object. "Executed" is only used when the artifact records a run;
/// "ExecutedLikely" when execution is inferred (for example a JAR listed in the Prefetch record of javaw.exe).
/// </summary>
public enum EvidenceEventType
{
    Existed,
    Created,
    Modified,
    Renamed,
    Moved,
    Deleted,
    Accessed,
    Executed,
    ExecutedLikely,
    Loaded,
    Downloaded,
    Observed,
}

/// <summary>Analytical confidence levels from the specification (section 17).</summary>
public enum Confidence
{
    Informational,
    Low,
    Medium,
    High,
    Inconclusive,
}

/// <summary>Signature match levels from the specification (section 17).</summary>
public enum SignatureMatchKind
{
    Unknown,
    PossibleMatch,
    NameMatch,
    MultipleFeatureMatch,
    VerifiedComponentMatch,
    ExactHashMatch,
}

/// <summary>Whether the information behind a record was fully collected.</summary>
public enum CollectionStatus
{
    Collected,
    Partial,
    Skipped,
    Failed,
}

/// <summary>Resolution of a timestamp as stored by its source, not as displayed.</summary>
public enum TimestampPrecision
{
    Unknown,
    /// <summary>Windows FILETIME, 100 ns ticks.</summary>
    HundredNanoseconds,
    Milliseconds,
    Seconds,
    /// <summary>DOS/FAT time as used by ZIP entries and ShellBag extension blocks.</summary>
    TwoSeconds,
    Day,
}
