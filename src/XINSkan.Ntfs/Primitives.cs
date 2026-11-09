namespace XINSkan.Ntfs;

/// <summary>An NTFS file reference: 48-bit MFT entry number and 16-bit sequence number.</summary>
public readonly record struct FileReference(ulong Entry, ushort Sequence)
{
    public static FileReference FromRaw(ulong raw) => new(raw & 0x0000_FFFF_FFFF_FFFFUL, (ushort)(raw >> 48));

    public bool IsEmpty => Entry == 0 && Sequence == 0;

    public override string ToString() => $"{Entry}/{Sequence}";
}

/// <summary>Windows FILETIME values as stored by NTFS (UTC, 100 ns since 1601-01-01).</summary>
public static class NtfsTime
{
    /// <summary>Values outside this range are kept as raw ticks but not converted: they cannot be real.</summary>
    public static readonly DateTimeOffset Earliest = new(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public static readonly DateTimeOffset Latest = new(2100, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private const long FileTimeEpochTicks = 504_911_232_000_000_000; // 1601-01-01 in DateTime ticks

    /// <summary>Converts a FILETIME, or returns null for 0 and for values outside 1980–2100.</summary>
    public static DateTimeOffset? ToUtc(long fileTime)
    {
        if (fileTime <= 0 || fileTime > DateTime.MaxValue.Ticks - FileTimeEpochTicks)
        {
            return null;
        }

        var value = new DateTimeOffset(fileTime + FileTimeEpochTicks, TimeSpan.Zero);
        return value < Earliest || value >= Latest ? null : value;
    }

    /// <summary>Whether the sub-second part (the last seven digits) is zero, as when a tool sets whole seconds.</summary>
    public static bool HasZeroFraction(long fileTime) => fileTime > 0 && fileTime % 10_000_000 == 0;
}

/// <summary>Four NTFS timestamps of one attribute, raw (FILETIME).</summary>
public readonly record struct NtfsTimes(long Created, long Modified, long MftModified, long Accessed);
