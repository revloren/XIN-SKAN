using System.Buffers.Binary;
using System.Text;

namespace XINSkan.Ntfs;

/// <summary>USN_RECORD reason flags: what happened to the file since it was opened.</summary>
[Flags]
public enum UsnReason : uint
{
    None = 0,
    DataOverwrite = 0x0000_0001,
    DataExtend = 0x0000_0002,
    DataTruncation = 0x0000_0004,
    NamedDataOverwrite = 0x0000_0010,
    NamedDataExtend = 0x0000_0020,
    NamedDataTruncation = 0x0000_0040,
    FileCreate = 0x0000_0100,
    FileDelete = 0x0000_0200,
    EaChange = 0x0000_0400,
    SecurityChange = 0x0000_0800,
    RenameOldName = 0x0000_1000,
    RenameNewName = 0x0000_2000,
    IndexableChange = 0x0000_4000,
    BasicInfoChange = 0x0000_8000,
    HardLinkChange = 0x0001_0000,
    CompressionChange = 0x0002_0000,
    EncryptionChange = 0x0004_0000,
    ObjectIdChange = 0x0008_0000,
    ReparsePointChange = 0x0010_0000,
    StreamChange = 0x0020_0000,
    TransactedChange = 0x0040_0000,
    IntegrityChange = 0x0080_0000,
    Close = 0x8000_0000,
}

/// <summary>One change journal record (version 2 or 3; NTFS 128-bit IDs are 64-bit references zero-extended).</summary>
public sealed record UsnRecord(
    long Usn,
    long TimeStamp,
    FileReference File,
    FileReference Parent,
    UsnReason Reason,
    uint SourceInfo,
    uint FileAttributes,
    string Name,
    int MajorVersion)
{
    public const uint AttributeDirectory = 0x10;

    public bool IsDirectory => (FileAttributes & AttributeDirectory) != 0;

    public DateTimeOffset? TimeUtc => NtfsTime.ToUtc(TimeStamp);
}

/// <summary>Statistics of parsing a block of journal data.</summary>
public sealed class UsnParseStatistics
{
    public long Records { get; internal set; }

    /// <summary>Records of version 4 (range tracking) or unknown versions, skipped by length.</summary>
    public long UnsupportedVersion { get; internal set; }

    /// <summary>Places where the data did not look like a record; parsing resumed at the next 8-byte boundary.</summary>
    public long Resynchronised { get; internal set; }
}

/// <summary>Parses change journal records from FSCTL_READ_USN_JOURNAL output or from a raw $UsnJrnl:$J stream.</summary>
public static class UsnParser
{
    private const int MinV2 = 60;
    private const int MinV3 = 76;
    private const int MaxRecord = 4096;

    /// <summary>Records in a block. Zero runs (sparse or padded parts of $J) are skipped; garbage is stepped over.</summary>
    public static IEnumerable<UsnRecord> Parse(ReadOnlyMemory<byte> block, UsnParseStatistics? stats = null)
    {
        var o = 0;
        while (o + 8 <= block.Length)
        {
            var b = block.Span;
            var length = BinaryPrimitives.ReadUInt32LittleEndian(b[o..]);
            if (length == 0)
            {
                // Skip zeros quickly: $J is sparse at its start and pages are padded with zeros.
                var next = b[o..].IndexOfAnyExcept((byte)0);
                if (next < 0)
                {
                    yield break;
                }

                o += next & ~7;
                if ((next & 7) != 0 && BinaryPrimitives.ReadUInt32LittleEndian(b[o..]) == 0)
                {
                    o += 8;
                }

                continue;
            }

            var record = TryRead(b, o, length, out var unsupported);
            if (record is not null)
            {
                if (stats is not null)
                {
                    stats.Records++;
                }

                yield return record;
                o += (int)length;
            }
            else if (unsupported)
            {
                if (stats is not null)
                {
                    stats.UnsupportedVersion++;
                }

                o += (int)length;
            }
            else
            {
                if (stats is not null)
                {
                    stats.Resynchronised++;
                }

                o += 8;
            }
        }
    }

    private static UsnRecord? TryRead(ReadOnlySpan<byte> b, int o, uint length, out bool unsupported)
    {
        unsupported = false;
        if (length < MinV2 || length > MaxRecord || length % 8 != 0 || o + length > b.Length)
        {
            return null;
        }

        var r = b.Slice(o, (int)length);
        var major = BinaryPrimitives.ReadUInt16LittleEndian(r[4..]);
        switch (major)
        {
            case 2:
            {
                int nameLength = BinaryPrimitives.ReadUInt16LittleEndian(r[56..]);
                int nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(r[58..]);
                if (nameOffset != 60 || nameLength % 2 != 0 || nameOffset + nameLength > r.Length)
                {
                    return null;
                }

                return new UsnRecord(
                    BinaryPrimitives.ReadInt64LittleEndian(r[24..]),
                    BinaryPrimitives.ReadInt64LittleEndian(r[32..]),
                    FileReference.FromRaw(BinaryPrimitives.ReadUInt64LittleEndian(r[8..])),
                    FileReference.FromRaw(BinaryPrimitives.ReadUInt64LittleEndian(r[16..])),
                    (UsnReason)BinaryPrimitives.ReadUInt32LittleEndian(r[40..]),
                    BinaryPrimitives.ReadUInt32LittleEndian(r[44..]),
                    BinaryPrimitives.ReadUInt32LittleEndian(r[52..]),
                    Encoding.Unicode.GetString(r.Slice(nameOffset, nameLength)),
                    2);
            }

            case 3:
            {
                if (length < MinV3)
                {
                    return null;
                }

                int nameLength = BinaryPrimitives.ReadUInt16LittleEndian(r[72..]);
                int nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(r[74..]);
                if (nameOffset != 76 || nameLength % 2 != 0 || nameOffset + nameLength > r.Length)
                {
                    return null;
                }

                // 128-bit IDs: on NTFS the upper half is zero; on ReFS it is not and the record cannot be mapped to the MFT.
                if (BinaryPrimitives.ReadUInt64LittleEndian(r[16..]) != 0 || BinaryPrimitives.ReadUInt64LittleEndian(r[32..]) != 0)
                {
                    unsupported = true;
                    return null;
                }

                return new UsnRecord(
                    BinaryPrimitives.ReadInt64LittleEndian(r[40..]),
                    BinaryPrimitives.ReadInt64LittleEndian(r[48..]),
                    FileReference.FromRaw(BinaryPrimitives.ReadUInt64LittleEndian(r[8..])),
                    FileReference.FromRaw(BinaryPrimitives.ReadUInt64LittleEndian(r[24..])),
                    (UsnReason)BinaryPrimitives.ReadUInt32LittleEndian(r[56..]),
                    BinaryPrimitives.ReadUInt32LittleEndian(r[60..]),
                    BinaryPrimitives.ReadUInt32LittleEndian(r[68..]),
                    Encoding.Unicode.GetString(r.Slice(nameOffset, nameLength)),
                    3);
            }

            case 4:
                unsupported = true;
                return null;
            default:
                return null;
        }
    }
}

/// <summary>FSCTL_QUERY_USN_JOURNAL output (USN_JOURNAL_DATA).</summary>
public sealed record UsnJournalInfo(ulong JournalId, long FirstUsn, long NextUsn, long LowestValidUsn, long MaxUsn, ulong MaximumSize, ulong AllocationDelta)
{
    public static UsnJournalInfo Parse(ReadOnlySpan<byte> b)
    {
        if (b.Length < 56)
        {
            throw new InvalidDataException($"USN_JOURNAL_DATA is at least 56 bytes, got {b.Length}.");
        }

        return new UsnJournalInfo(
            BinaryPrimitives.ReadUInt64LittleEndian(b),
            BinaryPrimitives.ReadInt64LittleEndian(b[8..]),
            BinaryPrimitives.ReadInt64LittleEndian(b[16..]),
            BinaryPrimitives.ReadInt64LittleEndian(b[24..]),
            BinaryPrimitives.ReadInt64LittleEndian(b[32..]),
            BinaryPrimitives.ReadUInt64LittleEndian(b[40..]),
            BinaryPrimitives.ReadUInt64LittleEndian(b[48..]));
    }

    /// <summary>
    /// NTFS creates the journal ID from the system time at creation, so it dates the journal. A journal created
    /// long after the system was installed was deleted and recreated at some point (by a person, a tool or Windows).
    /// </summary>
    public DateTimeOffset? CreatedUtc => NtfsTime.ToUtc((long)JournalId);
}
