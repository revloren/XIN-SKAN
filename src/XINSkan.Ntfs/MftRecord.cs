using System.Buffers.Binary;
using System.Text;

namespace XINSkan.Ntfs;

public enum FileNameNamespace : byte
{
    Posix = 0,
    Win32 = 1,
    Dos = 2,
    Win32AndDos = 3,
}

public enum MftRecordState
{
    /// <summary>Header and attributes parsed (problems, if any, are listed).</summary>
    Parsed,

    /// <summary>All zeros: the entry was never used.</summary>
    Empty,

    /// <summary>Not a FILE record (BAAD, garbage or unreadable header).</summary>
    Invalid,
}

/// <summary>$STANDARD_INFORMATION: the times Windows shows and programs can set.</summary>
public sealed record StandardInformation(NtfsTimes Times, uint FileAttributes, uint? SecurityId, long? Usn);

/// <summary>$FILE_NAME: a name in one directory. Its times are set by NTFS itself, not by SetFileTime.</summary>
public sealed record FileNameAttribute(
    FileReference Parent,
    NtfsTimes Times,
    long AllocatedSize,
    long RealSize,
    uint Flags,
    FileNameNamespace Namespace,
    string Name);

/// <summary>A $DATA attribute (unnamed = file content; named = alternate data stream).</summary>
public sealed record DataAttribute(
    string Name,
    bool NonResident,
    long Size,
    long AllocatedSize,
    long StartVcn,
    ushort Flags,
    IReadOnlyList<DataRun>? Runs,
    byte[]? ResidentValue)
{
    public bool IsCompressed => (Flags & 0x0001) != 0;

    public bool IsEncrypted => (Flags & 0x4000) != 0;

    public bool IsSparse => (Flags & 0x8000) != 0;
}

/// <summary>An entry of $ATTRIBUTE_LIST: an attribute of this file stored in another MFT record.</summary>
public sealed record AttributeListEntry(uint Type, string Name, long StartVcn, FileReference Record, ushort AttributeId);

/// <summary>One parsed FILE record. Parsing never throws: problems are collected in <see cref="Problems"/>.</summary>
public sealed class MftRecord
{
    public const uint TypeStandardInformation = 0x10;
    public const uint TypeAttributeList = 0x20;
    public const uint TypeFileName = 0x30;
    public const uint TypeObjectId = 0x40;
    public const uint TypeData = 0x80;
    public const uint TypeIndexRoot = 0x90;
    public const uint TypeIndexAllocation = 0xA0;
    public const uint TypeReparsePoint = 0xC0;
    private const uint EndMarker = 0xFFFF_FFFF;
    private const int MaxAttributes = 512;

    private MftRecord(ulong entry) => Entry = entry;

    /// <summary>Position of the record in $MFT (the authoritative entry number).</summary>
    public ulong Entry { get; }

    public MftRecordState State { get; private set; }

    /// <summary>Whether every sector of the record carried the update sequence value (no torn write).</summary>
    public bool FixupOk { get; private set; }

    public ushort Sequence { get; private set; }

    public ushort LinkCount { get; private set; }

    public ushort Flags { get; private set; }

    public bool InUse => (Flags & 0x0001) != 0;

    public bool IsDirectory => (Flags & 0x0002) != 0;

    public long LogFileSequenceNumber { get; private set; }

    /// <summary>For an extension record: the base record it belongs to; empty for a base record.</summary>
    public FileReference BaseRecord { get; private set; }

    public bool IsExtension => !BaseRecord.IsEmpty;

    /// <summary>Entry number stored in the header (NTFS 3.1+); may differ from <see cref="Entry"/> in a damaged record.</summary>
    public uint? HeaderEntryNumber { get; private set; }

    public StandardInformation? StandardInformation { get; private set; }

    public List<FileNameAttribute> FileNames { get; } = [];

    public List<DataAttribute> Data { get; } = [];

    public List<AttributeListEntry>? AttributeList { get; private set; }

    public bool HasReparsePoint { get; private set; }

    /// <summary>The $ATTRIBUTE_LIST is stored outside the record and was not read.</summary>
    public bool HasNonResidentAttributeList { get; private set; }

    public bool HasIndexRoot { get; private set; }

    public List<string> Problems { get; } = [];

    /// <summary>Bytes in use according to the header.</summary>
    public int UsedSize { get; private set; }

    /// <summary>Offset just past the end marker of the attribute chain.</summary>
    public int AttributesEnd { get; private set; }

    /// <summary>A free record whose attributes extend past its used size: they are remnants of the deleted object.</summary>
    public bool HasRemnantAttributes { get; private set; }

    /// <summary>The long name: Win32 or POSIX if present, the DOS 8.3 name only as a last resort.</summary>
    public FileNameAttribute? PrimaryName =>
        FileNames.FirstOrDefault(f => f.Namespace is FileNameNamespace.Win32AndDos or FileNameNamespace.Win32)
        ?? FileNames.FirstOrDefault(f => f.Namespace == FileNameNamespace.Posix)
        ?? FileNames.FirstOrDefault();

    /// <summary>The unnamed $DATA stream (file content), if this record holds it.</summary>
    public DataAttribute? MainData => Data.FirstOrDefault(d => d.Name.Length == 0 && d.StartVcn == 0);

    /// <summary>The reference other records use for this file while it is in use.</summary>
    public FileReference Reference => new(Entry, Sequence);

    /// <summary>Parses one FILE record. <paramref name="raw"/> is not modified; fixups are applied to a copy.</summary>
    /// <param name="entry">Index of the record in $MFT.</param>
    /// <param name="includeRuns">Decode data runs of non-resident $DATA (needed for $MFT itself; costs memory).</param>
    /// <param name="maxResidentBytes">Resident $DATA values up to this size are kept (small files, Zone.Identifier).</param>
    public static MftRecord Parse(ReadOnlySpan<byte> raw, ulong entry, bool includeRuns = false, int maxResidentBytes = 1024)
    {
        var r = new MftRecord(entry);
        if (raw.Length < 48)
        {
            r.State = MftRecordState.Invalid;
            r.Problems.Add("Запись короче заголовка.");
            return r;
        }

        if (raw.IndexOfAnyExcept((byte)0) < 0)
        {
            r.State = MftRecordState.Empty;
            return r;
        }

        if (!raw[..4].SequenceEqual("FILE"u8))
        {
            r.State = MftRecordState.Invalid;
            r.Problems.Add(raw[..4].SequenceEqual("BAAD"u8)
                ? "Запись помечена системой как повреждённая (BAAD)."
                : "Нет подписи FILE.");
            return r;
        }

        var buffer = raw.ToArray();
        var b = buffer.AsSpan();
        r.FixupOk = ApplyFixup(b, r.Problems);
        r.LogFileSequenceNumber = BinaryPrimitives.ReadInt64LittleEndian(b[8..]);
        r.Sequence = BinaryPrimitives.ReadUInt16LittleEndian(b[16..]);
        r.LinkCount = BinaryPrimitives.ReadUInt16LittleEndian(b[18..]);
        int firstAttribute = BinaryPrimitives.ReadUInt16LittleEndian(b[20..]);
        r.Flags = BinaryPrimitives.ReadUInt16LittleEndian(b[22..]);
        var used = BinaryPrimitives.ReadUInt32LittleEndian(b[24..]);
        r.BaseRecord = FileReference.FromRaw(BinaryPrimitives.ReadUInt64LittleEndian(b[32..]));
        int usaOffset = BinaryPrimitives.ReadUInt16LittleEndian(b[4..]);
        if (usaOffset >= 48)
        {
            r.HeaderEntryNumber = BinaryPrimitives.ReadUInt32LittleEndian(b[44..]);
            // Reserved and never-used records keep 0 here; only a live record with another number is suspicious.
            if (r.HeaderEntryNumber != (uint)entry && r.HeaderEntryNumber != 0)
            {
                r.Problems.Add($"Номер в заголовке ({r.HeaderEntryNumber}) не совпадает с позицией записи ({entry}).");
            }
        }

        if (used > b.Length)
        {
            r.Problems.Add($"Занятый размер {used} больше размера записи {b.Length}.");
        }

        // Attributes are read up to the end marker within the whole record, not only within the used size:
        // when NTFS frees a record it may shrink the used size while the attribute chain stays intact.
        r.State = MftRecordState.Parsed;
        r.UsedSize = (int)Math.Min(used, (uint)b.Length);
        r.ParseAttributes(b, firstAttribute, b.Length, includeRuns, maxResidentBytes);
        if (r.AttributesEnd > r.UsedSize)
        {
            if (r.InUse)
            {
                r.Problems.Add($"Атрибуты продолжаются за занятым размером записи ({r.AttributesEnd} > {r.UsedSize}).");
            }
            else
            {
                r.HasRemnantAttributes = true;
            }
        }

        return r;
    }

    /// <summary>Checks and undoes the update sequence: the last two bytes of every stride hold a check value.</summary>
    private static bool ApplyFixup(Span<byte> b, List<string> problems)
    {
        int offset = BinaryPrimitives.ReadUInt16LittleEndian(b[4..]);
        int count = BinaryPrimitives.ReadUInt16LittleEndian(b[6..]);
        if (count < 2 || offset < 40 || offset + (count * 2) > b.Length)
        {
            problems.Add("Массив проверки секторов (update sequence) вне записи.");
            return false;
        }

        var stride = b.Length / (count - 1);
        if (stride < 256 || stride * (count - 1) != b.Length)
        {
            problems.Add($"Размер записи {b.Length} не делится на {count - 1} секторов.");
            return false;
        }

        var check = BinaryPrimitives.ReadUInt16LittleEndian(b[offset..]);
        var ok = true;
        for (var i = 1; i < count; i++)
        {
            var at = (i * stride) - 2;
            if (BinaryPrimitives.ReadUInt16LittleEndian(b[at..]) != check)
            {
                ok = false;
            }

            b[(offset + (i * 2))..(offset + (i * 2) + 2)].CopyTo(b[at..]);
        }

        if (!ok)
        {
            problems.Add("Проверка секторов не сошлась: запись могла быть записана не полностью.");
        }

        return ok;
    }

    private void ParseAttributes(ReadOnlySpan<byte> b, int offset, int end, bool includeRuns, int maxResidentBytes)
    {
        if (offset < 24 || offset >= end)
        {
            Problems.Add($"Смещение первого атрибута {offset} вне записи.");
            return;
        }

        for (var n = 0; n < MaxAttributes; n++)
        {
            if (offset + 4 > end)
            {
                Problems.Add("Список атрибутов не закончен маркером конца.");
                return;
            }

            var type = BinaryPrimitives.ReadUInt32LittleEndian(b[offset..]);
            if (type == EndMarker)
            {
                AttributesEnd = offset + 4;
                return;
            }

            if (offset + 16 > end)
            {
                Problems.Add($"Заголовок атрибута 0x{type:X} обрезан.");
                return;
            }

            var length = BinaryPrimitives.ReadUInt32LittleEndian(b[(offset + 4)..]);
            if (length < 16 || length > (uint)(end - offset) || length % 8 != 0)
            {
                Problems.Add($"Длина атрибута 0x{type:X} ({length}) недопустима.");
                return;
            }

            ParseAttribute(b.Slice(offset, (int)length), type, includeRuns, maxResidentBytes);
            offset += (int)length;
        }

        Problems.Add($"Больше {MaxAttributes} атрибутов: разбор остановлен.");
    }

    private void ParseAttribute(ReadOnlySpan<byte> a, uint type, bool includeRuns, int maxResidentBytes)
    {
        var nonResident = a[8] != 0;
        int nameLength = a[9];
        int nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(a[10..]);
        var flags = BinaryPrimitives.ReadUInt16LittleEndian(a[12..]);
        var name = string.Empty;
        if (nameLength > 0)
        {
            if (nameOffset + (nameLength * 2) > a.Length)
            {
                Problems.Add($"Имя атрибута 0x{type:X} вне атрибута.");
                return;
            }

            name = Encoding.Unicode.GetString(a.Slice(nameOffset, nameLength * 2));
        }

        if (!nonResident)
        {
            if (a.Length < 24)
            {
                Problems.Add($"Резидентный атрибут 0x{type:X} короче заголовка.");
                return;
            }

            var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(a[16..]);
            int valueOffset = BinaryPrimitives.ReadUInt16LittleEndian(a[20..]);
            if (valueOffset > a.Length || valueLength > (uint)(a.Length - valueOffset))
            {
                Problems.Add($"Значение атрибута 0x{type:X} вне атрибута.");
                return;
            }

            ParseResident(type, name, flags, a.Slice(valueOffset, (int)valueLength), maxResidentBytes);
            return;
        }

        if (a.Length < 64)
        {
            Problems.Add($"Нерезидентный атрибут 0x{type:X} короче заголовка.");
            return;
        }

        var startVcn = BinaryPrimitives.ReadInt64LittleEndian(a[16..]);
        int runsOffset = BinaryPrimitives.ReadUInt16LittleEndian(a[32..]);
        var allocated = BinaryPrimitives.ReadInt64LittleEndian(a[40..]);
        var size = BinaryPrimitives.ReadInt64LittleEndian(a[48..]);
        switch (type)
        {
            case TypeData:
                IReadOnlyList<DataRun>? runs = null;
                if (includeRuns)
                {
                    if (runsOffset >= a.Length)
                    {
                        Problems.Add($"Цепочка кластеров потока «{name}» вне атрибута.");
                    }
                    else
                    {
                        var decoded = DataRuns.Decode(a[runsOffset..], out var runProblem);
                        runs = decoded;
                        if (runProblem is not null)
                        {
                            Problems.Add(runProblem);
                        }
                    }
                }

                // Only the first segment (StartVcn 0) carries sizes; later segments repeat zeros.
                Data.Add(new DataAttribute(name, true, startVcn == 0 ? size : 0, startVcn == 0 ? allocated : 0, startVcn, flags, runs, null));
                break;
            case TypeAttributeList:
                // Not read (it would need volume access). Names and streams in extension records are still
                // found, because every extension record is read on its own and refers back to its base.
                HasNonResidentAttributeList = true;
                break;
            case TypeIndexAllocation:
                break;
            default:
                break;
        }
    }

    private void ParseResident(uint type, string name, ushort flags, ReadOnlySpan<byte> v, int maxResidentBytes)
    {
        switch (type)
        {
            case TypeStandardInformation:
                if (v.Length < 48)
                {
                    Problems.Add("$STANDARD_INFORMATION короче 48 байт.");
                    return;
                }

                StandardInformation = new StandardInformation(
                    ReadTimes(v),
                    BinaryPrimitives.ReadUInt32LittleEndian(v[32..]),
                    v.Length >= 56 ? BinaryPrimitives.ReadUInt32LittleEndian(v[52..]) : null,
                    v.Length >= 72 ? BinaryPrimitives.ReadInt64LittleEndian(v[64..]) : null);
                break;

            case TypeFileName:
                if (v.Length < 66)
                {
                    Problems.Add("$FILE_NAME короче 66 байт.");
                    return;
                }

                int chars = v[64];
                if (66 + (chars * 2) > v.Length)
                {
                    Problems.Add("Имя в $FILE_NAME выходит за атрибут.");
                    return;
                }

                var ns = v[65];
                FileNames.Add(new FileNameAttribute(
                    FileReference.FromRaw(BinaryPrimitives.ReadUInt64LittleEndian(v)),
                    ReadTimes(v[8..]),
                    BinaryPrimitives.ReadInt64LittleEndian(v[40..]),
                    BinaryPrimitives.ReadInt64LittleEndian(v[48..]),
                    BinaryPrimitives.ReadUInt32LittleEndian(v[56..]),
                    ns <= 3 ? (FileNameNamespace)ns : FileNameNamespace.Posix,
                    Encoding.Unicode.GetString(v.Slice(66, chars * 2))));
                break;

            case TypeData:
                Data.Add(new DataAttribute(name, false, v.Length, v.Length, 0, flags, null, v.Length <= maxResidentBytes ? v.ToArray() : null));
                break;

            case TypeAttributeList:
                AttributeList = ParseAttributeList(v);
                break;

            case TypeIndexRoot:
                HasIndexRoot = true;
                break;

            case TypeReparsePoint:
                HasReparsePoint = true;
                break;

            default:
                break;
        }
    }

    private List<AttributeListEntry> ParseAttributeList(ReadOnlySpan<byte> v)
    {
        var list = new List<AttributeListEntry>();
        var o = 0;
        while (o + 26 <= v.Length && list.Count < MaxAttributes)
        {
            var type = BinaryPrimitives.ReadUInt32LittleEndian(v[o..]);
            int length = BinaryPrimitives.ReadUInt16LittleEndian(v[(o + 4)..]);
            int nameLength = v[o + 6];
            int nameOffset = v[o + 7];
            if (length < 26 || o + length > v.Length)
            {
                Problems.Add("Повреждённый элемент списка атрибутов.");
                break;
            }

            var name = nameLength > 0 && nameOffset + (nameLength * 2) <= length
                ? Encoding.Unicode.GetString(v.Slice(o + nameOffset, nameLength * 2))
                : string.Empty;
            list.Add(new AttributeListEntry(
                type,
                name,
                BinaryPrimitives.ReadInt64LittleEndian(v[(o + 8)..]),
                FileReference.FromRaw(BinaryPrimitives.ReadUInt64LittleEndian(v[(o + 16)..])),
                BinaryPrimitives.ReadUInt16LittleEndian(v[(o + 24)..])));
            o += (length + 7) & ~7;
        }

        return list;
    }

    private static NtfsTimes ReadTimes(ReadOnlySpan<byte> v) => new(
        BinaryPrimitives.ReadInt64LittleEndian(v),
        BinaryPrimitives.ReadInt64LittleEndian(v[8..]),
        BinaryPrimitives.ReadInt64LittleEndian(v[16..]),
        BinaryPrimitives.ReadInt64LittleEndian(v[24..]));
}
