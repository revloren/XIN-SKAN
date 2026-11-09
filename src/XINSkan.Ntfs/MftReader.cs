using System.Buffers.Binary;

namespace XINSkan.Ntfs;

/// <summary>Raw, read-only access to a volume (or a disk image) by byte offset.</summary>
public interface IRawVolume
{
    /// <summary>Reads up to <paramref name="buffer"/>.Length bytes at <paramref name="offset"/>; returns bytes read.</summary>
    int Read(long offset, Span<byte> buffer);
}

/// <summary>A disk image or extracted volume in a stream (tests and offline images).</summary>
public sealed class StreamVolume(Stream stream) : IRawVolume
{
    private readonly Lock _gate = new();

    public int Read(long offset, Span<byte> buffer)
    {
        lock (_gate)
        {
            if (offset >= stream.Length)
            {
                return 0;
            }

            stream.Position = offset;
            return stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
        }
    }
}

/// <summary>Geometry from the NTFS boot sector.</summary>
public sealed record NtfsBootSector(int BytesPerSector, int BytesPerCluster, int BytesPerRecord, long MftLcn, long MftMirrLcn, ulong VolumeSerial, long TotalSectors)
{
    public static NtfsBootSector Parse(ReadOnlySpan<byte> b)
    {
        if (b.Length < 512 || !b.Slice(3, 8).SequenceEqual("NTFS    "u8))
        {
            throw new InvalidDataException("Не загрузочный сектор NTFS.");
        }

        int bytesPerSector = BinaryPrimitives.ReadUInt16LittleEndian(b[11..]);
        int spc = b[13];
        var sectorsPerCluster = spc <= 0x80 ? spc : 1 << (256 - spc);
        var cluster = bytesPerSector * sectorsPerCluster;
        var cpr = (sbyte)b[64];
        var record = cpr > 0 ? cpr * cluster : 1 << -cpr;
        if (bytesPerSector is < 256 or > 4096 || (bytesPerSector & (bytesPerSector - 1)) != 0 || cluster is < 256 or > 2 * 1024 * 1024
            || record is < 256 or > 65536)
        {
            throw new InvalidDataException($"Неправдоподобная геометрия NTFS: сектор {bytesPerSector}, кластер {cluster}, запись {record}.");
        }

        return new NtfsBootSector(
            bytesPerSector,
            cluster,
            record,
            BinaryPrimitives.ReadInt64LittleEndian(b[48..]),
            BinaryPrimitives.ReadInt64LittleEndian(b[56..]),
            BinaryPrimitives.ReadUInt64LittleEndian(b[72..]),
            BinaryPrimitives.ReadInt64LittleEndian(b[40..]));
    }
}

/// <summary>One record as read from $MFT. <see cref="Bytes"/> is valid only until the enumeration moves on.</summary>
public readonly record struct MftRawRecord(ulong Entry, ReadOnlyMemory<byte> Bytes);

/// <summary>Statistics of one pass over $MFT.</summary>
public sealed class MftReadStatistics
{
    public long Records { get; internal set; }

    public long BytesRead { get; internal set; }

    public long UnreadableBytes { get; internal set; }
}

/// <summary>
/// Streams $MFT record by record, in large reads, without holding it in memory. The location of $MFT comes from
/// its own record 0 (data runs), so a fragmented $MFT is read correctly.
/// </summary>
public sealed class MftReader
{
    private const int ChunkRecords = 1024;

    private readonly IRawVolume _volume;
    private readonly List<(long Offset, long Length)> _extents;

    private MftReader(IRawVolume volume, NtfsBootSector boot, List<(long Offset, long Length)> extents, long size, List<string> problems)
    {
        _volume = volume;
        Boot = boot;
        _extents = extents;
        Size = size;
        Problems = problems;
    }

    public NtfsBootSector Boot { get; }

    /// <summary>Size of $MFT in bytes (from its $DATA attribute).</summary>
    public long Size { get; }

    public long RecordCount => Size / Boot.BytesPerRecord;

    public List<string> Problems { get; }

    public MftReadStatistics Statistics { get; } = new();

    /// <summary>Opens $MFT on an NTFS volume or image: boot sector → record 0 → its data runs.</summary>
    public static MftReader Open(IRawVolume volume)
    {
        ArgumentNullException.ThrowIfNull(volume);
        var bootBytes = new byte[512];
        if (volume.Read(0, bootBytes) < 512)
        {
            throw new InvalidDataException("Загрузочный сектор не прочитан.");
        }

        var boot = NtfsBootSector.Parse(bootBytes);
        var problems = new List<string>();
        var recordBytes = new byte[boot.BytesPerRecord];
        if (volume.Read(boot.MftLcn * boot.BytesPerCluster, recordBytes) < recordBytes.Length)
        {
            throw new InvalidDataException("Запись 0 ($MFT) не прочитана.");
        }

        var mft = MftRecord.Parse(recordBytes, 0, includeRuns: true);
        if (mft.State != MftRecordState.Parsed || mft.MainData is not { NonResident: true, Runs: not null } data)
        {
            throw new InvalidDataException("Запись $MFT не содержит расположения таблицы: " + string.Join(" ", mft.Problems));
        }

        problems.AddRange(mft.Problems.Select(p => "Запись $MFT: " + p));
        var runs = new List<DataRun>(data.Runs);
        var size = data.Size;

        // A very fragmented $MFT keeps later runs in extension records listed in its $ATTRIBUTE_LIST.
        if (mft.AttributeList is { } list)
        {
            var known = ToExtents(runs, boot.BytesPerCluster);
            foreach (var e in list.Where(e => e.Type == MftRecord.TypeData && e.Name.Length == 0 && e.StartVcn > 0).OrderBy(e => e.StartVcn))
            {
                var ext = ReadRecordAt(volume, known, boot, e.Record.Entry);
                var parsed = ext is null ? null : MftRecord.Parse(ext, e.Record.Entry, includeRuns: true);
                var segment = parsed?.Data.FirstOrDefault(d => d.Name.Length == 0 && d.StartVcn == e.StartVcn);
                if (segment?.Runs is null)
                {
                    problems.Add($"Продолжение $MFT в записи {e.Record} не прочитано; таблица прочитана не полностью.");
                    break;
                }

                runs.AddRange(segment.Runs);
                known = ToExtents(runs, boot.BytesPerCluster);
            }
        }

        var extents = ToExtents(runs, boot.BytesPerCluster);
        var mapped = extents.Sum(x => x.Length);
        if (mapped < size)
        {
            problems.Add($"Цепочка кластеров $MFT покрывает {mapped} из {size} байт.");
            size = mapped;
        }

        return new MftReader(volume, boot, extents, size, problems);
    }

    /// <summary>Reads one record by its number (raw bytes, fixups not applied); null when it is outside $MFT or unreadable.</summary>
    public byte[]? ReadRecord(ulong entry)
    {
        try
        {
            return (long)entry < RecordCount ? ReadRecordAt(_volume, _extents, Boot, entry) : null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>Reads bytes of the volume (for file content located through data runs).</summary>
    public int ReadVolume(long offset, Span<byte> buffer) => _volume.Read(offset, buffer);

    /// <summary>Enumerates every record in order. A failed read yields nothing for those records and is counted.</summary>
    public IEnumerable<MftRawRecord> ReadRecords(CancellationToken cancellationToken = default)
    {
        var recordSize = Boot.BytesPerRecord;
        var chunk = new byte[ChunkRecords * recordSize];
        long fileOffset = 0;
        foreach (var (volumeOffset, length) in _extents)
        {
            long done = 0;
            while (done < length && fileOffset < Size)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var want = (int)Math.Min(Math.Min(chunk.Length, length - done), Size - fileOffset);
                want -= want % recordSize;
                if (want == 0)
                {
                    break;
                }

                int got;
                try
                {
                    got = _volume.Read(volumeOffset + done, chunk.AsSpan(0, want));
                }
                catch (IOException)
                {
                    got = 0;
                }

                Statistics.BytesRead += got;
                if (got < want)
                {
                    Statistics.UnreadableBytes += want - got;
                }

                var whole = got - (got % recordSize);
                for (var o = 0; o < whole; o += recordSize)
                {
                    Statistics.Records++;
                    yield return new MftRawRecord((ulong)((fileOffset + o) / recordSize), chunk.AsMemory(o, recordSize));
                }

                done += want;
                fileOffset += want;
            }
        }
    }

    /// <summary>Records from an extracted $MFT file (as produced by forensic tools), for tests and offline use.</summary>
    public static IEnumerable<MftRawRecord> ReadExtracted(Stream mft, int recordSize = 0)
    {
        ArgumentNullException.ThrowIfNull(mft);
        if (recordSize == 0)
        {
            var head = new byte[48];
            if (mft.ReadAtLeast(head, 48, throwOnEndOfStream: false) < 48 || !head.AsSpan(0, 4).SequenceEqual("FILE"u8))
            {
                throw new InvalidDataException("Файл не начинается с записи FILE.");
            }

            recordSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(28));
            if (recordSize is < 256 or > 65536 || (recordSize & (recordSize - 1)) != 0)
            {
                throw new InvalidDataException($"Неправдоподобный размер записи {recordSize}.");
            }

            mft.Position = 0;
        }

        var buffer = new byte[recordSize * ChunkRecords];
        ulong entry = 0;
        int got;
        while ((got = mft.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false)) > 0)
        {
            for (var o = 0; o + recordSize <= got; o += recordSize)
            {
                yield return new MftRawRecord(entry++, buffer.AsMemory(o, recordSize));
            }
        }
    }

    private static byte[]? ReadRecordAt(IRawVolume volume, List<(long Offset, long Length)> extents, NtfsBootSector boot, ulong entry)
    {
        var at = (long)entry * boot.BytesPerRecord;
        foreach (var (offset, length) in extents)
        {
            if (at < length)
            {
                var buffer = new byte[boot.BytesPerRecord];
                return volume.Read(offset + at, buffer) == buffer.Length ? buffer : null;
            }

            at -= length;
        }

        return null;
    }

    private static List<(long Offset, long Length)> ToExtents(List<DataRun> runs, int cluster)
    {
        var list = new List<(long, long)>(runs.Count);
        foreach (var r in runs)
        {
            if (r.Lcn is not { } lcn)
            {
                break; // $MFT is never sparse; stop rather than map zeros as records.
            }

            list.Add((lcn * cluster, r.Length * cluster));
        }

        return list;
    }
}
