using System.Buffers.Binary;
using System.Text;

namespace XINSkan.ShellFormats;

/// <summary>
/// Minimal read-only reader of OLE compound files (MS-CFB, versions 3 and 4) — the container of
/// automaticDestinations-ms. Every sector chain is bounded by the file size and checked for loops.
/// </summary>
public sealed class CompoundFile
{
    public const int MaxBytes = 64 * 1024 * 1024;

    private const uint EndOfChain = 0xFFFF_FFFE;
    private const uint FreeSector = 0xFFFF_FFFF;
    private const int MaxRegular = 0x7FFF_FFF0;

    private readonly byte[] _data;
    private readonly int _sectorSize;
    private readonly int _miniSectorSize;
    private readonly uint _miniCutoff;
    private readonly List<uint> _fat = [];
    private readonly List<uint> _miniFat = [];
    private byte[] _miniStream = [];

    private CompoundFile(byte[] data, int sectorSize, int miniSectorSize, uint miniCutoff)
    {
        _data = data;
        _sectorSize = sectorSize;
        _miniSectorSize = miniSectorSize;
        _miniCutoff = miniCutoff;
    }

    public sealed record Entry(string Name, int Type, uint StartSector, long Size);

    /// <summary>Directory entries (type 1 storage, 2 stream, 5 root).</summary>
    public List<Entry> Entries { get; } = [];

    public List<string> Problems { get; } = [];

    public static bool LooksLikeCompoundFile(ReadOnlySpan<byte> b) =>
        b.Length >= 512 && b[..8].SequenceEqual(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 });

    /// <summary>Opens a compound file; null when it is not one or its header is unusable.</summary>
    public static CompoundFile? Open(byte[] data, out string? problem)
    {
        ArgumentNullException.ThrowIfNull(data);
        problem = null;
        if (!LooksLikeCompoundFile(data))
        {
            problem = "Нет подписи составного файла (OLE).";
            return null;
        }

        var b = data.AsSpan();
        int shift = BinaryPrimitives.ReadUInt16LittleEndian(b[30..]);
        int miniShift = BinaryPrimitives.ReadUInt16LittleEndian(b[32..]);
        if (shift is not (9 or 12) || miniShift != 6)
        {
            problem = $"Неподдерживаемый размер секторов (2^{shift}, мини 2^{miniShift}).";
            return null;
        }

        var cf = new CompoundFile(data, 1 << shift, 1 << miniShift, BinaryPrimitives.ReadUInt32LittleEndian(b[56..]));
        var fatSectors = BinaryPrimitives.ReadUInt32LittleEndian(b[44..]);
        var firstDir = BinaryPrimitives.ReadUInt32LittleEndian(b[48..]);
        var firstMiniFat = BinaryPrimitives.ReadUInt32LittleEndian(b[60..]);
        var firstDifat = BinaryPrimitives.ReadUInt32LittleEndian(b[68..]);
        var difatCount = BinaryPrimitives.ReadUInt32LittleEndian(b[72..]);

        // DIFAT: 109 entries in the header, then a chain of DIFAT sectors.
        var fatSectorList = new List<uint>();
        for (var i = 0; i < 109; i++)
        {
            var s = BinaryPrimitives.ReadUInt32LittleEndian(b[(76 + (i * 4))..]);
            if (s < MaxRegular)
            {
                fatSectorList.Add(s);
            }
        }

        var difat = firstDifat;
        var seen = new HashSet<uint>();
        for (var n = 0; n < difatCount && difat < MaxRegular; n++)
        {
            if (!seen.Add(difat) || cf.SectorSpan(difat) is not { } d)
            {
                cf.Problems.Add("Цепочка DIFAT повреждена.");
                break;
            }

            var per = (cf._sectorSize / 4) - 1;
            for (var i = 0; i < per; i++)
            {
                var s = BinaryPrimitives.ReadUInt32LittleEndian(d.Span[(i * 4)..]);
                if (s < MaxRegular)
                {
                    fatSectorList.Add(s);
                }
            }

            difat = BinaryPrimitives.ReadUInt32LittleEndian(d.Span[(per * 4)..]);
        }

        if (fatSectorList.Count < fatSectors)
        {
            cf.Problems.Add($"Найдено {fatSectorList.Count} секторов FAT из {fatSectors}.");
        }

        foreach (var s in fatSectorList.Take((int)Math.Min(fatSectors, (uint)fatSectorList.Count)))
        {
            if (cf.SectorSpan(s) is not { } f)
            {
                cf.Problems.Add($"Сектор FAT {s} вне файла.");
                continue;
            }

            for (var i = 0; i + 4 <= f.Length; i += 4)
            {
                cf._fat.Add(BinaryPrimitives.ReadUInt32LittleEndian(f.Span[i..]));
            }
        }

        var dir = cf.ReadChain(firstDir, long.MaxValue);
        for (var o = 0; o + 128 <= dir.Length; o += 128)
        {
            var e = dir.AsSpan(o, 128);
            int nameBytes = BinaryPrimitives.ReadUInt16LittleEndian(e[64..]);
            int type = e[66];
            if (type == 0)
            {
                continue;
            }

            var name = nameBytes is >= 2 and <= 64 ? Encoding.Unicode.GetString(e[..(nameBytes - 2)]) : string.Empty;
            var start = BinaryPrimitives.ReadUInt32LittleEndian(e[116..]);
            var rawSize = BinaryPrimitives.ReadUInt64LittleEndian(e[120..]);
            if (shift == 9)
            {
                rawSize &= 0xFFFF_FFFF; // version 3 keeps only 32 bits
            }

            var size = (long)Math.Min(rawSize, (ulong)long.MaxValue);

            cf.Entries.Add(new Entry(name, type, start, size));
        }

        if (cf.Entries.FirstOrDefault(x => x.Type == 5) is { } root)
        {
            cf._miniStream = cf.ReadChain(root.StartSector, root.Size);
            var miniFat = cf.ReadChain(firstMiniFat, long.MaxValue);
            for (var i = 0; i + 4 <= miniFat.Length; i += 4)
            {
                cf._miniFat.Add(BinaryPrimitives.ReadUInt32LittleEndian(miniFat.AsSpan(i)));
            }
        }
        else
        {
            cf.Problems.Add("Нет корневой записи каталога.");
        }

        return cf;
    }

    /// <summary>Contents of a stream by name, or null.</summary>
    public byte[]? ReadStream(string name)
    {
        var e = Entries.FirstOrDefault(x => x.Type == 2 && string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase));
        if (e is null)
        {
            return null;
        }

        if (e.Size > MaxBytes)
        {
            Problems.Add($"Поток {name} больше предела ({e.Size} байт).");
            return null;
        }

        return e.Size < _miniCutoff ? ReadMiniChain(e.StartSector, e.Size, name) : ReadChain(e.StartSector, e.Size);
    }

    private ReadOnlyMemory<byte>? SectorSpan(uint sector)
    {
        // Note: a bare "null" here would convert to an empty ReadOnlyMemory (through the array conversion), not to
        // a null Nullable — found by the damaged-file test. Keep the explicit type.
        var offset = ((long)sector + 1) * _sectorSize;
        return offset + _sectorSize <= _data.Length ? _data.AsMemory((int)offset, _sectorSize) : (ReadOnlyMemory<byte>?)null;
    }

    private byte[] ReadChain(uint start, long size)
    {
        var result = new List<byte>();
        var seen = new HashSet<uint>();
        var s = start;
        var limit = Math.Max(0, Math.Min(size, _data.Length));
        while (s < MaxRegular && result.Count < limit)
        {
            if (!seen.Add(s) || s >= _fat.Count || SectorSpan(s) is not { } span)
            {
                Problems.Add($"Цепочка секторов с {start} повреждена.");
                break;
            }

            result.AddRange(span.Span[..(int)Math.Min(_sectorSize, limit - result.Count)].ToArray());
            s = _fat[(int)s];
        }

        return [.. result];
    }

    private byte[]? ReadMiniChain(uint start, long size, string name)
    {
        var result = new byte[size];
        var seen = new HashSet<uint>();
        var s = start;
        var done = 0;
        while (done < size)
        {
            var offset = (long)s * _miniSectorSize;
            if (s >= _miniFat.Count || !seen.Add(s) || offset >= _miniStream.Length)
            {
                Problems.Add($"Поток {name}: мини-поток обрезан или цепочка повреждена.");
                return done == 0 ? null : result[..done];
            }

            var n = (int)Math.Min(Math.Min(_miniSectorSize, size - done), _miniStream.Length - offset);
            Array.Copy(_miniStream, offset, result, done, n);
            done += n;
            s = _miniFat[(int)s];
            if (s is EndOfChain or FreeSector && done < size)
            {
                Problems.Add($"Поток {name}: цепочка короче размера.");
                return result[..done];
            }
        }

        return result;
    }
}
