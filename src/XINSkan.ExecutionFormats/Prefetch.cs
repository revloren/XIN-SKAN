using System.Buffers.Binary;
using System.Text;

namespace XINSkan.ExecutionFormats;

/// <summary>A volume a prefetched program touched: device path, serial, creation time, folders and file references.</summary>
public sealed record PrefetchVolume(string DevicePath, uint Serial, long Created, IReadOnlyList<string> Directories, IReadOnlyList<(ulong Entry, ushort Sequence)> FileReferences);

/// <summary>A file the program loaded in its first seconds (from the file metrics), with its MFT reference.</summary>
public sealed record PrefetchFileEntry(string Path, ulong? MftEntry, ushort? MftSequence);

/// <summary>A parsed Prefetch file (versions 17, 23, 26, 30, 31). Never throws; problems are listed.</summary>
public sealed class PrefetchFile
{
    public const int MaxCompressed = 16 * 1024 * 1024;
    public const int MaxDecompressed = 64 * 1024 * 1024;

    public int Version { get; private set; }

    public bool WasCompressed { get; private set; }

    public string ExecutableName { get; private set; } = string.Empty;

    public uint Hash { get; private set; }

    /// <summary>Up to eight last run times (FILETIME, UTC), newest first; one in versions 17 and 23.</summary>
    public List<long> LastRunTimes { get; } = [];

    public int RunCount { get; private set; }

    public List<PrefetchFileEntry> Files { get; } = [];

    public List<PrefetchVolume> Volumes { get; } = [];

    public List<string> Problems { get; } = [];

    /// <summary>Parses a .pf file (MAM-compressed or not). Returns null only when it is not a Prefetch file.</summary>
    public static PrefetchFile? Parse(ReadOnlySpan<byte> data)
    {
        var pf = new PrefetchFile();
        byte[] raw;
        if (data.Length >= 8 && data[..3].SequenceEqual("MAM"u8))
        {
            pf.WasCompressed = true;
            var format = data[3] & 0x0F;
            var checksum = (data[3] & 0x80) != 0;
            var size = BinaryPrimitives.ReadUInt32LittleEndian(data[4..]);
            if (format != 4)
            {
                pf.Problems.Add($"Неподдерживаемое сжатие MAM {format}.");
                return pf;
            }

            if (size > MaxDecompressed)
            {
                pf.Problems.Add($"Размер после распаковки {size} больше предела.");
                return pf;
            }

            var start = checksum ? 12 : 8;
            try
            {
                raw = XpressHuffman.Decompress(data[Math.Min(start, data.Length)..], (int)size);
            }
            catch (InvalidDataException ex)
            {
                pf.Problems.Add("Распаковка не удалась: " + ex.Message);
                return pf;
            }
        }
        else
        {
            raw = data.ToArray();
        }

        if (raw.Length < 84 || !raw.AsSpan(4, 4).SequenceEqual("SCCA"u8))
        {
            return pf.WasCompressed ? pf.WithProblem("После распаковки нет подписи SCCA.") : null;
        }

        pf.Version = BinaryPrimitives.ReadInt32LittleEndian(raw);
        var name = Encoding.Unicode.GetString(raw.AsSpan(16, 60));
        var nul = name.IndexOf('\0', StringComparison.Ordinal);
        pf.ExecutableName = nul < 0 ? name : name[..nul];
        pf.Hash = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(76));
        var layout = pf.Version switch
        {
            17 => new Layout(68, 36, 1, 60, false, 20, 40),
            23 => new Layout(156, 44, 1, 68, false, 32, 104),
            26 => new Layout(224, 44, 8, 124, false, 32, 104),
            30 or 31 => new Layout(224, 44, 8, 124, true, 32, 96),
            _ => null,
        };
        if (layout is null)
        {
            pf.Problems.Add($"Неизвестная версия Prefetch {pf.Version}.");
            return pf;
        }

        pf.ParseBody(raw, layout);
        return pf;
    }

    private PrefetchFile WithProblem(string problem)
    {
        Problems.Add(problem);
        return this;
    }

    private sealed record Layout(int InfoSize, int RunTimesOffset, int RunTimes, int RunCountOffset, bool RunCountMayMove, int MetricSize, int VolumeEntrySize);

    private void ParseBody(byte[] raw, Layout l)
    {
        if (84 + l.InfoSize > raw.Length)
        {
            Problems.Add("Блок сведений о файле обрезан.");
            return;
        }

        var info = raw.AsSpan(84, l.InfoSize);
        var metricsOffset = BinaryPrimitives.ReadInt32LittleEndian(info);
        var metricsCount = BinaryPrimitives.ReadInt32LittleEndian(info[4..]);
        var stringsOffset = BinaryPrimitives.ReadInt32LittleEndian(info[16..]);
        var stringsSize = BinaryPrimitives.ReadInt32LittleEndian(info[20..]);
        var volumesOffset = BinaryPrimitives.ReadInt32LittleEndian(info[24..]);
        var volumeCount = BinaryPrimitives.ReadInt32LittleEndian(info[28..]);
        var volumesSize = BinaryPrimitives.ReadInt32LittleEndian(info[32..]);
        for (var i = 0; i < l.RunTimes; i++)
        {
            var t = BinaryPrimitives.ReadInt64LittleEndian(info[(l.RunTimesOffset + (i * 8))..]);
            if (t != 0 || l.RunTimes == 1)
            {
                LastRunTimes.Add(t);
            }
        }

        RunCount = BinaryPrimitives.ReadInt32LittleEndian(info[l.RunCountOffset..]);

        // Newer Windows 10/11 builds moved the run count 8 bytes back; the old place then has a nonzero value before it.
        if (l.RunCountMayMove && BinaryPrimitives.ReadInt32LittleEndian(info[(l.RunCountOffset - 4)..]) != 0)
        {
            RunCount = BinaryPrimitives.ReadInt32LittleEndian(info[(l.RunCountOffset - 8)..]);
        }

        // File names and, per name, the MFT reference from the file metrics.
        if (InRange(raw, stringsOffset, stringsSize))
        {
            var strings = raw.AsSpan(stringsOffset, stringsSize);
            if (InRange(raw, metricsOffset, (long)metricsCount * l.MetricSize) && metricsCount is >= 0 and <= 100_000)
            {
                for (var i = 0; i < metricsCount; i++)
                {
                    var m = raw.AsSpan(metricsOffset + (i * l.MetricSize), l.MetricSize);
                    int nameOffset, nameChars;
                    ulong? entry = null;
                    ushort? seq = null;
                    if (l.MetricSize == 20)
                    {
                        nameOffset = BinaryPrimitives.ReadInt32LittleEndian(m[8..]);
                        nameChars = BinaryPrimitives.ReadInt32LittleEndian(m[12..]);
                    }
                    else
                    {
                        nameOffset = BinaryPrimitives.ReadInt32LittleEndian(m[12..]);
                        nameChars = BinaryPrimitives.ReadInt32LittleEndian(m[16..]);
                        var low = BinaryPrimitives.ReadUInt32LittleEndian(m[24..]);
                        var high = BinaryPrimitives.ReadUInt16LittleEndian(m[28..]);
                        var s = BinaryPrimitives.ReadUInt16LittleEndian(m[30..]);
                        if (low != 0 || high != 0 || s != 0)
                        {
                            entry = ((ulong)high << 32) | low;
                            seq = s;
                        }
                    }

                    // Offsets into the strings are in bytes; lengths in characters.
                    if (nameOffset >= 0 && nameChars is > 0 and <= 32_768 && (long)nameOffset + ((long)nameChars * 2) <= strings.Length)
                    {
                        Files.Add(new PrefetchFileEntry(Encoding.Unicode.GetString(strings.Slice(nameOffset, nameChars * 2)), entry, seq));
                    }
                    else
                    {
                        Problems.Add($"Имя файла метрики {i} вне таблицы строк.");
                    }
                }
            }
            else
            {
                Problems.Add("Метрики файлов вне файла; имена взяты из таблицы строк без ссылок MFT.");
                foreach (var n in Encoding.Unicode.GetString(strings).Split('\0', StringSplitOptions.RemoveEmptyEntries))
                {
                    Files.Add(new PrefetchFileEntry(n, null, null));
                }
            }
        }
        else
        {
            Problems.Add("Таблица имён файлов вне файла.");
        }

        ParseVolumes(raw, volumesOffset, volumeCount, volumesSize, l);
    }

    private void ParseVolumes(byte[] raw, int offset, int count, int size, Layout l)
    {
        if (!InRange(raw, offset, size) || count is < 0 or > 1000 || (long)count * l.VolumeEntrySize > size)
        {
            Problems.Add("Сведения о томах вне файла.");
            return;
        }

        var block = raw.AsSpan(offset, size);
        for (var j = 0; j < count; j++)
        {
            var e = block.Slice(j * l.VolumeEntrySize, l.VolumeEntrySize);
            var devOffset = BinaryPrimitives.ReadInt32LittleEndian(e);
            var devChars = BinaryPrimitives.ReadInt32LittleEndian(e[4..]);
            var created = BinaryPrimitives.ReadInt64LittleEndian(e[8..]);
            var serial = BinaryPrimitives.ReadUInt32LittleEndian(e[16..]);
            var refsOffset = BinaryPrimitives.ReadInt32LittleEndian(e[20..]);
            var refsSize = BinaryPrimitives.ReadInt32LittleEndian(e[24..]);
            var dirsOffset = BinaryPrimitives.ReadInt32LittleEndian(e[28..]);
            var dirsCount = BinaryPrimitives.ReadInt32LittleEndian(e[32..]);
            var device = devOffset >= 0 && devChars is >= 0 and <= 1024 && (long)devOffset + ((long)devChars * 2) <= block.Length
                ? Encoding.Unicode.GetString(block.Slice(devOffset, devChars * 2))
                : string.Empty;

            var refs = new List<(ulong, ushort)>();
            if (refsSize > 0 && refsOffset >= 0 && (long)refsOffset + refsSize <= block.Length && refsSize >= 8)
            {
                var r = block.Slice(refsOffset, refsSize);
                var version = BinaryPrimitives.ReadInt32LittleEndian(r);
                var n = BinaryPrimitives.ReadInt32LittleEndian(r[4..]);
                var start = version >= 3 ? 16 : 8;
                if (n >= 0 && start + ((long)n * 8) <= r.Length)
                {
                    for (var i = 0; i < n; i++)
                    {
                        var low = BinaryPrimitives.ReadUInt32LittleEndian(r[(start + (i * 8))..]);
                        var high = BinaryPrimitives.ReadUInt16LittleEndian(r[(start + (i * 8) + 4)..]);
                        refs.Add((((ulong)high << 32) | low, BinaryPrimitives.ReadUInt16LittleEndian(r[(start + (i * 8) + 6)..])));
                    }
                }
                else
                {
                    Problems.Add($"Ссылки MFT тома {j} вне блока.");
                }
            }

            var dirs = new List<string>();
            var pos = (long)dirsOffset;
            for (var k = 0; k < dirsCount && k < 100_000 && dirsOffset >= 0; k++)
            {
                if (pos + 2 > block.Length)
                {
                    Problems.Add($"Имена папок тома {j} обрезаны.");
                    break;
                }

                int chars = BinaryPrimitives.ReadUInt16LittleEndian(block[(int)pos..]);
                pos += 2;
                var bytes = (chars * 2) + 2;
                if (pos + bytes > block.Length)
                {
                    Problems.Add($"Имена папок тома {j} обрезаны.");
                    break;
                }

                dirs.Add(Encoding.Unicode.GetString(block.Slice((int)pos, chars * 2)));
                pos += bytes;
            }

            Volumes.Add(new PrefetchVolume(device, serial, created, dirs, refs));
        }
    }

    private static bool InRange(byte[] raw, long offset, long size) => offset >= 0 && size >= 0 && offset + size <= raw.Length;
}
