using System.Buffers.Binary;
using System.Text;

namespace XINSkan.ExecutionFormats;

/// <summary>A registry value read from a hive file.</summary>
public sealed record HiveValue(string Name, int Type, byte[] Data)
{
    public const int RegSz = 1;
    public const int RegExpandSz = 2;
    public const int RegBinary = 3;
    public const int RegDword = 4;
    public const int RegMultiSz = 7;
    public const int RegQword = 11;

    /// <summary>The value as a string (REG_SZ, REG_EXPAND_SZ; the first string of REG_MULTI_SZ), up to the first NUL.</summary>
    public string? AsString()
    {
        if (Type is not (RegSz or RegExpandSz or RegMultiSz) || Data.Length < 2)
        {
            return Type is RegSz or RegExpandSz ? string.Empty : null;
        }

        var s = Encoding.Unicode.GetString(Data, 0, Data.Length & ~1);
        var nul = s.IndexOf('\0', StringComparison.Ordinal);
        return nul < 0 ? s : s[..nul];
    }

    /// <summary>The value as a number (REG_DWORD, REG_QWORD; also 4- or 8-byte REG_BINARY).</summary>
    public long? AsNumber() => Data.Length switch
    {
        >= 8 when Type is RegQword or RegBinary => BinaryPrimitives.ReadInt64LittleEndian(Data),
        >= 4 when Type is RegDword or RegBinary or RegQword => BinaryPrimitives.ReadUInt32LittleEndian(Data),
        _ => null,
    };
}

/// <summary>A key of a hive file. Subkeys and values are read when asked for.</summary>
public sealed class HiveKey
{
    private readonly RegistryHive _hive;
    private readonly int _subkeyList;
    private readonly int _subkeyCount;
    private readonly int _valueList;
    private readonly int _valueCount;

    internal HiveKey(RegistryHive hive, int offset, string name, long lastWriteTime, int subkeyList, int subkeyCount, int valueList, int valueCount)
    {
        _hive = hive;
        Offset = offset;
        Name = name;
        LastWriteTime = lastWriteTime;
        _subkeyList = subkeyList;
        _subkeyCount = subkeyCount;
        _valueList = valueList;
        _valueCount = valueCount;
    }

    /// <summary>Offset of the key cell from the start of the hive bins.</summary>
    public int Offset { get; }

    public string Name { get; }

    /// <summary>Last write time of the key (FILETIME, UTC).</summary>
    public long LastWriteTime { get; }

    public int SubKeyCount => _subkeyCount;

    public IReadOnlyList<HiveKey> SubKeys() => _subkeyCount == 0 ? [] : _hive.ReadSubKeys(_subkeyList, _subkeyCount);

    public IReadOnlyList<HiveValue> Values() => _valueCount == 0 ? [] : _hive.ReadValues(_valueList, _valueCount);

    public HiveKey? SubKey(string name) => SubKeys().FirstOrDefault(k => string.Equals(k.Name, name, StringComparison.OrdinalIgnoreCase));

    public HiveValue? Value(string name) => Values().FirstOrDefault(v => string.Equals(v.Name, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>A descendant by a backslash-separated path, case-insensitive.</summary>
    public HiveKey? Open(string path)
    {
        var key = this;
        foreach (var part in path.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            key = key?.SubKey(part);
        }

        return key;
    }
}

/// <summary>
/// Read-only parser of registry hive files (regf 1.3–1.6), with recovery of a dirty hive from its transaction
/// logs (new format, Windows 8.1 and later). Every offset and length is checked against the hive; damaged
/// structures are reported in <see cref="Problems"/> and skipped, never thrown.
/// </summary>
public sealed class RegistryHive
{
    public const int MaxBytes = 512 * 1024 * 1024;
    private const int BaseBlockSize = 4096;
    private const int MaxListDepth = 8;
    private const int MaxSubkeys = 2_000_000;
    private const int MaxValues = 1_000_000;
    private const int MaxValueBytes = 16 * 1024 * 1024;
    private const int BigDataSegment = 16344;

    private byte[] _data;
    private int _binsSize;

    private RegistryHive(byte[] data) => _data = data;

    public int MajorVersion { get; private set; }

    public int MinorVersion { get; private set; }

    /// <summary>Last write time from the base block (FILETIME, UTC).</summary>
    public long LastWritten { get; private set; }

    public uint PrimarySequence { get; private set; }

    public uint SecondarySequence { get; private set; }

    /// <summary>The hive was not fully written (sequence numbers or checksum differ): recent changes are in its logs.</summary>
    public bool WasDirty { get; private set; }

    /// <summary>Log entries applied while recovering a dirty hive.</summary>
    public int LogEntriesApplied { get; private set; }

    /// <summary>A dirty hive whose logs could not be applied fully: the newest changes may be missing.</summary>
    public bool RecoveryIncomplete { get; private set; }

    public HiveKey? Root { get; private set; }

    public List<string> Problems { get; } = [];

    public static bool LooksLikeHive(ReadOnlySpan<byte> b) => b.Length >= 512 && b[..4].SequenceEqual("regf"u8);

    /// <summary>Opens a hive; null when the data is not a hive. Logs (.LOG1, .LOG2) are applied when it is dirty.</summary>
    public static RegistryHive? Open(byte[] data, params byte[][] logs)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(logs);
        if (!LooksLikeHive(data) || data.Length < BaseBlockSize)
        {
            return null;
        }

        var hive = new RegistryHive(data);
        hive.ReadBaseBlock();
        if (hive.WasDirty)
        {
            hive.Recover(logs);
        }

        hive.ReadRoot();
        return hive;
    }

    private void ReadBaseBlock()
    {
        var b = _data.AsSpan(0, BaseBlockSize);
        PrimarySequence = BinaryPrimitives.ReadUInt32LittleEndian(b[4..]);
        SecondarySequence = BinaryPrimitives.ReadUInt32LittleEndian(b[8..]);
        LastWritten = BinaryPrimitives.ReadInt64LittleEndian(b[12..]);
        MajorVersion = BinaryPrimitives.ReadInt32LittleEndian(b[20..]);
        MinorVersion = BinaryPrimitives.ReadInt32LittleEndian(b[24..]);
        _binsSize = BinaryPrimitives.ReadInt32LittleEndian(b[40..]);
        var checksumOk = Checksum(b) == BinaryPrimitives.ReadUInt32LittleEndian(b[508..]);
        WasDirty = PrimarySequence != SecondarySequence || !checksumOk;
        if (!checksumOk)
        {
            Problems.Add("Контрольная сумма заголовка куста не совпадает.");
        }

        if (_binsSize <= 0 || (long)BaseBlockSize + _binsSize > _data.Length)
        {
            Problems.Add($"Размер данных куста {_binsSize} не совпадает с файлом ({_data.Length} байт); прочитано то, что есть.");
            _binsSize = _data.Length - BaseBlockSize;
        }
    }

    private static uint Checksum(ReadOnlySpan<byte> baseBlock)
    {
        uint x = 0;
        for (var i = 0; i < 508; i += 4)
        {
            x ^= BinaryPrimitives.ReadUInt32LittleEndian(baseBlock[i..]);
        }

        return x switch
        {
            0xFFFF_FFFF => 0xFFFF_FFFE,
            0 => 1,
            _ => x,
        };
    }

    /// <summary>
    /// Applies new-format log entries (HvLE) of both logs in sequence order, from the first one not older than the
    /// hive. Entries are checked with their Marvin32 hashes; the first gap or damaged entry ends recovery.
    /// </summary>
    private void Recover(byte[][] logs)
    {
        var entries = new SortedDictionary<uint, (byte[] Log, int Offset, int Size)>();
        var oldFormat = false;
        foreach (var log in logs.Where(l => l is { Length: >= 1024 }))
        {
            if (!log.AsSpan(0, 4).SequenceEqual("regf"u8))
            {
                continue;
            }

            if (log.AsSpan(512, 4).SequenceEqual("DIRT"u8))
            {
                oldFormat = true;
                continue;
            }

            // A log is a chain of entries numbered from its base block's sequence number; anything after a break
            // (an older entry left over from an earlier use of the file) is not part of it.
            var expected = BinaryPrimitives.ReadUInt32LittleEndian(log.AsSpan(4));
            for (var pos = 512; pos + 40 <= log.Length;)
            {
                var e = log.AsSpan(pos);
                if (!e[..4].SequenceEqual("HvLE"u8))
                {
                    break;
                }

                var size = BinaryPrimitives.ReadInt32LittleEndian(e[4..]);
                if (size < 40 || size % 512 != 0 || pos + (long)size > log.Length)
                {
                    break;
                }

                var entry = e[..size];
                var hash1 = BinaryPrimitives.ReadUInt64LittleEndian(entry[24..]);
                var hash2 = BinaryPrimitives.ReadUInt64LittleEndian(entry[32..]);
                if (Marvin.Hash64(entry[..32]) != hash2 || Marvin.Hash64(entry[40..]) != hash1)
                {
                    break;
                }

                var seq = BinaryPrimitives.ReadUInt32LittleEndian(entry[12..]);
                if (seq != expected)
                {
                    break;
                }

                entries.TryAdd(seq, (log, pos, size));
                expected++;
                pos += size;
            }
        }

        // The hive file itself is written rarely (Windows 8.1+): the logs continue from its secondary sequence
        // number or later. Recovery starts at the first logged entry not older than the hive.
        var next = entries.Keys.Where(k => k >= SecondarySequence).DefaultIfEmpty(SecondarySequence).Min();
        var applied = 0;
        if (entries.ContainsKey(next))
        {
            _data = (byte[])_data.Clone(); // the caller's buffer is never changed
        }

        while (entries.TryGetValue(next, out var found))
        {
            if (!Apply(found.Log.AsSpan(found.Offset, found.Size)))
            {
                break;
            }

            applied++;
            next++;
        }

        LogEntriesApplied = applied;
        if (applied == 0)
        {
            RecoveryIncomplete = true;
            Problems.Add(oldFormat
                ? "Куст не был полностью записан, а журналы старого формата (до Windows 8.1) не применяются: последние изменения могут отсутствовать."
                : "Куст не был полностью записан, и подходящих записей в журналах (.LOG1, .LOG2) нет: последние изменения могут отсутствовать.");
        }
        else if (entries.Keys.Any(k => k >= next))
        {
            RecoveryIncomplete = true;
            Problems.Add($"Записи журнала после номера {next} не применены (пропуск или повреждение).");
        }
    }

    private bool Apply(ReadOnlySpan<byte> entry)
    {
        var binsSize = BinaryPrimitives.ReadInt32LittleEndian(entry[16..]);
        var count = BinaryPrimitives.ReadInt32LittleEndian(entry[20..]);
        if (binsSize <= 0 || binsSize > MaxBytes - BaseBlockSize || count < 0 || 40 + ((long)count * 8) > entry.Length)
        {
            Problems.Add("Запись журнала с неверными размерами пропущена.");
            return false;
        }

        if (BaseBlockSize + binsSize > _data.Length)
        {
            Array.Resize(ref _data, BaseBlockSize + binsSize);
        }

        _binsSize = binsSize;
        var pagePos = 40 + (count * 8);
        for (var i = 0; i < count; i++)
        {
            var offset = BinaryPrimitives.ReadInt32LittleEndian(entry[(40 + (i * 8))..]);
            var size = BinaryPrimitives.ReadInt32LittleEndian(entry[(44 + (i * 8))..]);
            if (offset < 0 || size <= 0 || (long)offset + size > binsSize || (long)pagePos + size > entry.Length)
            {
                Problems.Add("Страница журнала вне куста пропущена.");
                return false;
            }

            entry.Slice(pagePos, size).CopyTo(_data.AsSpan(BaseBlockSize + offset));
            pagePos += size;
        }

        return true;
    }

    private void ReadRoot()
    {
        var rootOffset = BinaryPrimitives.ReadInt32LittleEndian(_data.AsSpan(36));
        Root = ReadKey(rootOffset);
        if (Root is null)
        {
            Problems.Add("Корневой ключ не прочитан.");
        }
    }

    /// <summary>The data of a cell (after its size field), or empty when the offset or size is out of the hive.</summary>
    private ReadOnlySpan<byte> Cell(int offset)
    {
        if (offset < 0 || (long)offset + 4 > _binsSize)
        {
            return default;
        }

        var start = BaseBlockSize + offset;
        var raw = BinaryPrimitives.ReadInt32LittleEndian(_data.AsSpan(start));
        var size = raw == int.MinValue ? 0 : Math.Abs(raw);
        if (size < 8 || (long)offset + size > _binsSize)
        {
            return default;
        }

        return _data.AsSpan(start + 4, size - 4);
    }

    internal HiveKey? ReadKey(int offset)
    {
        var c = Cell(offset);
        if (c.Length < 76 || !c[..2].SequenceEqual("nk"u8))
        {
            return null;
        }

        var flags = BinaryPrimitives.ReadUInt16LittleEndian(c[2..]);
        var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(c[72..]);
        if (76 + nameLength > c.Length)
        {
            Problems.Add($"Имя ключа в ячейке {offset} обрезано.");
            nameLength = (ushort)(c.Length - 76);
        }

        var nameBytes = c.Slice(76, nameLength);
        var name = (flags & 0x0020) != 0 ? Encoding.Latin1.GetString(nameBytes) : Encoding.Unicode.GetString(nameBytes[..(nameBytes.Length & ~1)]);
        return new HiveKey(this, offset, name,
            BinaryPrimitives.ReadInt64LittleEndian(c[4..]),
            BinaryPrimitives.ReadInt32LittleEndian(c[28..]),
            Math.Clamp(BinaryPrimitives.ReadInt32LittleEndian(c[20..]), 0, MaxSubkeys),
            BinaryPrimitives.ReadInt32LittleEndian(c[40..]),
            Math.Clamp(BinaryPrimitives.ReadInt32LittleEndian(c[36..]), 0, MaxValues));
    }

    internal IReadOnlyList<HiveKey> ReadSubKeys(int listOffset, int expected)
    {
        var offsets = new List<int>();
        var visited = new HashSet<int>();
        CollectSubkeyOffsets(listOffset, offsets, visited, 0);
        if (offsets.Count != expected)
        {
            Problems.Add($"Список подключей {listOffset}: найдено {offsets.Count} из {expected}.");
        }

        var keys = new List<HiveKey>(offsets.Count);
        foreach (var o in offsets)
        {
            if (ReadKey(o) is { } k)
            {
                keys.Add(k);
            }
            else
            {
                Problems.Add($"Подключ в ячейке {o} не прочитан.");
            }
        }

        return keys;
    }

    private void CollectSubkeyOffsets(int listOffset, List<int> result, HashSet<int> visited, int depth)
    {
        if (depth > MaxListDepth || !visited.Add(listOffset))
        {
            Problems.Add($"Список подключей {listOffset} зациклен или слишком глубок.");
            return;
        }

        var c = Cell(listOffset);
        if (c.Length < 4)
        {
            Problems.Add($"Список подключей {listOffset} вне куста.");
            return;
        }

        var sig = c[..2];
        int count = BinaryPrimitives.ReadUInt16LittleEndian(c[2..]);
        var step = sig.SequenceEqual("lf"u8) || sig.SequenceEqual("lh"u8) ? 8 : sig.SequenceEqual("li"u8) || sig.SequenceEqual("ri"u8) ? 4 : 0;
        if (step == 0)
        {
            Problems.Add($"Неизвестный список подключей в ячейке {listOffset}.");
            return;
        }

        if (4 + (count * step) > c.Length)
        {
            Problems.Add($"Список подключей {listOffset} обрезан.");
            count = (c.Length - 4) / step;
        }

        for (var i = 0; i < count && result.Count < MaxSubkeys; i++)
        {
            var o = BinaryPrimitives.ReadInt32LittleEndian(c[(4 + (i * step))..]);
            if (sig.SequenceEqual("ri"u8))
            {
                CollectSubkeyOffsets(o, result, visited, depth + 1);
            }
            else
            {
                result.Add(o);
            }
        }
    }

    internal IReadOnlyList<HiveValue> ReadValues(int listOffset, int count)
    {
        var list = Cell(listOffset);
        if (list.Length < count * 4)
        {
            Problems.Add($"Список значений {listOffset} обрезан.");
            count = list.Length / 4;
        }

        var values = new List<HiveValue>(count);
        for (var i = 0; i < count; i++)
        {
            var o = BinaryPrimitives.ReadInt32LittleEndian(list[(i * 4)..]);
            if (ReadValue(o) is { } v)
            {
                values.Add(v);
            }
        }

        return values;
    }

    private HiveValue? ReadValue(int offset)
    {
        var c = Cell(offset);
        if (c.Length < 20 || !c[..2].SequenceEqual("vk"u8))
        {
            Problems.Add($"Значение в ячейке {offset} не прочитано.");
            return null;
        }

        int nameLength = BinaryPrimitives.ReadUInt16LittleEndian(c[2..]);
        var rawSize = BinaryPrimitives.ReadUInt32LittleEndian(c[4..]);
        var dataOffset = BinaryPrimitives.ReadInt32LittleEndian(c[8..]);
        var type = BinaryPrimitives.ReadInt32LittleEndian(c[12..]);
        var flags = BinaryPrimitives.ReadUInt16LittleEndian(c[16..]);
        nameLength = Math.Min(nameLength, c.Length - 20);
        var nameBytes = c.Slice(20, nameLength);
        var name = (flags & 0x0001) != 0 ? Encoding.Latin1.GetString(nameBytes) : Encoding.Unicode.GetString(nameBytes[..(nameBytes.Length & ~1)]);

        byte[] data;
        var size = (int)(rawSize & 0x7FFF_FFFF);
        if ((rawSize & 0x8000_0000) != 0)
        {
            // Up to four bytes are kept in the offset field itself.
            data = c.Slice(8, Math.Min(size, 4)).ToArray();
        }
        else if (size > MaxValueBytes)
        {
            Problems.Add($"Значение {name}: {size} байт — больше предела.");
            data = [];
        }
        else if (size > BigDataSegment && MinorVersion >= 4 && Cell(dataOffset) is { Length: >= 8 } db && db[..2].SequenceEqual("db"u8))
        {
            data = ReadBigData(db, size, name);
        }
        else
        {
            var d = Cell(dataOffset);
            if (d.Length < size)
            {
                Problems.Add($"Данные значения {name} обрезаны ({d.Length} из {size} байт).");
                size = d.Length;
            }

            data = d[..size].ToArray();
        }

        return new HiveValue(name, type, data);
    }

    private byte[] ReadBigData(ReadOnlySpan<byte> db, int size, string name)
    {
        int segments = BinaryPrimitives.ReadUInt16LittleEndian(db[2..]);
        var list = Cell(BinaryPrimitives.ReadInt32LittleEndian(db[4..]));
        var result = new byte[size];
        var done = 0;
        for (var i = 0; i < segments && (i * 4) + 4 <= list.Length && done < size; i++)
        {
            var s = Cell(BinaryPrimitives.ReadInt32LittleEndian(list[(i * 4)..]));
            var n = Math.Min(Math.Min(s.Length, BigDataSegment), size - done);
            s[..n].CopyTo(result.AsSpan(done));
            done += n;
        }

        if (done < size)
        {
            Problems.Add($"Большое значение {name} прочитано не полностью ({done} из {size} байт).");
            return result[..done];
        }

        return result;
    }
}

/// <summary>Marvin32 (64-bit result) with the seed the registry uses for transaction log entries.</summary>
internal static class Marvin
{
    private const ulong RegistrySeed = 0x82EF4D887A4E55C5;

    public static ulong Hash64(ReadOnlySpan<byte> data, ulong seed = RegistrySeed)
    {
        var p0 = (uint)seed;
        var p1 = (uint)(seed >> 32);
        while (data.Length >= 4)
        {
            p0 += BinaryPrimitives.ReadUInt32LittleEndian(data);
            Block(ref p0, ref p1);
            data = data[4..];
        }

        p0 += data.Length switch
        {
            0 => 0x80u,
            1 => 0x8000u | data[0],
            2 => 0x80_0000u | BinaryPrimitives.ReadUInt16LittleEndian(data),
            _ => 0x8000_0000u | BinaryPrimitives.ReadUInt16LittleEndian(data) | ((uint)data[2] << 16),
        };
        Block(ref p0, ref p1);
        Block(ref p0, ref p1);
        return ((ulong)p1 << 32) | p0;
    }

    private static void Block(ref uint p0, ref uint p1)
    {
        p1 ^= p0;
        p0 = uint.RotateLeft(p0, 20);
        p0 += p1;
        p1 = uint.RotateLeft(p1, 9);
        p1 ^= p0;
        p0 = uint.RotateLeft(p0, 27);
        p0 += p1;
        p1 = uint.RotateLeft(p1, 19);
    }
}
