using System.Buffers.Binary;
using System.Text;
using XINSkan.ExecutionFormats;

namespace XINSkan.ExecutionTests;

internal sealed record TestValue(string Name, int Type, byte[] Data, bool AsciiName = true)
{
    public static TestValue Sz(string name, string value) => new(name, HiveValue.RegSz, Encoding.Unicode.GetBytes(value + "\0"));

    public static TestValue Dword(string name, int value) => new(name, HiveValue.RegDword, BitConverter.GetBytes(value));

    public static TestValue Qword(string name, long value) => new(name, HiveValue.RegQword, BitConverter.GetBytes(value));
}

internal sealed record TestKey(string Name, long LastWrite = 0, TestValue[]? Values = null, TestKey[]? SubKeys = null, string List = "lh", bool AsciiName = true);

/// <summary>Builds registry hive files (regf 1.5) by the published format, and new-format transaction logs.</summary>
internal static class HiveBuilder
{
    public static byte[] Build(TestKey root, uint primarySeq = 1, uint secondarySeq = 1, int minBins = 4096)
    {
        var cells = new MemoryStream();
        cells.Write(new byte[32]); // hbin header, filled at the end

        // The root key cell comes first, so its offset (kept in the base block, which logs do not change) is the
        // same in every version of a hive built from similar trees.
        var rootOffset = Cell(cells, new byte[76 + NameBytes(root.Name, root.AsciiName).Length]);
        WriteKey(cells, root, -1, rootOffset);
        var used = (int)cells.Length;
        var binSize = Math.Max(minBins, (used + 8 + 4095) / 4096 * 4096);
        var free = binSize - used;
        cells.Write(BitConverter.GetBytes(free)); // one free cell covers the rest
        cells.Write(new byte[free - 4]);
        var bins = cells.ToArray();
        "hbin"u8.CopyTo(bins);
        BinaryPrimitives.WriteInt32LittleEndian(bins.AsSpan(8), binSize);

        var hive = new byte[4096 + binSize];
        "regf"u8.CopyTo(hive);
        BinaryPrimitives.WriteUInt32LittleEndian(hive.AsSpan(4), primarySeq);
        BinaryPrimitives.WriteUInt32LittleEndian(hive.AsSpan(8), secondarySeq);
        BinaryPrimitives.WriteInt64LittleEndian(hive.AsSpan(12), new DateTime(2026, 11, 8, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc());
        BinaryPrimitives.WriteInt32LittleEndian(hive.AsSpan(20), 1);
        BinaryPrimitives.WriteInt32LittleEndian(hive.AsSpan(24), 5);
        BinaryPrimitives.WriteInt32LittleEndian(hive.AsSpan(32), 1);
        BinaryPrimitives.WriteInt32LittleEndian(hive.AsSpan(36), rootOffset);
        BinaryPrimitives.WriteInt32LittleEndian(hive.AsSpan(40), binSize);
        BinaryPrimitives.WriteInt32LittleEndian(hive.AsSpan(44), 1);
        bins.CopyTo(hive, 4096);
        WriteChecksum(hive);
        return hive;
    }

    public static void WriteChecksum(byte[] hive)
    {
        uint x = 0;
        for (var i = 0; i < 508; i += 4)
        {
            x ^= BinaryPrimitives.ReadUInt32LittleEndian(hive.AsSpan(i));
        }

        BinaryPrimitives.WriteUInt32LittleEndian(hive.AsSpan(508), x is 0 ? 1 : x == 0xFFFF_FFFF ? 0xFFFF_FFFE : x);
    }

    /// <summary>A new-format log (.LOG1) whose entries carry the whole hive-bins data of each given hive version.</summary>
    public static byte[] Log(uint firstSequence, params byte[][] versions)
    {
        var log = new MemoryStream();
        var header = new byte[512];
        "regf"u8.CopyTo(header);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4), firstSequence);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), firstSequence);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(28), 6);
        log.Write(header);
        var seq = firstSequence;
        foreach (var hive in versions)
        {
            var binsSize = hive.Length - 4096;
            var size = (48 + binsSize + 511) / 512 * 512;
            var e = new byte[size];
            "HvLE"u8.CopyTo(e);
            BinaryPrimitives.WriteInt32LittleEndian(e.AsSpan(4), size);
            BinaryPrimitives.WriteUInt32LittleEndian(e.AsSpan(12), seq++);
            BinaryPrimitives.WriteInt32LittleEndian(e.AsSpan(16), binsSize);
            BinaryPrimitives.WriteInt32LittleEndian(e.AsSpan(20), 1);
            BinaryPrimitives.WriteInt32LittleEndian(e.AsSpan(40), 0);
            BinaryPrimitives.WriteInt32LittleEndian(e.AsSpan(44), binsSize);
            hive.AsSpan(4096).CopyTo(e.AsSpan(48));
            BinaryPrimitives.WriteUInt64LittleEndian(e.AsSpan(24), Marvin.Hash64(e.AsSpan(40)));
            BinaryPrimitives.WriteUInt64LittleEndian(e.AsSpan(32), Marvin.Hash64(e.AsSpan(0, 32)));
            log.Write(e);
        }

        return log.ToArray();
    }

    private static int Cell(MemoryStream s, ReadOnlySpan<byte> data)
    {
        var offset = (int)s.Length;
        var size = (data.Length + 4 + 7) & ~7;
        s.Write(BitConverter.GetBytes(-size));
        s.Write(data);
        s.Write(new byte[size - 4 - data.Length]);
        return offset;
    }

    private static byte[] NameBytes(string name, bool ascii) => ascii ? Encoding.Latin1.GetBytes(name) : Encoding.Unicode.GetBytes(name);

    private static int WriteKey(MemoryStream s, TestKey key, int parent, int reserved = -1)
    {
        var values = key.Values ?? [];
        var subkeys = key.SubKeys ?? [];
        var subOffsets = subkeys.Select(k => WriteKey(s, k, 0)).ToList();
        var listOffset = -1;
        if (subOffsets.Count > 0)
        {
            listOffset = key.List == "ri" ? RiList(s, subOffsets) : List(s, key.List, subOffsets);
        }

        var valueOffsets = values.Select(v => WriteValue(s, v)).ToList();
        var valueList = valueOffsets.Count == 0 ? -1 : Cell(s, valueOffsets.SelectMany(BitConverter.GetBytes).ToArray());

        var name = key.AsciiName ? Encoding.Latin1.GetBytes(key.Name) : Encoding.Unicode.GetBytes(key.Name);
        var nk = new byte[76 + name.Length];
        "nk"u8.CopyTo(nk);
        BinaryPrimitives.WriteUInt16LittleEndian(nk.AsSpan(2), (ushort)((key.AsciiName ? 0x20 : 0) | (parent < 0 ? 0x04 : 0)));
        BinaryPrimitives.WriteInt64LittleEndian(nk.AsSpan(4), key.LastWrite);
        BinaryPrimitives.WriteInt32LittleEndian(nk.AsSpan(16), parent);
        BinaryPrimitives.WriteInt32LittleEndian(nk.AsSpan(20), subOffsets.Count);
        BinaryPrimitives.WriteInt32LittleEndian(nk.AsSpan(28), listOffset);
        BinaryPrimitives.WriteInt32LittleEndian(nk.AsSpan(32), -1);
        BinaryPrimitives.WriteInt32LittleEndian(nk.AsSpan(36), values.Length);
        BinaryPrimitives.WriteInt32LittleEndian(nk.AsSpan(40), valueList);
        BinaryPrimitives.WriteInt32LittleEndian(nk.AsSpan(44), -1);
        BinaryPrimitives.WriteInt32LittleEndian(nk.AsSpan(48), -1);
        BinaryPrimitives.WriteUInt16LittleEndian(nk.AsSpan(72), (ushort)name.Length);
        name.CopyTo(nk, 76);
        if (reserved < 0)
        {
            return Cell(s, nk);
        }

        var end = s.Position;
        s.Position = reserved + 4;
        s.Write(nk);
        s.Position = end;
        return reserved;
    }

    private static int List(MemoryStream s, string kind, List<int> offsets)
    {
        var step = kind == "li" ? 4 : 8;
        var b = new byte[4 + (offsets.Count * step)];
        Encoding.ASCII.GetBytes(kind).CopyTo(b, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(2), (ushort)offsets.Count);
        for (var i = 0; i < offsets.Count; i++)
        {
            BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(4 + (i * step)), offsets[i]);
        }

        return Cell(s, b);
    }

    /// <summary>An index root splitting the subkeys into lists of two (as Windows does for very large keys).</summary>
    private static int RiList(MemoryStream s, List<int> offsets)
    {
        var lists = offsets.Chunk(2).Select((c, i) => List(s, i % 2 == 0 ? "lh" : "li", [.. c])).ToList();
        var b = new byte[4 + (lists.Count * 4)];
        "ri"u8.CopyTo(b);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(2), (ushort)lists.Count);
        for (var i = 0; i < lists.Count; i++)
        {
            BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(4 + (i * 4)), lists[i]);
        }

        return Cell(s, b);
    }

    private static int WriteValue(MemoryStream s, TestValue v)
    {
        int dataOffset;
        uint size = (uint)v.Data.Length;
        if (v.Data.Length <= 4)
        {
            var inline = new byte[4];
            v.Data.CopyTo(inline, 0);
            dataOffset = BitConverter.ToInt32(inline);
            size |= 0x8000_0000;
        }
        else if (v.Data.Length > 16344)
        {
            var segments = v.Data.Chunk(16344).Select(c => Cell(s, c)).ToList();
            var list = Cell(s, segments.SelectMany(BitConverter.GetBytes).ToArray());
            var db = new byte[8];
            "db"u8.CopyTo(db);
            BinaryPrimitives.WriteUInt16LittleEndian(db.AsSpan(2), (ushort)segments.Count);
            BinaryPrimitives.WriteInt32LittleEndian(db.AsSpan(4), list);
            dataOffset = Cell(s, db);
        }
        else
        {
            dataOffset = Cell(s, v.Data);
        }

        var name = v.AsciiName ? Encoding.Latin1.GetBytes(v.Name) : Encoding.Unicode.GetBytes(v.Name);
        var vk = new byte[20 + name.Length];
        "vk"u8.CopyTo(vk);
        BinaryPrimitives.WriteUInt16LittleEndian(vk.AsSpan(2), (ushort)name.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(vk.AsSpan(4), size);
        BinaryPrimitives.WriteInt32LittleEndian(vk.AsSpan(8), dataOffset);
        BinaryPrimitives.WriteInt32LittleEndian(vk.AsSpan(12), v.Type);
        BinaryPrimitives.WriteUInt16LittleEndian(vk.AsSpan(16), (ushort)(v.AsciiName ? 1 : 0));
        name.CopyTo(vk, 20);
        return Cell(s, vk);
    }
}
