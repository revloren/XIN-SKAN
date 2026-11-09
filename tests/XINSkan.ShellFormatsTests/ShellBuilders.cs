using System.Buffers.Binary;
using System.Text;

namespace XINSkan.ShellFormatsTests;

/// <summary>Builds shell items and links byte by byte (the layouts of MS-SHLLINK and the BEEF0004 block).</summary>
public static class ShellBuilders
{
    public static byte[] Root(Guid folder)
    {
        var b = new byte[20];
        BinaryPrimitives.WriteUInt16LittleEndian(b, 20);
        b[2] = 0x1F;
        b[3] = 0x50;
        folder.ToByteArray().CopyTo(b, 4);
        return b;
    }

    public static byte[] Volume(char letter)
    {
        var b = new byte[25];
        BinaryPrimitives.WriteUInt16LittleEndian(b, 25);
        b[2] = 0x2F;
        Encoding.ASCII.GetBytes($"{letter}:\\").CopyTo(b, 3);
        return b;
    }

    public static ushort Dos(DateTime t) => (ushort)(((t.Year - 1980) << 9) | (t.Month << 5) | t.Day);

    public static ushort DosTime(DateTime t) => (ushort)((t.Hour << 11) | (t.Minute << 5) | (t.Second / 2));

    /// <summary>A file or folder entry with an ANSI 8.3 name and a BEEF0004 block of the given version.</summary>
    public static byte[] Entry(string shortName, string longName, bool folder, DateTime modified, int version = 9, ulong mftEntry = 0, ushort mftSeq = 0, uint size = 0)
    {
        var name = Encoding.ASCII.GetBytes(shortName + "\0");
        if (name.Length % 2 != 0)
        {
            name = [.. name, 0];
        }

        var longBytes = Encoding.Unicode.GetBytes(longName + "\0");
        var head = version >= 7 ? 36 : 18;
        head += version >= 3 ? 2 : 0;
        head += version >= 9 ? 4 : 0;
        head += version >= 8 ? 4 : 0;
        var extSize = head + longBytes.Length + 2;
        var ext = new byte[extSize];
        BinaryPrimitives.WriteUInt16LittleEndian(ext, (ushort)extSize);
        BinaryPrimitives.WriteUInt16LittleEndian(ext.AsSpan(2), (ushort)version);
        BinaryPrimitives.WriteUInt32LittleEndian(ext.AsSpan(4), 0xBEEF0004);
        BinaryPrimitives.WriteUInt16LittleEndian(ext.AsSpan(8), Dos(modified.AddDays(-3)));
        BinaryPrimitives.WriteUInt16LittleEndian(ext.AsSpan(10), DosTime(modified.AddDays(-3)));
        BinaryPrimitives.WriteUInt16LittleEndian(ext.AsSpan(12), Dos(modified));
        BinaryPrimitives.WriteUInt16LittleEndian(ext.AsSpan(14), DosTime(modified));
        if (version >= 7)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(ext.AsSpan(20), (uint)mftEntry);
            BinaryPrimitives.WriteUInt16LittleEndian(ext.AsSpan(24), (ushort)(mftEntry >> 32));
            BinaryPrimitives.WriteUInt16LittleEndian(ext.AsSpan(26), mftSeq);
        }

        longBytes.CopyTo(ext, head);
        var total = 14 + name.Length + ext.Length;
        var b = new byte[total];
        BinaryPrimitives.WriteUInt16LittleEndian(b, (ushort)total);
        b[2] = (byte)(folder ? 0x31 : 0x32);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), size);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(8), Dos(modified));
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(10), DosTime(modified));
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(12), (ushort)(folder ? 0x10 : 0x20));
        name.CopyTo(b, 14);
        ext.CopyTo(b, 14 + name.Length);
        return b;
    }

    public static byte[] IdList(params byte[][] items) => [.. items.SelectMany(i => i), 0, 0];

    /// <summary>A link with an ID list and LinkInfo (local path, drive type and serial) and Unicode string data.</summary>
    public static byte[] Link(string localPath, uint driveType, uint serial, string label, byte[]? idList = null, string? arguments = null, long targetModified = 0)
    {
        var flags = 0x02u | 0x80u | (idList is null ? 0 : 0x01u) | (arguments is null ? 0 : 0x20u);
        var header = new byte[76];
        BinaryPrimitives.WriteUInt32LittleEndian(header, 0x4C);
        new byte[] { 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }.CopyTo(header, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(20), flags);
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(44), targetModified);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(52), 4321);
        var parts = new List<byte>(header);
        if (idList is not null)
        {
            parts.AddRange(BitConverter.GetBytes((ushort)idList.Length));
            parts.AddRange(idList);
        }

        // LinkInfo: header 0x1C, VolumeID, ANSI local base path, empty suffix.
        var labelBytes = Encoding.ASCII.GetBytes(label + "\0");
        var volume = new byte[16 + labelBytes.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(volume, (uint)volume.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(volume.AsSpan(4), driveType);
        BinaryPrimitives.WriteUInt32LittleEndian(volume.AsSpan(8), serial);
        BinaryPrimitives.WriteUInt32LittleEndian(volume.AsSpan(12), 16);
        labelBytes.CopyTo(volume, 16);
        var local = Encoding.Latin1.GetBytes(localPath + "\0");
        var info = new byte[0x1C + volume.Length + local.Length + 1];
        BinaryPrimitives.WriteUInt32LittleEndian(info, (uint)info.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(4), 0x1C);
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(12), 0x1C);
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(16), (uint)(0x1C + volume.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(24), (uint)(info.Length - 1));
        volume.CopyTo(info, 0x1C);
        local.CopyTo(info, 0x1C + volume.Length);
        parts.AddRange(info);
        if (arguments is not null)
        {
            parts.AddRange(BitConverter.GetBytes((ushort)arguments.Length));
            parts.AddRange(Encoding.Unicode.GetBytes(arguments));
        }

        parts.AddRange(new byte[4]); // terminal extra-data block
        return [.. parts];
    }
}
