using System.Buffers.Binary;
using System.Text;

namespace XINSkan.ShellFormats;

/// <summary>Distributed link tracker data: the machine and NTFS object IDs of the target when the link was made.</summary>
public sealed record LinkTracker(string MachineId, Guid VolumeDroid, Guid FileDroid, Guid BirthVolumeDroid, Guid BirthFileDroid)
{
    /// <summary>MAC address from a time-based (version 1) file object ID, or null.</summary>
    public string? MacAddress => IsTimeBased(FileDroid)
        ? string.Join(":", FileDroid.ToByteArray()[10..16].Select(x => x.ToString("x2", System.Globalization.CultureInfo.InvariantCulture)))
        : null;

    /// <summary>Creation time of the object ID from a time-based GUID, or null.</summary>
    public DateTimeOffset? ObjectIdCreated
    {
        get
        {
            if (!IsTimeBased(FileDroid))
            {
                return null;
            }

            var b = FileDroid.ToByteArray();
            var ticks = (long)(BinaryPrimitives.ReadUInt64LittleEndian(b) & 0x0FFF_FFFF_FFFF_FFFFUL);
            var gregorianStart = new DateTimeOffset(1582, 10, 15, 0, 0, 0, TimeSpan.Zero);
            return ticks <= 0 || ticks > (DateTimeOffset.MaxValue - gregorianStart).Ticks ? null : gregorianStart.AddTicks(ticks);
        }
    }

    private static bool IsTimeBased(Guid g) => (g.ToByteArray()[7] >> 4) == 1;
}

/// <summary>A parsed shell link (.lnk). Never throws; problems are listed.</summary>
public sealed class LnkFile
{
    public const int MaxBytes = 1024 * 1024;

    private static readonly byte[] Clsid = [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];

    public uint Flags { get; private set; }

    public uint TargetAttributes { get; private set; }

    public long TargetCreated { get; private set; }

    public long TargetAccessed { get; private set; }

    public long TargetModified { get; private set; }

    public uint TargetSize { get; private set; }

    public List<ShellItem> TargetIdList { get; } = [];

    /// <summary>Drive type from LinkInfo (2 removable, 3 fixed, 4 network, 5 CD-ROM), or null.</summary>
    public uint? DriveType { get; private set; }

    public uint? DriveSerial { get; private set; }

    public string? VolumeLabel { get; private set; }

    public string? LocalBasePath { get; private set; }

    public string? CommonPathSuffix { get; private set; }

    public string? NetName { get; private set; }

    public string? Name { get; private set; }

    public string? RelativePath { get; private set; }

    public string? WorkingDirectory { get; private set; }

    public string? Arguments { get; private set; }

    public string? IconLocation { get; private set; }

    /// <summary>Target path with environment variables, from EnvironmentVariableDataBlock.</summary>
    public string? EnvironmentTarget { get; private set; }

    public LinkTracker? Tracker { get; private set; }

    public List<string> Problems { get; } = [];

    /// <summary>The best available target path: LinkInfo, then the ID list, then the environment-variable form.</summary>
    public string? TargetPath
    {
        get
        {
            if (!string.IsNullOrEmpty(LocalBasePath))
            {
                return LocalBasePath + (string.IsNullOrEmpty(CommonPathSuffix) ? string.Empty : (LocalBasePath.EndsWith('\\') ? string.Empty : "\\") + CommonPathSuffix);
            }

            if (!string.IsNullOrEmpty(NetName))
            {
                return NetName + (string.IsNullOrEmpty(CommonPathSuffix) ? string.Empty : "\\" + CommonPathSuffix);
            }

            var fromIds = ShellItemParser.ToPath(TargetIdList);
            if (fromIds.Length > 0)
            {
                return fromIds;
            }

            return EnvironmentTarget;
        }
    }

    /// <summary>The target's MFT reference from the last ID-list item (Vista+), if present.</summary>
    public ShellItem? TargetItem => TargetIdList.LastOrDefault(i => i.Kind is ShellItemKind.File or ShellItemKind.Folder);

    public static bool LooksLikeLnk(ReadOnlySpan<byte> b) =>
        b.Length >= 76 && BinaryPrimitives.ReadUInt32LittleEndian(b) == 0x4C && b.Slice(4, 16).SequenceEqual(Clsid);

    /// <summary>Parses a link; returns null only when the data is not a shell link at all.</summary>
    public static LnkFile? Parse(ReadOnlySpan<byte> b)
    {
        if (!LooksLikeLnk(b))
        {
            return null;
        }

        var l = new LnkFile
        {
            Flags = BinaryPrimitives.ReadUInt32LittleEndian(b[20..]),
            TargetAttributes = BinaryPrimitives.ReadUInt32LittleEndian(b[24..]),
            TargetCreated = BinaryPrimitives.ReadInt64LittleEndian(b[28..]),
            TargetAccessed = BinaryPrimitives.ReadInt64LittleEndian(b[36..]),
            TargetModified = BinaryPrimitives.ReadInt64LittleEndian(b[44..]),
            TargetSize = BinaryPrimitives.ReadUInt32LittleEndian(b[52..]),
        };

        var o = 76;
        if ((l.Flags & 0x01) != 0)
        {
            if (o + 2 > b.Length)
            {
                l.Problems.Add("Список элементов цели обрезан.");
                return l;
            }

            int size = BinaryPrimitives.ReadUInt16LittleEndian(b[o..]);
            if (o + 2 + size > b.Length)
            {
                l.Problems.Add($"Список элементов цели ({size} байт) выходит за файл.");
                return l;
            }

            l.TargetIdList.AddRange(ShellItemParser.ParseList(b.Slice(o + 2, size), out var p));
            if (p is not null)
            {
                l.Problems.Add(p);
            }

            o += 2 + size;
        }

        if ((l.Flags & 0x02) != 0 && (l.Flags & 0x100) == 0)
        {
            if (o + 4 > b.Length)
            {
                l.Problems.Add("LinkInfo обрезан.");
                return l;
            }

            var size = BinaryPrimitives.ReadUInt32LittleEndian(b[o..]);
            if (size < 28 || o + size > b.Length)
            {
                l.Problems.Add($"LinkInfo ({size} байт) выходит за файл.");
                return l;
            }

            l.ParseLinkInfo(b.Slice(o, (int)size));
            o += (int)size;
        }

        var unicode = (l.Flags & 0x80) != 0;
        l.Name = l.NextString(b, 0x04, unicode, ref o);
        l.RelativePath = l.NextString(b, 0x08, unicode, ref o);
        l.WorkingDirectory = l.NextString(b, 0x10, unicode, ref o);
        l.Arguments = l.NextString(b, 0x20, unicode, ref o);
        l.IconLocation = l.NextString(b, 0x40, unicode, ref o);
        l.ParseExtraData(b[Math.Min(o, b.Length)..]);
        return l;
    }

    /// <summary>One StringData field (present when its flag is set): a character count, then the characters.</summary>
    private string? NextString(ReadOnlySpan<byte> b, uint flag, bool unicode, ref int o)
    {
        if ((Flags & flag) == 0)
        {
            return null;
        }

        if (o + 2 > b.Length)
        {
            Problems.Add("Строковые данные обрезаны.");
            return null;
        }

        int chars = BinaryPrimitives.ReadUInt16LittleEndian(b[o..]);
        var bytes = unicode ? chars * 2 : chars;
        if (o + 2 + bytes > b.Length)
        {
            Problems.Add($"Строка длиной {chars} выходит за файл.");
            o = b.Length;
            return null;
        }

        var s = unicode ? Encoding.Unicode.GetString(b.Slice(o + 2, bytes)) : Encoding.Latin1.GetString(b.Slice(o + 2, bytes));
        o += 2 + bytes;
        return s;
    }

    private void ParseLinkInfo(ReadOnlySpan<byte> li)
    {
        var headerSize = BinaryPrimitives.ReadUInt32LittleEndian(li[4..]);
        var flags = BinaryPrimitives.ReadUInt32LittleEndian(li[8..]);
        var volumeIdOffset = BinaryPrimitives.ReadUInt32LittleEndian(li[12..]);
        var localBaseOffset = BinaryPrimitives.ReadUInt32LittleEndian(li[16..]);
        var networkOffset = BinaryPrimitives.ReadUInt32LittleEndian(li[20..]);
        var suffixOffset = BinaryPrimitives.ReadUInt32LittleEndian(li[24..]);
        uint localBaseUnicode = 0, suffixUnicode = 0;
        if (headerSize >= 0x24 && li.Length >= 36)
        {
            localBaseUnicode = BinaryPrimitives.ReadUInt32LittleEndian(li[28..]);
            suffixUnicode = BinaryPrimitives.ReadUInt32LittleEndian(li[32..]);
        }

        if ((flags & 0x01) != 0)
        {
            if (volumeIdOffset + 16 <= li.Length)
            {
                var v = li[(int)volumeIdOffset..];
                var vsize = BinaryPrimitives.ReadUInt32LittleEndian(v);
                if (vsize >= 16 && vsize <= v.Length)
                {
                    v = v[..(int)vsize];
                    DriveType = BinaryPrimitives.ReadUInt32LittleEndian(v[4..]);
                    DriveSerial = BinaryPrimitives.ReadUInt32LittleEndian(v[8..]);
                    var labelOffset = BinaryPrimitives.ReadUInt32LittleEndian(v[12..]);
                    if (labelOffset == 0x14 && v.Length >= 20)
                    {
                        var u = BinaryPrimitives.ReadUInt32LittleEndian(v[16..]);
                        VolumeLabel = Utf16At(v, u);
                    }
                    else
                    {
                        VolumeLabel = AnsiAt(v, labelOffset);
                    }
                }
                else
                {
                    Problems.Add("VolumeID повреждён.");
                }
            }

            LocalBasePath = localBaseUnicode != 0 ? Utf16At(li, localBaseUnicode) : AnsiAt(li, localBaseOffset);
        }

        if ((flags & 0x02) != 0 && networkOffset + 20 <= li.Length)
        {
            var n = li[(int)networkOffset..];
            var nsize = BinaryPrimitives.ReadUInt32LittleEndian(n);
            if (nsize >= 20 && nsize <= n.Length)
            {
                n = n[..(int)nsize];
                var netNameOffset = BinaryPrimitives.ReadUInt32LittleEndian(n[8..]);
                NetName = netNameOffset > 0x14 && n.Length >= 28
                    ? Utf16At(n, BinaryPrimitives.ReadUInt32LittleEndian(n[20..]))
                    : AnsiAt(n, netNameOffset);
            }
        }

        CommonPathSuffix = suffixUnicode != 0 ? Utf16At(li, suffixUnicode) : AnsiAt(li, suffixOffset);
    }

    private void ParseExtraData(ReadOnlySpan<byte> b)
    {
        var o = 0;
        for (var n = 0; n < 64 && o + 4 <= b.Length; n++)
        {
            var size = BinaryPrimitives.ReadUInt32LittleEndian(b[o..]);
            if (size < 4)
            {
                return; // terminal block
            }

            if (size < 8 || o + size > b.Length)
            {
                Problems.Add($"Блок дополнительных данных ({size} байт) выходит за файл.");
                return;
            }

            var block = b.Slice(o, (int)size);
            switch (BinaryPrimitives.ReadUInt32LittleEndian(block[4..]))
            {
                case 0xA0000003 when size >= 0x60:
                    var machine = block.Slice(16, 16);
                    var end = machine.IndexOf((byte)0);
                    Tracker = new LinkTracker(
                        Encoding.ASCII.GetString(machine[..(end < 0 ? 16 : end)]),
                        new Guid(block.Slice(32, 16)),
                        new Guid(block.Slice(48, 16)),
                        new Guid(block.Slice(64, 16)),
                        new Guid(block.Slice(80, 16)));
                    break;
                case 0xA0000001 when size >= 788:
                    var target = Encoding.Unicode.GetString(block.Slice(268, 520));
                    var nul = target.IndexOf('\0', StringComparison.Ordinal);
                    EnvironmentTarget = nul < 0 ? target : target[..nul];
                    break;
                default:
                    break;
            }

            o += (int)size;
        }
    }

    private static string? AnsiAt(ReadOnlySpan<byte> b, uint offset)
    {
        if (offset == 0 || offset >= b.Length)
        {
            return null;
        }

        var s = b[(int)offset..];
        var end = s.IndexOf((byte)0);
        return Encoding.Latin1.GetString(s[..(end < 0 ? s.Length : end)]);
    }

    private static string? Utf16At(ReadOnlySpan<byte> b, uint offset)
    {
        if (offset == 0 || offset >= b.Length)
        {
            return null;
        }

        var s = b[(int)offset..];
        var end = ShellItemParser.IndexOfUtf16Nul(s);
        return Encoding.Unicode.GetString(s[..(end < 0 ? s.Length & ~1 : end)]);
    }
}
