using System.Buffers.Binary;
using System.Text;

namespace XINSkan.ShellFormats;

public enum ShellItemKind
{
    Unknown,
    RootFolder,
    Volume,
    File,
    Folder,
    Network,
    Uri,
    ControlPanel,
    Delegate,
}

/// <summary>One shell item (an element of an ID list): a known folder, a drive, a file or folder entry.</summary>
public sealed record ShellItem
{
    public required ShellItemKind Kind { get; init; }

    public byte Type { get; init; }

    /// <summary>The name to show: the long name when present, else the 8.3 name, a drive, or a known folder name.</summary>
    public string? Name { get; init; }

    public string? ShortName { get; init; }

    public Guid? FolderId { get; init; }

    public uint? Size { get; init; }

    /// <summary>MS-DOS date and time of last modification, as stored (2-second resolution).</summary>
    public DateTimeOffset? Modified { get; init; }

    public DateTimeOffset? Created { get; init; }

    public DateTimeOffset? Accessed { get; init; }

    /// <summary>MFT entry and sequence of the object when the item was made (extension block BEEF0004, Vista+).</summary>
    public ulong? MftEntry { get; init; }

    public ushort? MftSequence { get; init; }

    public string? Problem { get; init; }
}

/// <summary>Parses shell items and ID lists. Every length is checked against the item; nothing throws.</summary>
public static class ShellItemParser
{
    public const int MaxItems = 128;

    private static readonly Dictionary<Guid, string> KnownFolders = new()
    {
        [new Guid("20D04FE0-3AEA-1069-A2D8-08002B30309D")] = "Этот компьютер",
        [new Guid("59031A47-3F72-44A7-89C5-5595FE6B30EE")] = "Папка пользователя",
        [new Guid("450D8FBA-AD25-11D0-98A8-0800361B1103")] = "Документы",
        [new Guid("645FF040-5081-101B-9F08-00AA002F954E")] = "Корзина",
        [new Guid("F02C1A0D-BE21-4350-88B0-7367FC96EF3C")] = "Сеть",
        [new Guid("208D2C60-3AEA-1069-A2D7-08002B30309D")] = "Сетевое окружение",
        [new Guid("031E4825-7B94-4DC3-B131-E946B44C8DD5")] = "Библиотеки",
        [new Guid("26EE0668-A00A-44D7-9371-BEB064C98683")] = "Панель управления",
        [new Guid("21EC2020-3AEA-1069-A2DD-08002B30309D")] = "Все элементы панели управления",
        [new Guid("679F85CB-0220-4080-B29B-5540CC05AAB6")] = "Быстрый доступ",
        [new Guid("018D5C66-4533-4307-9B53-224DE2ED1FE6")] = "OneDrive",
        [new Guid("374DE290-123F-4565-9164-39C4925E467B")] = "Загрузки",
        [new Guid("088E3905-0323-4B02-9826-5D99428E115F")] = "Загрузки",
        [new Guid("B4BFCC3A-DB2C-424C-B029-7FE99A87C641")] = "Рабочий стол",
        [new Guid("D3162B92-9365-467A-956B-92703ACA08AF")] = "Документы",
        [new Guid("F42EE2D3-909F-4907-8871-4C22FC0BF756")] = "Документы",
    };

    /// <summary>Items of an ID list (sequence of u16-sized items ending with a zero size).</summary>
    public static List<ShellItem> ParseList(ReadOnlySpan<byte> list, out string? problem)
    {
        problem = null;
        var items = new List<ShellItem>();
        var o = 0;
        while (o + 2 <= list.Length)
        {
            int size = BinaryPrimitives.ReadUInt16LittleEndian(list[o..]);
            if (size == 0)
            {
                return items;
            }

            if (size < 3 || o + size > list.Length)
            {
                problem = $"Элемент списка на смещении {o} длиной {size} выходит за список.";
                return items;
            }

            items.Add(Parse(list.Slice(o, size)));
            if (items.Count >= MaxItems)
            {
                problem = "Слишком много элементов в списке.";
                return items;
            }

            o += size;
        }

        problem = "Список элементов не закончен нулевым размером.";
        return items;
    }

    /// <summary>A readable path from items: drive or known folder first, then names.</summary>
    public static string ToPath(IEnumerable<ShellItem> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        var sb = new StringBuilder();
        foreach (var i in items)
        {
            switch (i.Kind)
            {
                case ShellItemKind.RootFolder when i.FolderId == new Guid("20D04FE0-3AEA-1069-A2D8-08002B30309D"):
                    continue; // "This PC" adds nothing to a drive path
                case ShellItemKind.Volume:
                    sb.Clear().Append(i.Name?.TrimEnd('\\'));
                    continue;
            }

            if (string.IsNullOrEmpty(i.Name))
            {
                continue;
            }

            if (sb.Length > 0)
            {
                sb.Append('\\');
            }

            sb.Append(i.Name);
        }

        return sb.ToString();
    }

    /// <summary>One item including its 2-byte size field.</summary>
    public static ShellItem Parse(ReadOnlySpan<byte> item)
    {
        if (item.Length < 3)
        {
            return new ShellItem { Kind = ShellItemKind.Unknown, Problem = "Элемент короче 3 байт." };
        }

        var type = item[2];
        try
        {
            return type switch
            {
                0x1F => RootFolder(item),
                >= 0x20 and <= 0x2F => Volume(item, type),
                >= 0x30 and <= 0x3F => FileEntry(item, type),
                >= 0x40 and <= 0x4F => Network(item, type),
                0x61 => Uri(item),
                0x71 or 0x70 => new ShellItem { Kind = ShellItemKind.ControlPanel, Type = type, FolderId = ReadGuid(item, 14) },
                0x74 => Delegate(item),
                _ => new ShellItem { Kind = ShellItemKind.Unknown, Type = type, Problem = $"Неизвестный тип элемента 0x{type:X2}." },
            };
        }
        catch (ArgumentOutOfRangeException)
        {
            return new ShellItem { Kind = ShellItemKind.Unknown, Type = type, Problem = "Элемент повреждён (поле за границей)." };
        }
    }

    private static ShellItem RootFolder(ReadOnlySpan<byte> b)
    {
        var guid = ReadGuid(b, 4);
        return new ShellItem
        {
            Kind = ShellItemKind.RootFolder,
            Type = 0x1F,
            FolderId = guid,
            Name = guid is { } g ? KnownFolders.GetValueOrDefault(g, "{" + g + "}") : null,
        };
    }

    private static ShellItem Volume(ReadOnlySpan<byte> b, byte type)
    {
        // Drive letter as ASCII ("C:\") right after the type byte; some variants hold a GUID instead.
        var end = b[3..].IndexOf((byte)0);
        var text = end > 0 ? Encoding.ASCII.GetString(b.Slice(3, Math.Min(end, 32))) : string.Empty;
        if (text.Length >= 2 && char.IsAsciiLetter(text[0]) && text[1] == ':')
        {
            return new ShellItem { Kind = ShellItemKind.Volume, Type = type, Name = text[..2] + "\\" };
        }

        return new ShellItem { Kind = ShellItemKind.Volume, Type = type, FolderId = b.Length >= 20 ? ReadGuid(b, 4) : null };
    }

    private static ShellItem FileEntry(ReadOnlySpan<byte> b, byte type)
    {
        if (b.Length < 14)
        {
            return new ShellItem { Kind = ShellItemKind.File, Type = type, Problem = "Элемент файла короче 14 байт." };
        }

        var isDirectory = (type & 0x01) != 0;
        var unicode = (type & 0x04) != 0;
        var size = BinaryPrimitives.ReadUInt32LittleEndian(b[4..]);
        var modified = DosTime(b.Slice(8, 4));
        string shortName;
        int afterName;
        if (unicode)
        {
            var span = b[14..];
            var end = IndexOfUtf16Nul(span);
            shortName = Encoding.Unicode.GetString(span[..(end < 0 ? span.Length & ~1 : end)]);
            afterName = 14 + (end < 0 ? span.Length : end + 2);
        }
        else
        {
            var span = b[14..];
            var end = span.IndexOf((byte)0);
            shortName = Encoding.Latin1.GetString(span[..(end < 0 ? span.Length : end)]);
            afterName = 14 + (end < 0 ? span.Length : end + 1);
            if ((afterName & 1) != 0)
            {
                afterName++; // padded to an even offset
            }
        }

        var item = new ShellItem
        {
            Kind = isDirectory ? ShellItemKind.Folder : ShellItemKind.File,
            Type = type,
            Name = shortName,
            ShortName = shortName,
            Size = isDirectory ? null : size,
            Modified = modified,
        };

        // Extension block BEEF0004 (Windows XP and later): long name, created/accessed times, MFT reference.
        var ext = FindBeef0004(b, afterName);
        return ext is null ? item : item with
        {
            Name = string.IsNullOrEmpty(ext.Value.LongName) ? shortName : ext.Value.LongName,
            Created = ext.Value.Created,
            Accessed = ext.Value.Accessed,
            MftEntry = ext.Value.MftEntry,
            MftSequence = ext.Value.MftSequence,
        };
    }

    private readonly record struct Beef0004(string? LongName, DateTimeOffset? Created, DateTimeOffset? Accessed, ulong? MftEntry, ushort? MftSequence);

    private static Beef0004? FindBeef0004(ReadOnlySpan<byte> b, int start)
    {
        for (var o = start; o + 8 <= b.Length; o += 2)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(b[(o + 4)..]) != 0xBEEF0004)
            {
                continue;
            }

            int size = BinaryPrimitives.ReadUInt16LittleEndian(b[o..]);
            if (size < 20 || o + size > b.Length)
            {
                return null;
            }

            var e = b.Slice(o, size);
            int version = BinaryPrimitives.ReadUInt16LittleEndian(e[2..]);
            var created = DosTime(e.Slice(8, 4));
            var accessed = DosTime(e.Slice(12, 4));
            ulong? entry = null;
            ushort? seq = null;
            var index = 18;
            if (version >= 7)
            {
                index += 2;
                if (index + 8 <= e.Length)
                {
                    var low = BinaryPrimitives.ReadUInt32LittleEndian(e[index..]);
                    var high = BinaryPrimitives.ReadUInt16LittleEndian(e[(index + 4)..]);
                    var s = BinaryPrimitives.ReadUInt16LittleEndian(e[(index + 6)..]);
                    var n = ((ulong)high << 32) | low;
                    if (n != 0 || s != 0)
                    {
                        entry = n;
                        seq = s;
                    }
                }

                index += 16;
            }

            if (version >= 3)
            {
                index += 2;
            }

            if (version >= 9)
            {
                index += 4;
            }

            if (version >= 8)
            {
                index += 4;
            }

            string? longName = null;
            if (index < e.Length - 2)
            {
                var span = e[index..^2];
                var end = IndexOfUtf16Nul(span);
                longName = Encoding.Unicode.GetString(span[..(end < 0 ? span.Length & ~1 : end)]);
            }

            return new Beef0004(longName, created, accessed, entry, seq);
        }

        return null;
    }

    private static ShellItem Network(ReadOnlySpan<byte> b, byte type)
    {
        if (b.Length < 6)
        {
            return new ShellItem { Kind = ShellItemKind.Network, Type = type, Problem = "Сетевой элемент короче 6 байт." };
        }

        var span = b[5..];
        var end = span.IndexOf((byte)0);
        return new ShellItem { Kind = ShellItemKind.Network, Type = type, Name = Encoding.Latin1.GetString(span[..(end < 0 ? span.Length : end)]) };
    }

    private static ShellItem Uri(ReadOnlySpan<byte> b)
    {
        // Variable layout; the URI is a NUL-terminated string (Unicode or ASCII) somewhere after the header.
        var text = Encoding.Unicode.GetString(b[Math.Min(b.Length, 8)..^((b.Length - Math.Min(b.Length, 8)) & 1)]);
        var at = text.IndexOf("://", StringComparison.Ordinal);
        var name = at > 0 ? text[Math.Max(0, text.LastIndexOfAny([' ', '\0'], at) + 1)..].Split('\0')[0] : null;
        return new ShellItem { Kind = ShellItemKind.Uri, Type = 0x61, Name = name };
    }

    private static ShellItem Delegate(ReadOnlySpan<byte> b)
    {
        // Delegate items wrap a file entry ("CFSF") used by OneDrive and libraries.
        var at = b.IndexOf("CFSF"u8);
        if (at >= 0 && at + 6 < b.Length)
        {
            int inner = BinaryPrimitives.ReadUInt16LittleEndian(b[(at + 4)..]);
            if (inner >= 14 && at + 4 + inner <= b.Length)
            {
                var file = FileEntry(b.Slice(at + 4, inner), b[at + 6]);
                return file with { Kind = file.Kind, Type = 0x74 };
            }
        }

        return new ShellItem { Kind = ShellItemKind.Delegate, Type = 0x74, Problem = "Делегированный элемент без вложенного файла." };
    }

    internal static DateTimeOffset? DosTime(ReadOnlySpan<byte> b)
    {
        if (b.Length < 4)
        {
            return null;
        }

        var date = BinaryPrimitives.ReadUInt16LittleEndian(b);
        var time = BinaryPrimitives.ReadUInt16LittleEndian(b[2..]);
        var day = date & 0x1F;
        var month = (date >> 5) & 0x0F;
        var year = (date >> 9) + 1980;
        var hour = time >> 11;
        var minute = (time >> 5) & 0x3F;
        var second = (time & 0x1F) * 2;
        if (month is < 1 or > 12 || day < 1 || day > DateTime.DaysInMonth(year, month) || hour > 23 || minute > 59 || second > 59)
        {
            return null;
        }

        return new DateTimeOffset(year, month, day, hour, minute, second, TimeSpan.Zero);
    }

    internal static Guid? ReadGuid(ReadOnlySpan<byte> b, int offset) =>
        offset >= 0 && offset + 16 <= b.Length ? new Guid(b.Slice(offset, 16)) : null;

    internal static int IndexOfUtf16Nul(ReadOnlySpan<byte> span)
    {
        for (var i = 0; i + 1 < span.Length; i += 2)
        {
            if (span[i] == 0 && span[i + 1] == 0)
            {
                return i;
            }
        }

        return -1;
    }
}
