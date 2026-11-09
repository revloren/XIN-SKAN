using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace XINSkan.ShellFormats;

/// <summary>One entry of a DestList: a file or folder an application opened, with when and how often.</summary>
public sealed record DestListEntry(
    int EntryNumber,
    int MruPosition,
    string Path,
    string Hostname,
    long LastModified,
    bool Pinned,
    int? InteractionCount,
    LinkTracker Droids,
    LnkFile? Lnk);

/// <summary>A parsed automaticDestinations-ms (Jump List of one application).</summary>
public sealed class AutomaticDestinations
{
    public int Version { get; private set; }

    public int DeclaredEntries { get; private set; }

    public int DeclaredPinned { get; private set; }

    public List<DestListEntry> Entries { get; } = [];

    public List<string> Problems { get; } = [];

    public static AutomaticDestinations? Parse(byte[] data, out string? problem)
    {
        var cf = CompoundFile.Open(data, out problem);
        if (cf is null)
        {
            return null;
        }

        var a = new AutomaticDestinations();
        a.Problems.AddRange(cf.Problems);
        var dest = cf.ReadStream("DestList");
        if (dest is null)
        {
            a.Problems.Add("Нет потока DestList.");
            return a;
        }

        if (dest.Length < 32)
        {
            if (dest.Length > 0)
            {
                a.Problems.Add("Поток DestList короче заголовка.");
            }

            return a;
        }

        var d = dest.AsSpan();
        a.Version = BinaryPrimitives.ReadInt32LittleEndian(d);
        a.DeclaredEntries = BinaryPrimitives.ReadInt32LittleEndian(d[4..]);
        a.DeclaredPinned = BinaryPrimitives.ReadInt32LittleEndian(d[8..]);
        var pathSizeOffset = a.Version == 1 ? 112 : 128;
        var o = 32;
        var mru = 0;
        while (o < d.Length && (a.Version != 1 || a.Entries.Count < a.DeclaredEntries) && a.Entries.Count < 10_000)
        {
            var remaining = d.Length - o;
            if (remaining < pathSizeOffset + 2)
            {
                a.Problems.Add($"{remaining} байт в конце DestList не составляют запись.");
                break;
            }

            int chars = BinaryPrimitives.ReadInt16LittleEndian(d[(o + pathSizeOffset)..]);
            var entrySize = pathSizeOffset + 2 + (chars * 2);
            if (chars < 0 || entrySize > remaining)
            {
                a.Problems.Add($"Запись DestList на 0x{o:X}: путь длиной {chars} выходит за поток.");
                break;
            }

            var stride = entrySize;
            if (a.Version != 1)
            {
                if (remaining < entrySize + 4)
                {
                    a.Problems.Add($"Запись DestList на 0x{o:X} без размера хранилища свойств.");
                    break;
                }

                var sps = BinaryPrimitives.ReadInt32LittleEndian(d[(o + entrySize)..]);
                if (sps < 0 || sps > remaining - entrySize - 4)
                {
                    a.Problems.Add($"Запись DestList на 0x{o:X}: хранилище свойств выходит за поток.");
                    break;
                }

                stride = entrySize + 4 + sps;
            }

            var e = d.Slice(o, stride);
            var host = e.Slice(72, 16);
            var hostEnd = host.IndexOf((byte)0);
            var number = BinaryPrimitives.ReadInt32LittleEndian(e[88..]);
            var lnkBytes = cf.ReadStream(number.ToString("x", CultureInfo.InvariantCulture));
            var lnk = lnkBytes is null ? null : LnkFile.Parse(lnkBytes);
            var hostname = Encoding.ASCII.GetString(host[..(hostEnd < 0 ? 16 : hostEnd)]);
            a.Entries.Add(new DestListEntry(
                number,
                mru++,
                Encoding.Unicode.GetString(e.Slice(pathSizeOffset + 2, chars * 2)),
                hostname,
                BinaryPrimitives.ReadInt64LittleEndian(e[100..]),
                BinaryPrimitives.ReadInt32LittleEndian(e[108..]) != -1,
                a.Version > 1 ? BinaryPrimitives.ReadInt32LittleEndian(e[116..]) : null,
                new LinkTracker(hostname, new Guid(e.Slice(8, 16)), new Guid(e.Slice(24, 16)), new Guid(e.Slice(40, 16)), new Guid(e.Slice(56, 16))),
                lnk));
            o += stride;
        }

        return a;
    }
}

/// <summary>Links in a customDestinations-ms (tasks and categories an application put in its Jump List).</summary>
public static class CustomDestinations
{
    public static List<LnkFile> Parse(ReadOnlySpan<byte> b)
    {
        var links = new List<LnkFile>();
        for (var o = 0; o + 76 <= b.Length && links.Count < 10_000; o++)
        {
            if (b[o] != 0x4C || !LnkFile.LooksLikeLnk(b[o..]))
            {
                continue;
            }

            if (LnkFile.Parse(b[o..]) is { } l)
            {
                links.Add(l);
            }

            o += 75;
        }

        return links;
    }
}
