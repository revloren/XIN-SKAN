using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection.PortableExecutable;
using System.Text;

namespace XINSkan.Analyzers.FileHunter.Content;

/// <summary>Facts from the headers and version resource of a Windows executable. Nothing is loaded or run.</summary>
public sealed record PeFacts
{
    public string? Machine { get; init; }

    public bool IsDll { get; init; }

    public bool IsDotNet { get; init; }

    public string? Subsystem { get; init; }

    /// <summary>Link time from the header. Often a hash in reproducible builds, so it is reported, never trusted.</summary>
    public uint TimeDateStamp { get; init; }

    public bool HasEmbeddedSignature { get; init; }

    /// <summary>FileVersion from VS_FIXEDFILEINFO, "a.b.c.d".</summary>
    public string? FixedFileVersion { get; init; }

    /// <summary>StringFileInfo values: CompanyName, OriginalFilename, ProductName, ...</summary>
    public IReadOnlyDictionary<string, string> Version { get; init; } = new Dictionary<string, string>();

    public IReadOnlyList<string> Problems { get; init; } = [];
}

/// <summary>Reads PE headers and the RT_VERSION resource with bounds checks on every step.</summary>
public static class PeInspector
{
    private const int RtVersion = 16;
    private const int MaxVersionResourceBytes = 64 * 1024;

    private static readonly string[] VersionKeys =
    [
        "CompanyName", "FileDescription", "FileVersion", "InternalName", "LegalCopyright", "OriginalFilename", "ProductName", "ProductVersion",
    ];

    public static PeFacts Inspect(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        stream.Position = 0;
        var problems = new List<string>();
        try
        {
            using var reader = new PEReader(stream, PEStreamOptions.LeaveOpen);
            var h = reader.PEHeaders;
            var coff = h.CoffHeader;
            var pe = h.PEHeader;

            string? fixedVersion = null;
            var version = new Dictionary<string, string>(StringComparer.Ordinal);
            if (pe is not null && pe.ResourceTableDirectory.Size > 0)
            {
                try
                {
                    var data = FindVersionResource(reader, pe.ResourceTableDirectory.RelativeVirtualAddress);
                    if (data is not null)
                    {
                        fixedVersion = ParseVersionInfo(data.Value.AsSpan(), version);
                    }
                }
                catch (Exception ex) when (ex is BadImageFormatException or ArgumentOutOfRangeException or InvalidOperationException or ArgumentException)
                {
                    problems.Add($"Ресурс версии повреждён: {ex.Message}");
                }
            }

            return new PeFacts
            {
                Machine = coff.Machine.ToString(),
                IsDll = (coff.Characteristics & Characteristics.Dll) != 0,
                IsDotNet = h.CorHeader is not null,
                Subsystem = pe?.Subsystem.ToString(),
                TimeDateStamp = unchecked((uint)coff.TimeDateStamp),
                HasEmbeddedSignature = pe is not null && pe.CertificateTableDirectory.Size > 0,
                FixedFileVersion = fixedVersion,
                Version = version,
                Problems = problems,
            };
        }
        catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException or ArgumentOutOfRangeException or IOException)
        {
            return new PeFacts { Problems = [$"Заголовки PE не читаются: {ex.Message}"] };
        }
    }

    /// <summary>Walks the resource directory: type RT_VERSION → first name → first language → data entry.</summary>
    private static ImmutableArray<byte>? FindVersionResource(PEReader reader, int resourceRva)
    {
        var section = reader.GetSectionData(resourceRva);
        if (section.Length < 16)
        {
            return null;
        }

        var rsrc = section.GetContent();
        var typeEntry = FindEntry(rsrc, 0, RtVersion, matchId: true);
        if (typeEntry is null || !IsDirectory(typeEntry.Value))
        {
            return null;
        }

        var nameEntry = FindEntry(rsrc, DirectoryOffset(typeEntry.Value), 0, matchId: false);
        if (nameEntry is null || !IsDirectory(nameEntry.Value))
        {
            return null;
        }

        var langEntry = FindEntry(rsrc, DirectoryOffset(nameEntry.Value), 0, matchId: false);
        if (langEntry is null || IsDirectory(langEntry.Value))
        {
            return null;
        }

        var dataEntry = (int)langEntry.Value;
        if (dataEntry < 0 || dataEntry + 16 > rsrc.Length)
        {
            throw new BadImageFormatException("Resource data entry lies outside the resource section.");
        }

        var span = rsrc.AsSpan();
        var dataRva = BinaryPrimitives.ReadInt32LittleEndian(span[dataEntry..]);
        var size = BinaryPrimitives.ReadInt32LittleEndian(span[(dataEntry + 4)..]);
        if (size <= 0 || size > MaxVersionResourceBytes)
        {
            throw new BadImageFormatException($"Version resource size {size} is out of range.");
        }

        var block = reader.GetSectionData(dataRva);
        if (block.Length < size)
        {
            throw new BadImageFormatException("Version resource extends beyond its section.");
        }

        return block.GetContent(0, size);
    }

    /// <returns>OffsetToData of the matching entry (high bit = subdirectory), or null.</returns>
    private static uint? FindEntry(ImmutableArray<byte> rsrc, int dirOffset, int id, bool matchId)
    {
        var span = rsrc.AsSpan();
        if (dirOffset < 0 || dirOffset + 16 > span.Length)
        {
            throw new BadImageFormatException("Resource directory lies outside the resource section.");
        }

        int named = BinaryPrimitives.ReadUInt16LittleEndian(span[(dirOffset + 12)..]);
        int ids = BinaryPrimitives.ReadUInt16LittleEndian(span[(dirOffset + 14)..]);
        var count = named + ids;
        var first = dirOffset + 16;
        if (first + (count * 8) > span.Length)
        {
            throw new BadImageFormatException("Resource directory entries lie outside the resource section.");
        }

        for (var i = 0; i < count; i++)
        {
            var e = first + (i * 8);
            var nameOrId = BinaryPrimitives.ReadUInt32LittleEndian(span[e..]);
            var offset = BinaryPrimitives.ReadUInt32LittleEndian(span[(e + 4)..]);
            if (!matchId || ((nameOrId & 0x8000_0000) == 0 && nameOrId == (uint)id))
            {
                return offset;
            }
        }

        return null;
    }

    private static bool IsDirectory(uint offsetToData) => (offsetToData & 0x8000_0000) != 0;

    private static int DirectoryOffset(uint offsetToData) => (int)(offsetToData & 0x7FFF_FFFF);

    /// <summary>Parses VS_VERSIONINFO; fills the string table values and returns the fixed file version.</summary>
    internal static string? ParseVersionInfo(ReadOnlySpan<byte> data, Dictionary<string, string> strings)
    {
        var root = Node(data, 0);
        if (root is null || root.Value.Key != "VS_VERSION_INFO")
        {
            return null;
        }

        string? fixedVersion = null;
        var r = root.Value;
        if (r.ValueOffset + 52 <= r.End && BinaryPrimitives.ReadUInt32LittleEndian(data[r.ValueOffset..]) == 0xFEEF04BD)
        {
            var ms = BinaryPrimitives.ReadUInt32LittleEndian(data[(r.ValueOffset + 8)..]);
            var ls = BinaryPrimitives.ReadUInt32LittleEndian(data[(r.ValueOffset + 12)..]);
            fixedVersion = $"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}";
        }

        foreach (var child in Children(data, r))
        {
            if (child.Key != "StringFileInfo")
            {
                continue;
            }

            foreach (var table in Children(data, child))
            {
                foreach (var s in Children(data, table))
                {
                    if (VersionKeys.Contains(s.Key, StringComparer.Ordinal) && !strings.ContainsKey(s.Key))
                    {
                        var value = ReadZString(data, s.ValueOffset, s.End);
                        if (!string.IsNullOrWhiteSpace(value))
                        {
                            strings[s.Key] = value.Trim();
                        }
                    }
                }

                // The first string table is the primary language; others usually repeat it.
                break;
            }
        }

        return fixedVersion;
    }

    private readonly record struct VersionNode(string Key, int ValueOffset, int ChildrenOffset, int End);

    private static VersionNode? Node(ReadOnlySpan<byte> data, int offset)
    {
        if (offset < 0 || offset + 6 > data.Length)
        {
            return null;
        }

        int length = BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
        int valueLength = BinaryPrimitives.ReadUInt16LittleEndian(data[(offset + 2)..]);
        int type = BinaryPrimitives.ReadUInt16LittleEndian(data[(offset + 4)..]);
        var end = offset + length;
        if (length < 6 || end > data.Length)
        {
            return null;
        }

        var keyStart = offset + 6;
        var keyEnd = keyStart;
        while (keyEnd + 1 < end && (data[keyEnd] != 0 || data[keyEnd + 1] != 0))
        {
            keyEnd += 2;
        }

        if (keyEnd + 1 >= end)
        {
            return null;
        }

        var key = Encoding.Unicode.GetString(data[keyStart..keyEnd]);
        var valueOffset = Align4(keyEnd + 2);
        var valueBytes = type == 1 ? valueLength * 2 : valueLength;
        var childrenOffset = Math.Min(end, Align4(valueOffset + valueBytes));
        return new VersionNode(key, Math.Min(valueOffset, end), childrenOffset, end);
    }

    private static List<VersionNode> Children(ReadOnlySpan<byte> data, VersionNode parent)
    {
        var list = new List<VersionNode>();
        var o = parent.ChildrenOffset;
        while (o < parent.End && list.Count < 256)
        {
            var n = Node(data, o);
            if (n is null || n.Value.End <= o)
            {
                break;
            }

            list.Add(n.Value);
            o = Align4(n.Value.End);
        }

        return list;
    }

    private static string ReadZString(ReadOnlySpan<byte> data, int start, int end)
    {
        var e = start;
        while (e + 1 < end && (data[e] != 0 || data[e + 1] != 0))
        {
            e += 2;
        }

        return start < e ? Encoding.Unicode.GetString(data[start..e]) : string.Empty;
    }

    private static int Align4(int v) => (v + 3) & ~3;
}
