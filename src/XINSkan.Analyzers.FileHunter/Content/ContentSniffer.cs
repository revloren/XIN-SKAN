using System.Buffers.Binary;

namespace XINSkan.Analyzers.FileHunter.Content;

/// <summary>What a file is by its bytes, regardless of its name.</summary>
public enum ContentType
{
    Unknown,
    Empty,
    Zip,
    PortableExecutable,
    JavaClass,
}

/// <summary>Recognises archives, Windows executables and Java classes from the first bytes of a file.</summary>
public static class ContentSniffer
{
    /// <summary>How many bytes <see cref="Detect"/> needs to recognise every supported type.</summary>
    public const int HeaderSize = 1024;

    public static ContentType Detect(ReadOnlySpan<byte> header, long fileLength)
    {
        if (fileLength == 0 || header.IsEmpty)
        {
            return ContentType.Empty;
        }

        if (header.Length >= 4 && header[0] == 'P' && header[1] == 'K'
            && ((header[2] == 3 && header[3] == 4) || (header[2] == 5 && header[3] == 6) || (header[2] == 7 && header[3] == 8)))
        {
            return ContentType.Zip;
        }

        if (header.Length >= 4 && BinaryPrimitives.ReadUInt32BigEndian(header) == 0xCAFEBABE)
        {
            return ContentType.JavaClass;
        }

        if (header.Length >= 0x40 && header[0] == 'M' && header[1] == 'Z')
        {
            var peOffset = BinaryPrimitives.ReadInt32LittleEndian(header[0x3C..]);
            if (peOffset > 0 && peOffset <= header.Length - 4
                && header[peOffset] == 'P' && header[peOffset + 1] == 'E' && header[peOffset + 2] == 0 && header[peOffset + 3] == 0)
            {
                return ContentType.PortableExecutable;
            }

            // A PE header beyond the sniffed range is still most likely an executable; the PE inspector decides.
            if (peOffset > header.Length - 4 && peOffset < 1024 * 1024)
            {
                return ContentType.PortableExecutable;
            }
        }

        return ContentType.Unknown;
    }

    /// <summary>Extension-implied type, used to report a mismatch between name and content.</summary>
    public static ContentType ImpliedBy(string extension) => extension.ToUpperInvariant() switch
    {
        ".JAR" or ".ZIP" or ".MRPACK" => ContentType.Zip,
        ".EXE" or ".DLL" or ".SYS" or ".SCR" or ".CPL" or ".OCX" => ContentType.PortableExecutable,
        ".CLASS" => ContentType.JavaClass,
        _ => ContentType.Unknown,
    };
}
