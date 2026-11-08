namespace XINSkan.Core.IO;

/// <summary>
/// NTFS identity of an open file: volume serial and the 64-bit file reference (48-bit MFT entry + 16-bit sequence).
/// This is the strongest key for linking a live file to MFT and USN records.
/// </summary>
public sealed record FileIdentity(ulong VolumeSerial, ulong MftEntry, ushort MftSequence, int LinkCount)
{
    /// <summary>Splits a 64-bit NTFS file reference into entry and sequence.</summary>
    public static FileIdentity FromFileReference(ulong volumeSerial, ulong fileReference, int linkCount) =>
        new(volumeSerial, fileReference & 0x0000_FFFF_FFFF_FFFFUL, (ushort)(fileReference >> 48), linkCount);
}

/// <summary>A file opened for reading. Disposing closes it.</summary>
public interface IOpenedFile : IDisposable
{
    /// <summary>Seekable, non-writable stream positioned at 0.</summary>
    Stream Content { get; }

    /// <summary>NTFS identity, when the platform can provide it.</summary>
    FileIdentity? Identity { get; }
}

/// <summary>
/// The only way analyzers open investigated files. On Windows: GENERIC_READ with full sharing
/// (XINSkan.Platform.Windows); tests supply their own implementation.
/// </summary>
public interface IFileSource
{
    /// <exception cref="IOException">The file cannot be opened (missing, locked exclusively, ...).</exception>
    /// <exception cref="UnauthorizedAccessException">Access is denied.</exception>
    IOpenedFile Open(string path);

    /// <summary>Opens an alternate data stream (for example "Zone.Identifier"); null when it does not exist.</summary>
    IOpenedFile? TryOpenStream(string path, string streamName);
}

/// <summary>One directory entry as returned by enumeration; no file is opened to obtain it.</summary>
public sealed record FsEntry(
    string FullPath,
    string Name,
    bool IsDirectory,
    long Length,
    FileAttributes Attributes,
    DateTime CreationTimeUtc,
    DateTime LastWriteTimeUtc,
    DateTime LastAccessTimeUtc)
{
    public bool IsReparsePoint => (Attributes & FileAttributes.ReparsePoint) != 0;

    public bool IsHidden => (Attributes & FileAttributes.Hidden) != 0;

    public bool IsSystem => (Attributes & FileAttributes.System) != 0;
}

/// <summary>Lists one directory level. Errors (access denied, vanished directory) are thrown to the caller.</summary>
public interface IDirectoryLister
{
    IReadOnlyList<FsEntry> List(string directory);

    bool DirectoryExists(string path);
}

/// <summary>Embedded Authenticode signature status of a file.</summary>
public enum SignatureStatus
{
    /// <summary>Not checked (not a PE file, platform without verification, or verification not attempted).</summary>
    NotChecked,

    /// <summary>The file has no embedded signature. Windows system files are often catalog-signed and show here.</summary>
    NotSigned,

    /// <summary>The signature is valid and chains to a trusted root (revocation not checked, no network).</summary>
    Valid,

    /// <summary>The file was modified after signing.</summary>
    Tampered,

    /// <summary>A signature is present but not trusted (unknown root, expired, explicitly distrusted, ...).</summary>
    Untrusted,

    /// <summary>Verification itself failed.</summary>
    Error,
}

public sealed record SignatureResult(SignatureStatus Status, string Detail);

/// <summary>Verifies embedded signatures without network access.</summary>
public interface ISignatureVerifier
{
    SignatureResult Verify(string path);
}

/// <summary>Used where the platform cannot verify signatures; reports NotChecked honestly.</summary>
public sealed class NoSignatureVerifier : ISignatureVerifier
{
    public static readonly NoSignatureVerifier Instance = new();

    public SignatureResult Verify(string path) => new(SignatureStatus.NotChecked, "Signature verification is not available on this platform.");
}

/// <summary>Directory enumeration through System.IO (read-only; FindFirstFile data, no file is opened).</summary>
public sealed class SystemDirectoryLister : IDirectoryLister
{
    private static readonly EnumerationOptions Options = new()
    {
        RecurseSubdirectories = false,
        IgnoreInaccessible = false,
        AttributesToSkip = 0,
        ReturnSpecialDirectories = false,
        MatchType = MatchType.Simple,
    };

    public static readonly SystemDirectoryLister Instance = new();

    public IReadOnlyList<FsEntry> List(string directory)
    {
        var list = new List<FsEntry>();
        foreach (var i in new DirectoryInfo(directory).EnumerateFileSystemInfos("*", Options))
        {
            var isDir = (i.Attributes & FileAttributes.Directory) != 0;
            list.Add(new FsEntry(
                i.FullName,
                i.Name,
                isDir,
                isDir ? 0 : ((FileInfo)i).Length,
                i.Attributes,
                i.CreationTimeUtc,
                i.LastWriteTimeUtc,
                i.LastAccessTimeUtc));
        }

        return list;
    }

    public bool DirectoryExists(string path) => Directory.Exists(path);
}
