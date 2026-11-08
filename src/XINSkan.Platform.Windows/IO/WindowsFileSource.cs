using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using XINSkan.Core.IO;

namespace XINSkan.Platform.Windows.IO;

/// <summary>
/// <see cref="IFileSource"/> for Windows: every file and alternate stream is opened through
/// <see cref="ReadOnlyFile"/> (GENERIC_READ, full sharing), and the NTFS identity is read from the same handle.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFileSource : IFileSource
{
    /// <summary>How files are opened, as written to the audit log.</summary>
    public const string AccessDescription = "GENERIC_READ; share read/write/delete; OPEN_EXISTING; backup semantics";

    public static readonly WindowsFileSource Instance = new();

    public IOpenedFile Open(string path) => Wrap(ReadOnlyFile.OpenHandle(path));

    public IOpenedFile? TryOpenStream(string path, string streamName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(streamName);
        if (streamName.AsSpan().IndexOfAny(":\\/") >= 0)
        {
            throw new ArgumentException("A stream name must not contain ':' or path separators.", nameof(streamName));
        }

        var handle = ReadOnlyFile.TryOpenExisting(path + ":" + streamName);
        return handle is null ? null : Wrap(handle);
    }

    private static OpenedFile Wrap(SafeFileHandle handle)
    {
        try
        {
            var identity = ReadOnlyFile.GetIdentity(handle);
            return new OpenedFile(handle, identity);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private sealed class OpenedFile(SafeFileHandle handle, FileIdentity? identity) : IOpenedFile
    {
        private readonly ReadOnlyHandleStream _stream = new(handle, ownsHandle: true);

        public Stream Content => _stream;

        public FileIdentity? Identity { get; } = identity;

        public void Dispose() => _stream.Dispose();
    }
}
