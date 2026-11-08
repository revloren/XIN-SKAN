using System.ComponentModel;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using XINSkan.Platform.Windows.Native;

namespace XINSkan.Platform.Windows.IO;

/// <summary>
/// Opens investigated files. The access mask is fixed to GENERIC_READ and sharing to read, write and delete,
/// so the investigated system's own processes are never blocked. There is no overload that takes an access mode.
/// </summary>
/// <remarks>
/// Known side effect: if NTFS last-access updates are enabled, reading a file may change its last-access time.
/// Preventing that requires FILE_WRITE_ATTRIBUTES, which this layer never requests (see docs/SECURITY.md).
/// </remarks>
[SupportedOSPlatform("windows")]
public static class ReadOnlyFile
{
    private const int ErrorAccessDenied = 5;

    public static SafeFileHandle OpenHandle(string path) =>
        TryOpenHandle(path, out var error) ?? throw Translate(path, error);

    /// <summary>Like <see cref="OpenHandle"/>, but returns null when the file or stream does not exist.</summary>
    public static SafeFileHandle? TryOpenExisting(string path)
    {
        var handle = TryOpenHandle(path, out var error);
        if (handle is not null)
        {
            return handle;
        }

        return error is NativeMethods.ErrorFileNotFound or NativeMethods.ErrorPathNotFound ? null : throw Translate(path, error);
    }

    /// <summary>NTFS identity of an open file (volume serial, MFT entry and sequence); null if the file system has none.</summary>
    public static unsafe XINSkan.Core.IO.FileIdentity? GetIdentity(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        NativeMethods.ByHandleFileInformation info;
        if (!NativeMethods.GetFileInformationByHandle(handle, &info))
        {
            return null;
        }

        var reference = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
        return XINSkan.Core.IO.FileIdentity.FromFileReference(info.VolumeSerialNumber, reference, (int)info.NumberOfLinks);
    }

    /// <summary>
    /// Adds the \\?\ prefix to paths at or beyond MAX_PATH, so CreateFileW accepts them without the system-wide
    /// long-path setting.
    /// </summary>
    public static string ToExtendedPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (path.Length < 248 || path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            return path;
        }

        return path.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + path[2..] : @"\\?\" + path;
    }

    private static SafeFileHandle? TryOpenHandle(string path, out int error)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var handle = NativeMethods.CreateFile(
            ToExtendedPath(path),
            NativeMethods.GenericRead,
            NativeMethods.ShareAll,
            IntPtr.Zero,
            NativeMethods.OpenExisting,
            NativeMethods.FileFlagBackupSemantics | NativeMethods.FileFlagSequentialScan,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            error = System.Runtime.InteropServices.Marshal.GetLastPInvokeError();
            handle.Dispose();
            return null;
        }

        error = 0;
        return handle;
    }

    /// <summary>Access denied → <see cref="UnauthorizedAccessException"/>; missing → <see cref="FileNotFoundException"/>; else <see cref="IOException"/>.</summary>
    private static Exception Translate(string path, int error)
    {
        var w = new Win32Exception(error);
        return error switch
        {
            ErrorAccessDenied => new UnauthorizedAccessException($"Access to '{path}' is denied.", w),
            NativeMethods.ErrorFileNotFound or NativeMethods.ErrorPathNotFound => new FileNotFoundException($"'{path}' does not exist.", path, w),
            _ => new IOException($"Cannot open '{path}' for reading: {w.Message} (Win32 error {error}).", w),
        };
    }

    /// <summary>A seekable, non-writable stream over the file.</summary>
    public static Stream OpenRead(string path) => new ReadOnlyHandleStream(OpenHandle(path), ownsHandle: true);
}

/// <summary>
/// Stream over a read handle. <see cref="CanWrite"/> is false and every write path throws, so a parser that
/// receives this stream cannot write back even if it tries.
/// </summary>
public sealed class ReadOnlyHandleStream : Stream
{
    private readonly SafeFileHandle _handle;
    private readonly bool _ownsHandle;
    private readonly long _length;
    private long _position;

    public ReadOnlyHandleStream(SafeFileHandle handle, bool ownsHandle, long? length = null)
    {
        ArgumentNullException.ThrowIfNull(handle);
        _handle = handle;
        _ownsHandle = ownsHandle;
        _length = length ?? RandomAccess.GetLength(handle);
    }

    public override bool CanRead => !_handle.IsClosed;

    public override bool CanSeek => !_handle.IsClosed;

    public override bool CanWrite => false;

    public override long Length => _length;

    public override long Position
    {
        get => _position;
        set => Seek(value, SeekOrigin.Begin);
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_handle.IsClosed, this);
        if (_position >= _length || buffer.IsEmpty)
        {
            return 0;
        }

        var toRead = (int)Math.Min(buffer.Length, _length - _position);
        var read = RandomAccess.Read(_handle, buffer[..toRead], _position);
        _position += read;
        return read;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        var target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };

        ArgumentOutOfRangeException.ThrowIfNegative(target, nameof(offset));
        _position = target;
        return _position;
    }

    public override void Flush()
    {
        // Nothing is ever written.
    }

    public override void SetLength(long value) => throw new NotSupportedException("XIN SKAN streams are read-only.");

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException("XIN SKAN streams are read-only.");

    public override void Write(ReadOnlySpan<byte> buffer) => throw new NotSupportedException("XIN SKAN streams are read-only.");

    public override void WriteByte(byte value) => throw new NotSupportedException("XIN SKAN streams are read-only.");

    protected override void Dispose(bool disposing)
    {
        if (disposing && _ownsHandle)
        {
            _handle.Dispose();
        }

        base.Dispose(disposing);
    }
}
