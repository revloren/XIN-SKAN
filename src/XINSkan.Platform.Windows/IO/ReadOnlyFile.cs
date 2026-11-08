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
    public static SafeFileHandle OpenHandle(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var handle = NativeMethods.CreateFile(
            path,
            NativeMethods.GenericRead,
            NativeMethods.ShareAll,
            IntPtr.Zero,
            NativeMethods.OpenExisting,
            NativeMethods.FileFlagBackupSemantics | NativeMethods.FileFlagSequentialScan,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            var error = new Win32Exception();
            handle.Dispose();
            throw new IOException($"Cannot open '{path}' for reading: {error.Message}", error);
        }

        return handle;
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
