using System.Buffers;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using XINSkan.Platform.Windows.Native;

namespace XINSkan.Platform.Windows.IO;

/// <summary>Values reported by FSCTL_GET_NTFS_VOLUME_DATA (NTFS_VOLUME_DATA_BUFFER).</summary>
public sealed record NtfsVolumeData(
    ulong VolumeSerialNumber,
    long NumberSectors,
    long TotalClusters,
    uint BytesPerSector,
    uint BytesPerCluster,
    uint BytesPerFileRecordSegment,
    long MftValidDataLength,
    long MftStartLcn,
    long Mft2StartLcn)
{
    internal const int MinimumSize = 96;

    /// <summary>Parses the fixed part of NTFS_VOLUME_DATA_BUFFER.</summary>
    public static NtfsVolumeData Parse(ReadOnlySpan<byte> b)
    {
        if (b.Length < MinimumSize)
        {
            throw new ArgumentException($"NTFS_VOLUME_DATA_BUFFER is at least {MinimumSize} bytes, got {b.Length}.", nameof(b));
        }

        var data = new NtfsVolumeData(
            VolumeSerialNumber: BinaryPrimitives.ReadUInt64LittleEndian(b),
            NumberSectors: BinaryPrimitives.ReadInt64LittleEndian(b[8..]),
            TotalClusters: BinaryPrimitives.ReadInt64LittleEndian(b[16..]),
            BytesPerSector: BinaryPrimitives.ReadUInt32LittleEndian(b[40..]),
            BytesPerCluster: BinaryPrimitives.ReadUInt32LittleEndian(b[44..]),
            BytesPerFileRecordSegment: BinaryPrimitives.ReadUInt32LittleEndian(b[48..]),
            MftValidDataLength: BinaryPrimitives.ReadInt64LittleEndian(b[56..]),
            MftStartLcn: BinaryPrimitives.ReadInt64LittleEndian(b[64..]),
            Mft2StartLcn: BinaryPrimitives.ReadInt64LittleEndian(b[72..]));

        if (data.BytesPerSector is 0 || (data.BytesPerSector & (data.BytesPerSector - 1)) != 0
            || data.BytesPerCluster < data.BytesPerSector || data.BytesPerFileRecordSegment is < 256 or > 65536)
        {
            throw new InvalidDataException($"Implausible NTFS geometry: sector {data.BytesPerSector}, cluster {data.BytesPerCluster}, record {data.BytesPerFileRecordSegment}.");
        }

        return data;
    }
}

/// <summary>
/// Raw, sector-aligned reads from a mounted volume (\\.\C:). Requires administrator rights.
/// Opened with GENERIC_READ and full sharing; Windows keeps the volume mounted and writable for its own use.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class VolumeReader : IDisposable
{
    private readonly SafeFileHandle _handle;

    private VolumeReader(SafeFileHandle handle, string driveLetter, uint sectorSize)
    {
        _handle = handle;
        DriveLetter = driveLetter;
        SectorSize = sectorSize;
    }

    public string DriveLetter { get; }

    public uint SectorSize { get; }

    public SafeFileHandle Handle => _handle;

    /// <param name="drive">A drive letter such as "C" or "C:".</param>
    public static VolumeReader Open(string drive)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(drive);
        var letter = char.ToUpperInvariant(drive[0]);
        if (!char.IsAsciiLetterUpper(letter) || drive.Length > 3)
        {
            throw new ArgumentException($"'{drive}' is not a drive letter.", nameof(drive));
        }

        var handle = NativeMethods.CreateFile(
            $@"\\.\{letter}:",
            NativeMethods.GenericRead,
            NativeMethods.ShareAll,
            IntPtr.Zero,
            NativeMethods.OpenExisting,
            0,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            var error = new Win32Exception();
            handle.Dispose();
            throw new UnauthorizedAccessException($"Cannot open volume {letter}: for raw reading: {error.Message}", error);
        }

        uint sector = 512;
        try
        {
            Span<byte> geometry = stackalloc byte[24];
            if (SafeIoControl.Invoke(handle, AllowedIoControl.DiskGetDriveGeometry, default, geometry) >= 24)
            {
                // DISK_GEOMETRY: Cylinders(8) MediaType(4) TracksPerCylinder(4) SectorsPerTrack(4) BytesPerSector(4)
                var bps = BinaryPrimitives.ReadUInt32LittleEndian(geometry[20..]);
                if (bps is >= 512 and <= 65536 && (bps & (bps - 1)) == 0)
                {
                    sector = bps;
                }
            }
        }
        catch (Win32Exception)
        {
            // Some virtual volumes do not answer the geometry query; 512 is the safe minimum alignment.
        }

        return new VolumeReader(handle, $"{letter}:", sector);
    }

    /// <summary>Reads <paramref name="destination"/>.Length bytes at <paramref name="offset"/>; alignment is handled here.</summary>
    /// <returns>Bytes actually read (less than requested only at the end of the volume).</returns>
    public int Read(long offset, Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        if (destination.IsEmpty)
        {
            return 0;
        }

        var start = offset - (offset % SectorSize);
        var end = offset + destination.Length;
        var alignedEnd = end % SectorSize == 0 ? end : end + (SectorSize - (end % SectorSize));
        var length = checked((int)(alignedEnd - start));

        var buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            var total = 0;
            while (total < length)
            {
                var read = RandomAccess.Read(_handle, buffer.AsSpan(total, length - total), start + total);
                if (read == 0)
                {
                    break;
                }

                total += read;
            }

            var skip = (int)(offset - start);
            var available = Math.Max(0, Math.Min(destination.Length, total - skip));
            buffer.AsSpan(skip, available).CopyTo(destination);
            return available;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public NtfsVolumeData GetNtfsVolumeData()
    {
        Span<byte> output = stackalloc byte[128];
        var n = SafeIoControl.Invoke(_handle, AllowedIoControl.GetNtfsVolumeData, default, output);
        return NtfsVolumeData.Parse(output[..n]);
    }

    public void Dispose() => _handle.Dispose();
}
