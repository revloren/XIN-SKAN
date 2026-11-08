using System.ComponentModel;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using XINSkan.Platform.Windows.Native;

namespace XINSkan.Platform.Windows.IO;

/// <summary>
/// The complete list of device control codes XIN SKAN may send. All of them only query or read.
/// Codes that change state (FSCTL_DELETE_USN_JOURNAL, FSCTL_CREATE_USN_JOURNAL, FSCTL_WRITE_USN_CLOSE_RECORD,
/// FSCTL_SET_*, IOCTL_DISK_*_WRITE...) are not representable here.
/// </summary>
public enum AllowedIoControl : uint
{
    /// <summary>IOCTL_DISK_GET_DRIVE_GEOMETRY — sector size of the device.</summary>
    DiskGetDriveGeometry = 0x0007_0000,

    /// <summary>FSCTL_GET_NTFS_VOLUME_DATA — cluster size, MFT location and size.</summary>
    GetNtfsVolumeData = 0x0009_0064,

    /// <summary>FSCTL_GET_RETRIEVAL_POINTERS — cluster runs of a file (to read locked files from the volume).</summary>
    GetRetrievalPointers = 0x0009_0073,

    /// <summary>FSCTL_ENUM_USN_DATA — enumerate MFT entries through the change journal interface.</summary>
    EnumUsnData = 0x0009_00B3,

    /// <summary>FSCTL_READ_USN_JOURNAL — read change journal records.</summary>
    ReadUsnJournal = 0x0009_00BB,

    /// <summary>FSCTL_QUERY_USN_JOURNAL — journal ID, first and next USN, maximum size.</summary>
    QueryUsnJournal = 0x0009_00F4,
}

public static class SafeIoControl
{
    /// <summary>Sends an allowed control code. Values outside <see cref="AllowedIoControl"/> are refused even if cast in.</summary>
    /// <returns>Number of bytes written to <paramref name="output"/>.</returns>
    [SupportedOSPlatform("windows")]
    public static unsafe int Invoke(SafeFileHandle device, AllowedIoControl code, ReadOnlySpan<byte> input, Span<byte> output)
    {
        ArgumentNullException.ThrowIfNull(device);
        EnsureAllowed(code);

        fixed (byte* inPtr = input)
        fixed (byte* outPtr = output)
        {
            if (!NativeMethods.DeviceIoControl(device, (uint)code, inPtr, (uint)input.Length, outPtr, (uint)output.Length, out var returned, IntPtr.Zero))
            {
                throw new Win32Exception();
            }

            return (int)returned;
        }
    }

    /// <summary>Throws for any value that is not a declared member of the allow-list.</summary>
    public static void EnsureAllowed(AllowedIoControl code)
    {
        if (!Enum.IsDefined(code))
        {
            throw new ArgumentOutOfRangeException(nameof(code), $"Control code 0x{(uint)code:X8} is not on the read-only allow-list.");
        }
    }
}
