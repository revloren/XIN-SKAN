using System.Runtime.Versioning;
using XINSkan.Platform.Windows.Native;

namespace XINSkan.Platform.Windows.IO;

/// <summary>A mounted volume as artifacts name it: drive letter, NT device path and serial number.</summary>
public sealed record MountedVolume(string Drive, string? DevicePath, uint? Serial, DriveType Type);

/// <summary>Lists mounted volumes with their device paths and serials (QueryDosDeviceW, GetVolumeInformationW). Query only.</summary>
[SupportedOSPlatform("windows")]
public static class VolumeNames
{
    public static IReadOnlyList<MountedVolume> List()
    {
        var list = new List<MountedVolume>();
        foreach (var d in DriveInfo.GetDrives())
        {
            var drive = d.Name[..2];
            list.Add(new MountedVolume(drive, Device(drive), Serial(d.Name), d.DriveType));
        }

        return list;
    }

    private static unsafe string? Device(string drive)
    {
        var buffer = stackalloc char[1024];
        var n = NativeMethods.QueryDosDevice(drive, buffer, 1024);
        return n == 0 ? null : new string(buffer).TrimEnd('\0');
    }

    private static unsafe uint? Serial(string root)
    {
        return NativeMethods.GetVolumeInformation(root, null, 0, out var serial, out _, out _, null, 0) ? serial : null;
    }
}
