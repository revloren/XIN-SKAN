using System.Runtime.Versioning;
using XINSkan.Analyzers.History;
using XINSkan.Ntfs;
using XINSkan.Platform.Windows.IO;

namespace XINSkan.Investigation;

/// <summary>Raw read-only volume access for the History Engine through the platform layer (\\.\C:).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsVolumeOpener : IVolumeOpener
{
    public static readonly WindowsVolumeOpener Instance = new();

    public IRawVolume Open(string drive) => new Volume(VolumeReader.Open(drive));

    private sealed class Volume(VolumeReader reader) : IRawVolume, IDisposable
    {
        public int Read(long offset, Span<byte> buffer) => reader.Read(offset, buffer);

        public void Dispose() => reader.Dispose();
    }
}
