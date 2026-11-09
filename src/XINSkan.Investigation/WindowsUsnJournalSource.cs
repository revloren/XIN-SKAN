using System.Runtime.Versioning;
using XINSkan.Analyzers.History;
using XINSkan.Ntfs;
using XINSkan.Platform.Windows.IO;

namespace XINSkan.Investigation;

/// <summary>The change journal of a mounted volume, read through FSCTL_READ_USN_JOURNAL (read only).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsUsnJournalSource : IUsnJournalSource
{
    public static readonly WindowsUsnJournalSource Instance = new();

    public UsnJournalInfo Query(string drive)
    {
        using var volume = VolumeReader.Open(drive);
        return UsnJournalInfo.Parse(UsnJournal.Query(volume.Handle));
    }

    public IEnumerable<ReadOnlyMemory<byte>> Read(string drive, UsnJournalInfo info, CancellationToken cancellationToken)
    {
        using var volume = VolumeReader.Open(drive);

        // If the system overwrites the oldest records while we read, continue from the new first record.
        long Restart() => UsnJournalInfo.Parse(UsnJournal.Query(volume.Handle)).FirstUsn;
        foreach (var block in UsnJournal.Read(volume.Handle, info.JournalId, info.FirstUsn, info.NextUsn, Restart, cancellationToken))
        {
            yield return block;
        }
    }
}

/// <summary>Used where no change journal can be read (tests, other platforms).</summary>
public sealed class NoUsnJournal : IUsnJournalSource
{
    public static readonly NoUsnJournal Instance = new();

    public UsnJournalInfo Query(string drive) => throw new UnauthorizedAccessException($"The change journal of {drive} is not available here.");

    public IEnumerable<ReadOnlyMemory<byte>> Read(string drive, UsnJournalInfo info, CancellationToken cancellationToken) => [];
}
