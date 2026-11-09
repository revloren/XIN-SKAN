using XINSkan.Analyzers.History;
using XINSkan.Core.IO;
using XINSkan.Ntfs;
using XINSkan.Security;

namespace XINSkan.Investigation;

/// <summary>Records every file and stream an analyzer opens in the audit log, with the result.</summary>
/// <remarks>
/// A probe for an alternate stream that does not exist opens nothing and is not recorded; every stream that is
/// opened, and every failure other than "not found", is.
/// </remarks>
public sealed class AuditingFileSource(IFileSource inner, AuditLogger log, string access) : IFileSource
{
    public IOpenedFile Open(string path)
    {
        try
        {
            var opened = inner.Open(path);
            log.Record("open-file", path, access, "ok");
            return opened;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log.Record("open-file", path, access, AuditResults.Of(ex), ex.Message);
            throw;
        }
    }

    public IOpenedFile? TryOpenStream(string path, string streamName)
    {
        var target = path + ":" + streamName;
        try
        {
            var opened = inner.TryOpenStream(path, streamName);
            if (opened is not null)
            {
                log.Record("open-stream", target, access, "ok");
            }

            return opened;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log.Record("open-stream", target, access, AuditResults.Of(ex), ex.Message);
            throw;
        }
    }
}

/// <summary>Records every directory listing in the audit log.</summary>
public sealed class AuditingDirectoryLister(IDirectoryLister inner, AuditLogger log) : IDirectoryLister
{
    public IReadOnlyList<FsEntry> List(string directory)
    {
        try
        {
            var entries = inner.List(directory);
            log.Record("list-directory", directory, "list", "ok", $"{entries.Count} entries");
            return entries;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log.Record("list-directory", directory, "list", AuditResults.Of(ex), ex.Message);
            throw;
        }
    }

    public bool DirectoryExists(string path) => inner.DirectoryExists(path);
}

internal static class AuditResults
{
    public static string Of(Exception ex) => ex switch
    {
        UnauthorizedAccessException => "denied",
        FileNotFoundException or DirectoryNotFoundException => "not-found",
        _ => "error",
    };
}

/// <summary>Records every raw volume opened (the volume itself; individual sector reads are not listed).</summary>
public sealed class AuditingVolumeOpener(IVolumeOpener inner, AuditLogger log) : IVolumeOpener
{
    public IRawVolume Open(string drive)
    {
        var target = $@"\\.\{drive}";
        try
        {
            var volume = inner.Open(drive);
            log.Record("open-volume", target, "GENERIC_READ; share read/write; raw sectors", "ok");
            return volume;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            log.Record("open-volume", target, "GENERIC_READ; share read/write; raw sectors", AuditResults.Of(ex), ex.Message);
            throw;
        }
    }
}

/// <summary>Records each change journal query and read in the audit log.</summary>
public sealed class AuditingJournalSource(IUsnJournalSource inner, AuditLogger log) : IUsnJournalSource
{
    private const string Access = "FSCTL_QUERY_USN_JOURNAL / FSCTL_READ_USN_JOURNAL (read only)";

    public UsnJournalInfo Query(string drive)
    {
        var target = $@"\\.\{drive}\$Extend\$UsnJrnl";
        try
        {
            var info = inner.Query(drive);
            log.Record("query-journal", target, Access, "ok", $"id {info.JournalId:X}, USN {info.FirstUsn}..{info.NextUsn}");
            return info;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or System.ComponentModel.Win32Exception)
        {
            log.Record("query-journal", target, Access, AuditResults.Of(ex), ex.Message);
            throw;
        }
    }

    public IEnumerable<ReadOnlyMemory<byte>> Read(string drive, UsnJournalInfo info, CancellationToken cancellationToken)
    {
        log.Record("read-journal", $@"\\.\{drive}\$Extend\$UsnJrnl", Access, "started", $"USN {info.FirstUsn}..{info.NextUsn}");
        return inner.Read(drive, info, cancellationToken);
    }
}
