using XINSkan.Core.IO;
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
