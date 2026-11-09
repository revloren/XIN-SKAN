using XINSkan.Analyzers.History;
using XINSkan.Core.IO;
using XINSkan.Ntfs;

namespace XINSkan.Analyzers.Execution;

/// <summary>A file read either normally or, when Windows holds it open exclusively, from the volume.</summary>
/// <param name="Method">"file" (opened read-only with full sharing) or "volume" (read through its MFT record).</param>
public sealed record ProtectedFile(string Path, byte[] Data, string Method, IReadOnlyList<string> Problems);

/// <summary>Reads files that may be locked by Windows (registry hives, their logs, the SRUM database).</summary>
public interface IProtectedFileSource
{
    /// <summary>The file, or null when it does not exist. A file that exists but cannot be read has problems and no data.</summary>
    ProtectedFile? Read(string path, long maxBytes);
}

/// <summary>
/// First opens the file read-only with full sharing; if Windows holds it exclusively (a loaded registry hive),
/// reads it from the volume through the MFT record found by the MFT module. Nothing is copied, no service
/// (Volume Shadow Copy, backup API) is asked to help, and the volume is opened for reading only.
/// </summary>
public sealed class ProtectedFileSource(IFileSource files, IVolumeOpener volumes, VolumeHistoryCache cache) : IProtectedFileSource
{
    public ProtectedFile? Read(string path, long maxBytes)
    {
        ArgumentNullException.ThrowIfNull(path);
        string failure;
        try
        {
            using var f = files.Open(path);
            if (f.Content.Length > maxBytes)
            {
                return new ProtectedFile(path, [], "file", [$"Файл {f.Content.Length} байт больше предела {maxBytes}."]);
            }

            var data = new byte[f.Content.Length];
            var n = f.Content.ReadAtLeast(data, data.Length, throwOnEndOfStream: false);
            return new ProtectedFile(path, n == data.Length ? data : data[..n], "file", []);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return cache.Located(path) is null ? null : FromVolume(path, maxBytes, "файл не открылся обычным способом");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            failure = ex.Message;
        }

        return FromVolume(path, maxBytes, failure);
    }

    private ProtectedFile FromVolume(string path, long maxBytes, string failure)
    {
        if (cache.Located(path) is not { } reference)
        {
            return new ProtectedFile(path, [], "none", [$"Файл занят системой ({failure}), а его запись MFT неизвестна: модуль MFT не выполнялся или не нашёл его."]);
        }

        IRawVolume? volume = null;
        try
        {
            volume = volumes.Open(path[..2]);
            var reader = MftReader.Open(volume);
            var content = NtfsFile.Read(reader, reference, maxBytes);
            return content is null
                ? new ProtectedFile(path, [], "volume", ["Запись MFT файла уже принадлежит другому объекту (файл заменён после чтения MFT)."])
                : new ProtectedFile(path, content.Data, "volume", content.Problems);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or System.ComponentModel.Win32Exception)
        {
            return new ProtectedFile(path, [], "volume", [$"Файл не прочитан с тома: {ex.Message}"]);
        }
        finally
        {
            (volume as IDisposable)?.Dispose();
        }
    }
}
