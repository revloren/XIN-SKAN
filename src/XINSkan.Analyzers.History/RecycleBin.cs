using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using XINSkan.Analyzers.FileHunter.Content;
using XINSkan.Core.IO;
using XINSkan.Core.Paths;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;
using XINSkan.Ntfs;

namespace XINSkan.Analyzers.History;

/// <summary>Contents of a $I file: what was deleted to the Recycle Bin, from where and when.</summary>
public sealed record RecycleInfo(int Version, long Size, long DeletedFileTime, string OriginalPath)
{
    public DateTimeOffset? DeletedUtc => NtfsTime.ToUtc(DeletedFileTime);
}

/// <summary>Parses $I files: version 1 (Vista–8.1, fixed 260-character path) and version 2 (Windows 10/11).</summary>
public static class RecycleInfoParser
{
    public const int MaxBytes = 64 * 1024;

    public static RecycleInfo? Parse(ReadOnlySpan<byte> b, out string? problem)
    {
        problem = null;
        if (b.Length < 24)
        {
            problem = "Файл $I короче заголовка.";
            return null;
        }

        var version = BinaryPrimitives.ReadInt64LittleEndian(b);
        var size = BinaryPrimitives.ReadInt64LittleEndian(b[8..]);
        var deleted = BinaryPrimitives.ReadInt64LittleEndian(b[16..]);
        string path;
        switch (version)
        {
            case 1:
                if (b.Length < 24 + 520)
                {
                    problem = "Файл $I версии 1 короче 544 байт.";
                    return null;
                }

                path = ZeroTerminated(b.Slice(24, 520));
                break;
            case 2:
                if (b.Length < 28)
                {
                    problem = "Файл $I версии 2 без длины пути.";
                    return null;
                }

                var chars = BinaryPrimitives.ReadUInt32LittleEndian(b[24..]);
                if (chars is 0 or > 32_768 || 28 + ((long)chars * 2) > b.Length)
                {
                    problem = $"Длина пути {chars} в $I выходит за файл.";
                    return null;
                }

                path = ZeroTerminated(b.Slice(28, (int)chars * 2));
                break;
            default:
                problem = $"Неизвестная версия $I: {version}.";
                return null;
        }

        if (path.Length == 0)
        {
            problem = "В $I нет исходного пути.";
            return null;
        }

        return new RecycleInfo((int)version, size, deleted, path);
    }

    private static string ZeroTerminated(ReadOnlySpan<byte> utf16)
    {
        var s = Encoding.Unicode.GetString(utf16);
        var nul = s.IndexOf('\0', StringComparison.Ordinal);
        return nul < 0 ? s : s[..nul];
    }
}

/// <summary>
/// Reads $Recycle.Bin on each volume: for every $I file, the original path and deletion time; for the matching
/// $R item (the deleted file itself, still on disk), its content type, hash and mod metadata.
/// Only items that matter for the check are recorded.
/// </summary>
public sealed class RecycleBinAnalyzer(HistoryOptions options, IDirectoryLister lister, IFileSource files) : IAnalyzer
{
    public const string ModuleId = "recycle-bin";
    private const string ParserName = "xinskan-recycle-bin";
    private const string ParserVersion = "1";
    private const int MaxFilesInFolder = 2000;

    private static readonly HashSet<string> RelevantExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jar", ".zip", ".exe", ".dll", ".mrpack", ".class",
    };

    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    public string Id => ModuleId;

    public string DisplayName => "Корзина";

    public AnalyzerRequirements Requirements { get; } = new()
    {
        OptionalCapabilities = [Capability.Administrator, Capability.OtherUserProfiles],
    };

    public async Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var scope = new HistoryScope(options.UsersRoot, options.CurrentProfile, context.Permissions.Has(Capability.OtherUserProfiles), options.TempFolders, options.ExtraRoots);
        foreach (var drive in options.Volumes)
        {
            // "C:" → C:\$Recycle.Bin; a folder (tests, mounted images) → <folder>/$Recycle.Bin.
            var bin = drive.EndsWith(':') ? drive + @"\$Recycle.Bin" : Path.Combine(drive, "$Recycle.Bin");
            long items = 0, recorded = 0, unreadable = 0;
            var limitations = new List<Limitation>();
            if (!lister.DirectoryExists(bin))
            {
                await context.Writer.AddCoverageAsync(Coverage(context, bin, CollectionStatus.Collected, 0,
                    [new Limitation("RECYCLE.NONE", "Корзины на этом томе нет (её не создавали или её папка удалена).")]), cancellationToken).ConfigureAwait(false);
                continue;
            }

            foreach (var sidFolder in List(bin, limitations).Where(e => e.IsDirectory))
            {
                foreach (var entry in List(sidFolder.FullPath, limitations).Where(e => !e.IsDirectory && e.Name.StartsWith("$I", StringComparison.OrdinalIgnoreCase)))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    items++;
                    var info = ReadInfo(entry.FullPath, out var problem);
                    if (info is null)
                    {
                        unreadable++;
                        if (unreadable <= 20)
                        {
                            await context.Writer.AddErrorAsync(new ModuleError($"{entry.FullPath}: {problem}", null, entry.FullPath), cancellationToken).ConfigureAwait(false);
                        }

                        continue;
                    }

                    var rPath = Path.Combine(sidFolder.FullPath, "$R" + entry.Name[2..]);
                    foreach (var e in Items(context, scope, sidFolder.Name, entry.FullPath, rPath, info))
                    {
                        await context.Writer.AddEvidenceAsync(e, cancellationToken).ConfigureAwait(false);
                        recorded++;
                    }
                }
            }

            if (unreadable > 0)
            {
                limitations.Add(new Limitation("RECYCLE.UNREADABLE", $"{unreadable} файлов $I не прочитано."));
            }

            await context.Writer.AddCoverageAsync(Coverage(context, bin, limitations.Count == 0 ? CollectionStatus.Collected : CollectionStatus.Partial, items, limitations), cancellationToken).ConfigureAwait(false);
            context.Progress.Report(new ModuleProgress(Id, ModuleState.Running, $"{bin}: элементов {items.ToString("N0", Ru)}, записано {recorded.ToString("N0", Ru)}."));
        }
    }

    private IReadOnlyList<FsEntry> List(string folder, List<Limitation> limitations)
    {
        try
        {
            return lister.List(folder);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            limitations.Add(new Limitation("RECYCLE.FOLDER", $"{folder}: не прочитана ({ex.Message}). Корзины других пользователей доступны только администратору."));
            return [];
        }
    }

    private RecycleInfo? ReadInfo(string path, out string? problem)
    {
        try
        {
            using var f = files.Open(path);
            var buffer = new byte[RecycleInfoParser.MaxBytes];
            var n = f.Content.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
            return RecycleInfoParser.Parse(buffer.AsSpan(0, n), out problem);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            problem = ex.Message;
            return null;
        }
    }

    private IEnumerable<Evidence> Items(AnalyzerContext context, HistoryScope scope, string sid, string iPath, string rPath, RecycleInfo info)
    {
        var match = scope.Match(info.OriginalPath);
        var relevantName = RelevantExtensions.Contains(Path.GetExtension(info.OriginalPath));

        if (lister.DirectoryExists(rPath))
        {
            // A whole folder was deleted: record it if it matters, and the archives and programs inside it.
            var inside = Walk(rPath).ToList();
            var relevantInside = inside.Where(x => RelevantExtensions.Contains(Path.GetExtension(x.Entry.Name))).ToList();
            if (!match.InScope || (!match.InMinecraftTree && relevantInside.Count == 0))
            {
                yield break;
            }

            yield return Build(context, sid, iPath, rPath, info, info.OriginalPath, isFolder: true, content: null, match,
                $"Папка {LastSegment(info.OriginalPath)} удалена в Корзину ({inside.Count} файлов внутри): {info.OriginalPath}.");
            foreach (var (entry, relative) in relevantInside.Take(MaxFilesInFolder))
            {
                var original = info.OriginalPath.TrimEnd('\\') + "\\" + relative;
                var content = Inspect(entry.FullPath);
                yield return Build(context, sid, iPath, entry.FullPath, info, original, isFolder: false, content, scope.Match(original),
                    $"Файл {entry.Name} в удалённой в Корзину папке: {original}.");
            }

            yield break;
        }

        var item = Inspect(rPath);
        var relevantContent = item?.Type is ContentType.Zip or ContentType.PortableExecutable or ContentType.JavaClass;
        if (!match.InScope || !(relevantName || match.InMinecraftTree || relevantContent))
        {
            yield break;
        }

        yield return Build(context, sid, iPath, rPath, info, info.OriginalPath, isFolder: false, item, match,
            $"Файл {LastSegment(info.OriginalPath)} удалён в Корзину: {info.OriginalPath}" + (item is null ? " (сам файл из Корзины уже удалён)." : "."));
    }

    private IEnumerable<(FsEntry Entry, string Relative)> Walk(string root)
    {
        var stack = new Stack<(string Dir, string Rel)>();
        stack.Push((root, string.Empty));
        var count = 0;
        while (stack.Count > 0 && count < MaxFilesInFolder * 10)
        {
            var (dir, rel) = stack.Pop();
            IReadOnlyList<FsEntry> entries;
            try
            {
                entries = lister.List(dir);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var e in entries)
            {
                var r = rel.Length == 0 ? e.Name : rel + "\\" + e.Name;
                if (e.IsDirectory)
                {
                    if (!e.IsReparsePoint)
                    {
                        stack.Push((e.FullPath, r));
                    }
                }
                else
                {
                    count++;
                    yield return (e, r);
                }
            }
        }
    }

    private sealed record ItemContent(ContentType Type, long Length, Sha256Hash? Hash, ArchiveFacts? Archive, string? Problem);

    /// <summary>The $R item: content type, SHA-256 (up to 256 MB) and, for archives, mod metadata.</summary>
    private ItemContent? Inspect(string path)
    {
        try
        {
            using var f = files.Open(path);
            var s = f.Content;
            var header = new byte[ContentSniffer.HeaderSize];
            var n = s.ReadAtLeast(header, header.Length, throwOnEndOfStream: false);
            var type = ContentSniffer.Detect(header.AsSpan(0, n), s.Length);
            Sha256Hash? hash = null;
            if (s.Length <= 256L * 1024 * 1024)
            {
                s.Position = 0;
                hash = Sha256Hash.FromBytes(SHA256.HashData(s));
            }

            ArchiveFacts? archive = null;
            if (type == ContentType.Zip)
            {
                archive = ArchiveInspector.Inspect(s, options.Archive);
            }

            return new ItemContent(type, s.Length, hash, archive, null);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new ItemContent(ContentType.Unknown, 0, null, null, ex.Message);
        }
    }

    private Evidence Build(
        AnalyzerContext context,
        string sid,
        string iPath,
        string itemPath,
        RecycleInfo info,
        string originalPath,
        bool isFolder,
        ItemContent? content,
        ScopeMatch match,
        string description)
    {
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Recycle.InfoFile"] = iPath,
            ["Recycle.Item"] = itemPath,
            ["Recycle.Version"] = info.Version.ToString(CultureInfo.InvariantCulture),
            ["Recycle.ItemPresent"] = content is null && !isFolder ? "false" : "true",
        };
        if (match.MinecraftRoot is not null)
        {
            attrs["MinecraftRoot"] = match.MinecraftRoot;
        }

        var limitations = new List<Limitation>();
        if (content is not null)
        {
            attrs["Content"] = content.Type.ToString();
            if (content.Archive is { Mods.Count: > 0 } archive && archive.Mods[0] is var mod)
            {
                attrs["Mod.Loader"] = mod.Loader;
                attrs["Mod.Id"] = mod.Id ?? "?";
                attrs["Mod.Name"] = mod.Name ?? "?";
                attrs["Mod.Version"] = mod.Version ?? "?";
            }

            // The same component facts File Hunter records, so a deleted client can be identified as well as a present one.
            if (content.Archive is { } facts)
            {
                if (facts.TopPackages.Count > 0)
                {
                    attrs["Jar.TopPackages"] = string.Join(", ", facts.TopPackages);
                }

                foreach (var key in (string[])["Main-Class", "Premain-Class", "Agent-Class"])
                {
                    if (facts.Manifest?.GetValueOrDefault(key) is { } value)
                    {
                        attrs["Manifest." + key] = value;
                    }
                }

                if (facts.FeatureClasses.Count > 0)
                {
                    attrs["Jar.FeatureClasses"] = string.Join(", ", facts.FeatureClasses);
                }

                if (facts.ServerPlugin is not null)
                {
                    attrs["Jar.ServerPlugin"] = facts.ServerPlugin;
                }
            }

            if (content.Problem is not null)
            {
                limitations.Add(new Limitation("CONTENT.UNREADABLE", $"Файл в Корзине не прочитан: {content.Problem}"));
            }
        }

        if (content is null && !isFolder)
        {
            limitations.Add(new Limitation("RECYCLE.ITEM_GONE", "Сам файл ($R) из Корзины уже удалён: известны только имя, место и время."));
        }

        return new Evidence
        {
            EvidenceId = context.NewEvidenceId(),
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = new SourceRef(EvidenceSourceKind.RecycleBin, iPath, ParserName, ParserVersion),
            Locator = iPath,
            EventType = EvidenceEventType.Deleted,
            Timestamp = info.DeletedUtc is { } t ? new EvidenceTimestamp(t, "$I.DeletionTime", TimestampPrecision.HundredNanoseconds) : null,
            Target = new ObjectRef
            {
                RecordedPath = originalPath,
                NormalizedPath = PathNormalizer.Normalize(originalPath),
                FileName = LastSegment(originalPath),
                Size = isFolder ? null : content?.Length ?? info.Size,
            },
            ObjectSha256 = content?.Hash,
            Confidence = Confidence.Informational,
            Rationale = "Запись Корзины Windows: что удалено, откуда и когда (время пишет Проводник при удалении). Удаление в Корзину — обычное действие и само по себе ничего не доказывает.",
            CollectionStatus = limitations.Count == 0 ? CollectionStatus.Collected : CollectionStatus.Partial,
            Description = description,
            Limitations = limitations,
            UserSid = sid,
            Attributes = attrs,
            CollectedAtUtc = context.Time.GetUtcNow(),
        };
    }

    /// <summary>File name of a Windows path regardless of the platform the analysis runs on.</summary>
    private static string LastSegment(string path)
    {
        var trimmed = path.TrimEnd('\\', '/');
        var i = trimmed.LastIndexOfAny(['\\', '/']);
        return i < 0 ? trimmed : trimmed[(i + 1)..];
    }

    private SourceCoverage Coverage(AnalyzerContext context, string scope, CollectionStatus status, long items, List<Limitation> limitations) => new()
    {
        InvestigationId = context.InvestigationId,
        ModuleId = Id,
        Source = EvidenceSourceKind.RecycleBin,
        Scope = scope,
        Status = status,
        ItemsRead = items,
        Limitations = limitations,
    };
}
