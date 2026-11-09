using System.Globalization;
using XINSkan.Analyzers.FileHunter.Scanning;
using XINSkan.Core.IO;
using XINSkan.Core.Paths;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;
using XINSkan.Ntfs;
using XINSkan.ShellFormats;

namespace XINSkan.Analyzers.History;

/// <summary>Which targets of links, Jump Lists and ShellBags are worth recording.</summary>
internal static class ShellTargets
{
    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jar", ".zip", ".exe", ".dll", ".mrpack", ".class", ".rar", ".7z",
    };

    /// <summary>Folder names of Minecraft and its launchers (not cheat names: those belong to the verified database).</summary>
    private static readonly string[] MinecraftNames =
    [
        ".minecraft", "minecraft", "tlauncher", ".tlauncher", "lunarclient", ".lunarclient", "badlion client", ".badlion",
        "prismlauncher", "multimc", "atlauncher", "curseforge", "feather", ".feather", "modrinth", "modrinthapp", "polymc", "gdlauncher",
    ];

    public static bool IsRelevant(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var segments = path.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            return false;
        }

        if (segments.Any(s => MinecraftNames.Contains(s, StringComparer.OrdinalIgnoreCase)))
        {
            return true;
        }

        // A file with a telling extension, or a folder inside an archive opened in Explorer.
        return Extensions.Contains(Path.GetExtension(segments[^1])) || segments[..^1].Any(s => s.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) || s.EndsWith(".jar", StringComparison.OrdinalIgnoreCase));
    }

    public static string FileName(string path)
    {
        var t = path.TrimEnd('\\', '/');
        var i = t.LastIndexOfAny(['\\', '/']);
        return i < 0 ? t : t[(i + 1)..];
    }

    public static string? DriveTypeName(uint? type) => type switch
    {
        2 => "съёмный",
        3 => "встроенный",
        4 => "сетевой",
        5 => "CD/DVD",
        6 => "RAM-диск",
        null => null,
        _ => $"тип {type}",
    };
}

/// <summary>Per-user folders of the profiles that may be read.</summary>
internal static class Profiles
{
    public static IEnumerable<string> Readable(HistoryOptions options, IDirectoryLister lister, PermissionSnapshot permissions)
    {
        yield return options.CurrentProfile;
        if (!permissions.Has(Capability.OtherUserProfiles))
        {
            yield break;
        }

        IReadOnlyList<FsEntry> all;
        try
        {
            all = lister.List(options.UsersRoot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        foreach (var p in all.Where(p => p.IsDirectory && !p.IsReparsePoint && !ScopeBuilder.IsSystemProfile(p.Name)))
        {
            if (!string.Equals(PathNormalizer.Normalize(p.FullPath), PathNormalizer.Normalize(options.CurrentProfile), StringComparison.Ordinal))
            {
                yield return p.FullPath;
            }
        }
    }

    public static string Recent(string profile) => Path.Combine(profile, "AppData", "Roaming", "Microsoft", "Windows", "Recent");
}

/// <summary>
/// Shell links in Recent (made by Windows when a file is opened) and on the Desktop: which file or folder was
/// opened, from which drive (including USB drives), with the target's times and size at that moment.
/// </summary>
public sealed class LnkAnalyzer(HistoryOptions options, IDirectoryLister lister, IFileSource files) : IAnalyzer
{
    public const string ModuleId = "lnk";
    private const string ParserName = "xinskan-lnk";
    private const string ParserVersion = "1";

    public string Id => ModuleId;

    public string DisplayName => "Ярлыки (LNK)";

    public AnalyzerRequirements Requirements { get; } = new() { OptionalCapabilities = [Capability.OtherUserProfiles] };

    public async Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        long read = 0, recorded = 0, damaged = 0;
        var folders = new List<string>();
        foreach (var profile in Profiles.Readable(options, lister, context.Permissions))
        {
            foreach (var folder in new[] { Profiles.Recent(profile), Path.Combine(profile, "Desktop") })
            {
                if (!lister.DirectoryExists(folder))
                {
                    continue;
                }

                folders.Add(folder);
                IReadOnlyList<FsEntry> entries;
                try
                {
                    entries = lister.List(folder);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    await context.Writer.AddErrorAsync(new ModuleError($"{folder}: {ex.Message}", ex.GetType().Name, folder), cancellationToken).ConfigureAwait(false);
                    continue;
                }

                foreach (var e in entries.Where(e => !e.IsDirectory && e.Name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    read++;
                    var bytes = ShellIo.Read(files, e.FullPath, LnkFile.MaxBytes);
                    var lnk = bytes is null ? null : LnkFile.Parse(bytes);
                    if (lnk is null)
                    {
                        damaged++;
                        continue;
                    }

                    if (!ShellTargets.IsRelevant(lnk.TargetPath))
                    {
                        continue;
                    }

                    await context.Writer.AddEvidenceAsync(ShellEvidence.FromLink(context, Id, EvidenceSourceKind.Lnk, e.FullPath, e.FullPath, ParserName, ParserVersion, lnk,
                        e.LastWriteTimeUtc, e.CreationTimeUtc, interactionCount: null,
                        $"Открывался {(lnk.TargetItem?.Kind == ShellItemKind.Folder ? "объект" : "файл")} {lnk.TargetPath} (ярлык {e.Name})."), cancellationToken).ConfigureAwait(false);
                    recorded++;
                }
            }
        }

        await context.Writer.AddCoverageAsync(new SourceCoverage
        {
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = EvidenceSourceKind.Lnk,
            Scope = folders.Count == 0 ? "Папки Recent и Desktop не найдены" : string.Join("; ", folders),
            Status = damaged > 0 ? CollectionStatus.Partial : CollectionStatus.Collected,
            ItemsRead = read,
            Limitations =
            [
                new("LNK.CLEANABLE", "Windows хранит ограниченное число недавних ярлыков, а пользователь может очистить «Недавние»: отсутствие ярлыка ничего не доказывает."),
                .. damaged > 0 ? new[] { new Limitation("LNK.DAMAGED", $"{damaged} файлов .lnk не прочитано или повреждено.") } : [],
            ],
        }, cancellationToken).ConfigureAwait(false);
        context.Progress.Report(new ModuleProgress(Id, ModuleState.Running, $"Ярлыков прочитано {read}, записано {recorded}."));
    }
}

/// <summary>
/// Jump Lists: for each application, the files and folders it opened (DestList: when last, how often, pinned),
/// with the shell link of each.
/// </summary>
public sealed class JumpListAnalyzer(HistoryOptions options, IDirectoryLister lister, IFileSource files) : IAnalyzer
{
    public const string ModuleId = "jumplists";
    private const string ParserName = "xinskan-jumplist";
    private const string ParserVersion = "1";

    /// <summary>A few well-known application IDs (the rest are recorded by their hex ID).</summary>
    private static readonly Dictionary<string, string> AppIds = new(StringComparer.OrdinalIgnoreCase)
    {
        ["f01b4d95cf55d32a"] = "Проводник Windows",
        ["5f7b5f1e01b83767"] = "Проводник Windows",
        ["1b4dd67f29cb1962"] = "Проводник Windows",
        ["9b9cdc69c1c24e2b"] = "Блокнот",
        ["290532160612e071"] = "WinRAR",
        ["23646679aaccfae0"] = "Adobe Reader",
        ["b8c29862d9f95832"] = "7-Zip",
        ["fb3b0dbfee58fac8"] = "Microsoft Word",
        ["9d1f905ce5044aee"] = "Microsoft Edge",
    };

    public string Id => ModuleId;

    public string DisplayName => "Jump Lists";

    public AnalyzerRequirements Requirements { get; } = new() { OptionalCapabilities = [Capability.OtherUserProfiles] };

    public async Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        long read = 0, recorded = 0, damaged = 0;
        var folders = new List<string>();
        foreach (var profile in Profiles.Readable(options, lister, context.Permissions))
        {
            var auto = Path.Combine(Profiles.Recent(profile), "AutomaticDestinations");
            var custom = Path.Combine(Profiles.Recent(profile), "CustomDestinations");
            foreach (var (folder, suffix) in new[] { (auto, ".automaticDestinations-ms"), (custom, ".customDestinations-ms") })
            {
                if (!lister.DirectoryExists(folder))
                {
                    continue;
                }

                folders.Add(folder);
                IReadOnlyList<FsEntry> entries;
                try
                {
                    entries = lister.List(folder);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    await context.Writer.AddErrorAsync(new ModuleError($"{folder}: {ex.Message}", ex.GetType().Name, folder), cancellationToken).ConfigureAwait(false);
                    continue;
                }

                foreach (var e in entries.Where(e => !e.IsDirectory && e.Name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    read++;
                    var appId = e.Name[..e.Name.IndexOf('.', StringComparison.Ordinal)];
                    var app = AppIds.GetValueOrDefault(appId, appId);
                    var bytes = ShellIo.Read(files, e.FullPath, CompoundFile.MaxBytes);
                    if (bytes is null)
                    {
                        damaged++;
                        continue;
                    }

                    if (suffix == ".automaticDestinations-ms")
                    {
                        var jl = AutomaticDestinations.Parse(bytes, out _);
                        if (jl is null)
                        {
                            damaged++;
                            continue;
                        }

                        foreach (var d in jl.Entries.Where(d => ShellTargets.IsRelevant(d.Lnk?.TargetPath ?? d.Path)))
                        {
                            var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
                            {
                                ["JumpList.AppId"] = appId,
                                ["JumpList.App"] = app,
                                ["JumpList.Entry"] = d.EntryNumber.ToString(CultureInfo.InvariantCulture),
                                ["JumpList.Pinned"] = d.Pinned ? "true" : "false",
                                ["JumpList.Host"] = d.Hostname,
                            };
                            var lastUsed = NtfsTime.ToUtc(d.LastModified);
                            await context.Writer.AddEvidenceAsync(ShellEvidence.FromDestList(context, Id, e.FullPath, ParserName, ParserVersion, d, lastUsed, attrs,
                                $"{app} открывал {d.Lnk?.TargetPath ?? d.Path}" + (d.InteractionCount is { } n ? $" (раз: {n})" : string.Empty) + "."), cancellationToken).ConfigureAwait(false);
                            recorded++;
                        }
                    }
                    else
                    {
                        foreach (var l in CustomDestinations.Parse(bytes).Where(l => ShellTargets.IsRelevant(l.TargetPath)))
                        {
                            await context.Writer.AddEvidenceAsync(ShellEvidence.FromLink(context, Id, EvidenceSourceKind.JumpList, e.FullPath, e.FullPath, ParserName, ParserVersion, l,
                                e.LastWriteTimeUtc, null, null,
                                $"{app}: в списке переходов закреплён {l.TargetPath}.", new Dictionary<string, string> { ["JumpList.AppId"] = appId, ["JumpList.App"] = app }), cancellationToken).ConfigureAwait(false);
                            recorded++;
                        }
                    }
                }
            }
        }

        await context.Writer.AddCoverageAsync(new SourceCoverage
        {
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = EvidenceSourceKind.JumpList,
            Scope = folders.Count == 0 ? "Папки Jump Lists не найдены" : string.Join("; ", folders),
            Status = damaged > 0 ? CollectionStatus.Partial : CollectionStatus.Collected,
            ItemsRead = read,
            Limitations =
            [
                new("JUMPLIST.CLEANABLE", "Списки переходов очищаются пользователем и самой системой; отсутствие записи ничего не доказывает."),
                .. damaged > 0 ? new[] { new Limitation("JUMPLIST.DAMAGED", $"{damaged} файлов Jump List не прочитано или повреждено.") } : [],
            ],
        }, cancellationToken).ConfigureAwait(false);
        context.Progress.Report(new ModuleProgress(Id, ModuleState.Running, $"Списков переходов прочитано {read}, записей {recorded}."));
    }
}

/// <summary>Read access to the current user's registry, as far as ShellBags need it.</summary>
public interface IShellBagSource
{
    /// <summary>Binary values of a key (name → bytes), or null if the key does not exist.</summary>
    IReadOnlyList<(string Name, byte[] Data)>? Values(string key);

    IReadOnlyList<string>? SubKeys(string key);

    /// <summary>Last write time of the key (FILETIME), or null.</summary>
    long? LastWriteTime(string key);
}

/// <summary>ShellBags of another user, read from that user's NTUSER.DAT and UsrClass.dat files.</summary>
/// <param name="Prefix">How keys of this source are shown (for example "NTUSER(anna)").</param>
public sealed record UserShellBags(string User, string? Sid, IShellBagSource Source, string Prefix, IReadOnlyList<string> Problems);

/// <summary>Loads the registry files of users other than the one running XIN SKAN.</summary>
public interface IOtherUserShellBags
{
    /// <param name="otherUsersAllowed">Whether other profiles may be read (Capability.OtherUserProfiles).</param>
    IReadOnlyList<UserShellBags> Load(bool otherUsersAllowed);
}

/// <summary>
/// ShellBags: folders Explorer has shown (including deleted folders, USB drives and folders inside archives),
/// rebuilt from the BagMRU tree — of the current user from the live registry, of other users from their hive files.
/// </summary>
public sealed class ShellBagsAnalyzer(IShellBagSource registry, IOtherUserShellBags? otherUsers = null) : IAnalyzer
{
    public const string ModuleId = "shellbags";
    private const string ParserName = "xinskan-shellbags";
    private const string ParserVersion = "1";
    private const int MaxNodes = 100_000;

    public static readonly string[] Roots =
    [
        @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
        @"Software\Microsoft\Windows\Shell\BagMRU",
    ];

    public string Id => ModuleId;

    public string DisplayName => "ShellBags";

    public AnalyzerRequirements Requirements { get; } = AnalyzerRequirements.None;

    public async Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var sources = new List<UserShellBags> { new(string.Empty, null, registry, "HKCU", []) };
        var limitations = new List<Limitation>
        {
            new("SHELLBAGS.TIME", "Время — время последней записи ключа реестра: когда Проводник последний раз сохранял вид этой папки или её подпапок, а не обязательно когда её открывали."),
        };
        if (otherUsers is null)
        {
            limitations.Add(new Limitation("SHELLBAGS.CURRENT_USER", "Прочитаны ShellBags только текущего пользователя."));
        }
        else
        {
            var allowed = context.Permissions.Has(Capability.OtherUserProfiles);
            sources.AddRange(otherUsers.Load(allowed));
            if (!allowed)
            {
                limitations.Add(new Limitation("SHELLBAGS.OTHER_USERS", "ShellBags других пользователей не прочитаны: нет разрешения на чужие профили."));
            }
        }

        foreach (var problem in sources.SelectMany(u => u.Problems.Select(p => $"{u.User}: {p}")))
        {
            limitations.Add(new Limitation("SHELLBAGS.USER_HIVE", problem));
        }

        long nodes = 0, recorded = 0;
        var found = new List<string>();
        foreach (var source in sources)
        {
            foreach (var root in Roots)
            {
                if (source.Source.SubKeys(root) is null)
                {
                    continue;
                }

                found.Add(source.Prefix + "\\" + root);
                var stack = new Stack<(string Key, List<ShellItem> Items)>();
                stack.Push((root, []));
                while (stack.Count > 0 && nodes < MaxNodes)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var (key, items) = stack.Pop();
                    var values = source.Source.Values(key) ?? [];
                    foreach (var (name, data) in values.Where(v => int.TryParse(v.Name, NumberStyles.None, CultureInfo.InvariantCulture, out _)))
                    {
                        nodes++;
                        var item = ShellItemParser.Parse(data);
                        var path = new List<ShellItem>(items) { item };
                        var text = ShellItemParser.ToPath(path);
                        var child = key + "\\" + name;
                        if (ShellTargets.IsRelevant(text))
                        {
                            await context.Writer.AddEvidenceAsync(Build(context, source, child, text, item, source.Source.LastWriteTime(child)), cancellationToken).ConfigureAwait(false);
                            recorded++;
                        }

                        stack.Push((child, path));
                    }
                }
            }
        }

        if (nodes >= MaxNodes)
        {
            limitations.Add(new Limitation("SHELLBAGS.LIMIT", $"Прочитано {MaxNodes:N0} узлов, остальные пропущены."));
        }

        await context.Writer.AddCoverageAsync(new SourceCoverage
        {
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = EvidenceSourceKind.ShellBags,
            Scope = found.Count == 0 ? "Ключи ShellBags не найдены" : string.Join("; ", found),
            Status = nodes >= MaxNodes || sources.Any(u => u.Problems.Count > 0) ? CollectionStatus.Partial : CollectionStatus.Collected,
            ItemsRead = nodes,
            Limitations = limitations,
        }, cancellationToken).ConfigureAwait(false);
        context.Progress.Report(new ModuleProgress(Id, ModuleState.Running, $"Узлов ShellBags {nodes}, записано {recorded}, пользователей {sources.Count}."));
    }

    private Evidence Build(AnalyzerContext context, UserShellBags source, string key, string path, ShellItem item, long? lastWrite)
    {
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal) { ["ShellBags.Key"] = source.Prefix + "\\" + key };
        if (source.User.Length > 0)
        {
            attrs["ShellBags.User"] = source.User;
        }
        if (item.MftEntry is { } entry)
        {
            attrs["Shell.MftEntry"] = entry.ToString(CultureInfo.InvariantCulture);
        }

        var others = new List<EvidenceTimestamp>();
        if (item.Modified is { } m)
        {
            others.Add(new EvidenceTimestamp(m, "ShellItem.Modified", TimestampPrecision.TwoSeconds));
        }

        if (item.Created is { } c)
        {
            others.Add(new EvidenceTimestamp(c, "ShellItem.Created", TimestampPrecision.TwoSeconds));
        }

        if (item.Accessed is { } a)
        {
            others.Add(new EvidenceTimestamp(a, "ShellItem.Accessed", TimestampPrecision.TwoSeconds));
        }

        var written = lastWrite is { } lw ? NtfsTime.ToUtc(lw) : null;
        return new Evidence
        {
            EvidenceId = context.NewEvidenceId(),
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = new SourceRef(EvidenceSourceKind.ShellBags, source.Prefix + "\\" + Roots[0], ParserName, ParserVersion),
            Locator = source.Prefix + "\\" + key,
            UserSid = source.Sid,
            EventType = EvidenceEventType.Accessed,
            Timestamp = written is null ? null : new EvidenceTimestamp(written.Value, "Registry.KeyLastWrite", TimestampPrecision.HundredNanoseconds),
            OtherTimestamps = others,
            Target = new ObjectRef
            {
                RecordedPath = path,
                NormalizedPath = path.Length > 2 && path[1] == ':' ? PathNormalizer.Normalize(path) : null,
                FileName = item.Name,
                MftEntry = item.MftEntry,
                MftSequence = item.MftSequence,
            },
            Confidence = Confidence.Informational,
            Rationale = "ShellBags: Проводник запоминает вид каждой открытой папки, и запись остаётся после удаления папки или отключения диска. Это след того, что папку показывали в Проводнике.",
            CollectionStatus = item.Problem is null ? CollectionStatus.Collected : CollectionStatus.Partial,
            Description = $"Папка открывалась в Проводнике{(source.User.Length > 0 ? $" (пользователь {source.User})" : string.Empty)}: {path}.",
            Limitations = item.Problem is null ? [] : [new Limitation("SHELL.ITEM", item.Problem)],
            Attributes = attrs,
            CollectedAtUtc = context.Time.GetUtcNow(),
        };
    }
}

internal static class ShellIo
{
    public static byte[]? Read(IFileSource files, string path, int max)
    {
        try
        {
            using var f = files.Open(path);
            if (f.Content.Length > max)
            {
                return null;
            }

            var buffer = new byte[f.Content.Length];
            var n = f.Content.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
            return n == buffer.Length ? buffer : buffer[..n];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}

internal static class ShellEvidence
{
    public static Evidence FromLink(
        AnalyzerContext context,
        string module,
        EvidenceSourceKind kind,
        string artifact,
        string locator,
        string parser,
        string version,
        LnkFile lnk,
        DateTime linkWritten,
        DateTime? linkCreated,
        int? interactionCount,
        string description,
        Dictionary<string, string>? extra = null)
    {
        var attrs = extra ?? new Dictionary<string, string>(StringComparer.Ordinal);
        AddLinkAttributes(attrs, lnk);
        var others = TargetTimes(lnk);
        if (linkCreated is { Year: >= 1980 } created)
        {
            others.Add(new EvidenceTimestamp(new DateTimeOffset(DateTime.SpecifyKind(created, DateTimeKind.Utc)), "Lnk.FileCreated", TimestampPrecision.HundredNanoseconds));
        }

        var path = lnk.TargetPath!;
        return new Evidence
        {
            EvidenceId = context.NewEvidenceId(),
            InvestigationId = context.InvestigationId,
            ModuleId = module,
            Source = new SourceRef(kind, artifact, parser, version),
            Locator = locator,
            EventType = EvidenceEventType.Accessed,
            Timestamp = linkWritten.Year >= 1980
                ? new EvidenceTimestamp(new DateTimeOffset(DateTime.SpecifyKind(linkWritten, DateTimeKind.Utc)), "Lnk.FileModified", TimestampPrecision.HundredNanoseconds)
                : null,
            OtherTimestamps = others,
            Target = Target(lnk, path),
            Confidence = Confidence.Informational,
            Rationale = "Ярлык в «Недавних» Windows создаёт сама, когда файл открывают через Проводник или диалог; время изменения ярлыка — последнее такое открытие. Ярлык показывает, что файл открывали, а не что его запускали.",
            CollectionStatus = lnk.Problems.Count == 0 ? CollectionStatus.Collected : CollectionStatus.Partial,
            Description = description,
            Limitations = lnk.Problems.Take(3).Select(p => new Limitation("LNK.PARSE", p)).ToList(),
            Attributes = attrs,
            CollectedAtUtc = context.Time.GetUtcNow(),
        };
    }

    public static Evidence FromDestList(
        AnalyzerContext context,
        string module,
        string artifact,
        string parser,
        string version,
        DestListEntry d,
        DateTimeOffset? lastUsed,
        Dictionary<string, string> attrs,
        string description)
    {
        if (d.InteractionCount is { } n)
        {
            attrs["JumpList.InteractionCount"] = n.ToString(CultureInfo.InvariantCulture);
        }

        List<EvidenceTimestamp> others = [];
        var path = d.Lnk?.TargetPath ?? d.Path;
        if (d.Lnk is { } lnk)
        {
            AddLinkAttributes(attrs, lnk);
            others = TargetTimes(lnk);
        }

        return new Evidence
        {
            EvidenceId = context.NewEvidenceId(),
            InvestigationId = context.InvestigationId,
            ModuleId = module,
            Source = new SourceRef(EvidenceSourceKind.JumpList, artifact, parser, version),
            Locator = $"{artifact} DestList #{d.EntryNumber}",
            EventType = EvidenceEventType.Accessed,
            Timestamp = lastUsed is null ? null : new EvidenceTimestamp(lastUsed.Value, "DestList.LastModified", TimestampPrecision.HundredNanoseconds),
            OtherTimestamps = others,
            Target = d.Lnk is { } l2 ? Target(l2, path) : new ObjectRef { RecordedPath = path, NormalizedPath = PathNormalizer.Normalize(path), FileName = ShellTargets.FileName(path) },
            Confidence = Confidence.Informational,
            Rationale = "Список переходов приложения: Windows записывает, какие файлы и папки приложение открывало, когда в последний раз и сколько раз. Это след открытия, не запуска.",
            CollectionStatus = d.Lnk is null || d.Lnk.Problems.Count > 0 ? CollectionStatus.Partial : CollectionStatus.Collected,
            Description = description,
            Limitations = d.Lnk is null
                ? [new Limitation("JUMPLIST.NO_LNK", "У записи нет ярлыка в файле списка: известны только путь и время.")]
                : d.Lnk.Problems.Take(3).Select(p => new Limitation("LNK.PARSE", p)).ToList(),
            Attributes = attrs,
            CollectedAtUtc = context.Time.GetUtcNow(),
        };
    }

    private static ObjectRef Target(LnkFile lnk, string path) => new()
    {
        RecordedPath = path,
        NormalizedPath = path.Length > 2 && path[1] == ':' ? PathNormalizer.Normalize(path) : null,
        FileName = ShellTargets.FileName(path),
        VolumeSerial = lnk.DriveSerial,
        MftEntry = lnk.TargetItem?.MftEntry,
        MftSequence = lnk.TargetItem?.MftSequence,
        Size = lnk.TargetSize == 0 ? null : lnk.TargetSize,
    };

    private static void AddLinkAttributes(Dictionary<string, string> attrs, LnkFile lnk)
    {
        void Put(string k, string? v)
        {
            if (!string.IsNullOrWhiteSpace(v))
            {
                attrs[k] = v;
            }
        }

        Put("Lnk.DriveType", ShellTargets.DriveTypeName(lnk.DriveType));
        Put("Lnk.DriveSerial", lnk.DriveSerial?.ToString("X8", CultureInfo.InvariantCulture));
        Put("Lnk.VolumeLabel", lnk.VolumeLabel);
        Put("Lnk.Arguments", lnk.Arguments);
        Put("Lnk.WorkingDirectory", lnk.WorkingDirectory);
        Put("Lnk.Machine", lnk.Tracker?.MachineId);
        Put("Lnk.MacAddress", lnk.Tracker?.MacAddress);
    }

    private static List<EvidenceTimestamp> TargetTimes(LnkFile lnk)
    {
        var list = new List<EvidenceTimestamp>();
        void Add(long ft, string field)
        {
            if (NtfsTime.ToUtc(ft) is { } t)
            {
                list.Add(new EvidenceTimestamp(t, field, TimestampPrecision.HundredNanoseconds));
            }
        }

        Add(lnk.TargetCreated, "Lnk.TargetCreated");
        Add(lnk.TargetModified, "Lnk.TargetModified");
        Add(lnk.TargetAccessed, "Lnk.TargetAccessed");
        return list;
    }
}
