using System.Globalization;
using XINSkan.Core.Paths;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;
using XINSkan.Ntfs;

namespace XINSkan.Analyzers.History;

/// <summary>Reads a volume's change journal.</summary>
public interface IUsnJournalSource
{
    UsnJournalInfo Query(string drive);

    /// <summary>Blocks of whole records, oldest first, from the first valid USN up to <see cref="UsnJournalInfo.NextUsn"/>.</summary>
    IEnumerable<ReadOnlyMemory<byte>> Read(string drive, UsnJournalInfo info, CancellationToken cancellationToken);
}

/// <summary>
/// Reads the NTFS change journal and rebuilds, per file, what happened to it: created, renamed or moved,
/// content changed, times or attributes changed, deleted — with the exact time NTFS wrote each record.
/// Only files that matter for the check are recorded (by any of their names and places over time).
/// </summary>
/// <remarks>
/// The journal is a ring: it keeps the most recent changes only (typically days to weeks). Every coverage
/// record states the window, because the absence of an event before it proves nothing.
/// </remarks>
public sealed class UsnAnalyzer(HistoryOptions options, IUsnJournalSource journal, VolumeHistoryCache cache) : IAnalyzer
{
    public const string ModuleId = "usn";
    private const string ParserName = "xinskan-ntfs-usn";
    private const string ParserVersion = "1";
    private const int MaxRetained = 5_000_000;

    private const UsnReason DataChange = UsnReason.DataOverwrite | UsnReason.DataExtend | UsnReason.DataTruncation;
    private const UsnReason StreamChanges = UsnReason.StreamChange | UsnReason.NamedDataOverwrite | UsnReason.NamedDataExtend | UsnReason.NamedDataTruncation;

    private static readonly HashSet<string> RelevantExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jar", ".zip", ".exe", ".dll", ".mrpack", ".class",
    };

    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    public string Id => ModuleId;

    public string DisplayName => "USN Journal";

    public AnalyzerRequirements Requirements { get; } = new()
    {
        RequiredCapabilities = [Capability.UsnJournalRead],
        OptionalCapabilities = [Capability.OtherUserProfiles],
    };

    public async Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        foreach (var drive in options.Volumes)
        {
            await RunVolumeAsync(context, drive, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task RunVolumeAsync(AnalyzerContext context, string drive, CancellationToken ct)
    {
        var artifact = $@"\\.\{drive}\$Extend\$UsnJrnl:$J";
        UsnJournalInfo info;
        try
        {
            info = journal.Query(drive);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or System.ComponentModel.Win32Exception)
        {
            await context.Writer.AddErrorAsync(new ModuleError($"{drive}: журнал изменений не открыт: {ex.Message}", ex.GetType().Name, artifact), ct).ConfigureAwait(false);
            await context.Writer.AddCoverageAsync(Coverage(context, artifact, CollectionStatus.Failed, 0,
                [new Limitation("USN.UNAVAILABLE", $"Журнал изменений тома {drive} не прочитан: {ex.Message}")]), ct).ConfigureAwait(false);
            return;
        }

        // One pass: folders go to a name map, files are kept compactly for the lifecycle step.
        var stats = new UsnParseStatistics();
        var folders = new Dictionary<FileReference, (string Name, FileReference Parent)>();
        var files = new List<UsnRecord>();
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        long total = 0, dropped = 0;
        DateTimeOffset? first = null, last = null;
        string? readFailure = null;
        foreach (var block in ReadSafely(journal.Read(drive, info, ct), e => readFailure = e))
        {
            foreach (var r in UsnParser.Parse(block, stats))
            {
                total++;
                if (r.TimeUtc is { } t)
                {
                    first ??= t;
                    last = t;
                }

                if (r.IsDirectory)
                {
                    if ((r.Reason & UsnReason.RenameOldName) == 0)
                    {
                        folders[r.File] = (r.Name, r.Parent);
                    }
                    else
                    {
                        folders.TryAdd(r.File, (r.Name, r.Parent));
                    }

                    continue;
                }

                if (files.Count >= MaxRetained)
                {
                    dropped++;
                    continue;
                }

                var name = names.TryGetValue(r.Name, out var pooled) ? pooled : names[r.Name] = r.Name;
                files.Add(name == r.Name && ReferenceEquals(name, r.Name) ? r : r with { Name = name });
            }

            if (total % 500_000 < 2_000)
            {
                context.Progress.Report(new ModuleProgress(Id, ModuleState.Running, $"{drive}: записей журнала {total.ToString("N0", Ru)}"));
            }
        }

        var resolver = new UsnPathResolver(drive, cache.Get(drive), folders);
        var scope = new HistoryScope(options.UsersRoot, options.CurrentProfile, context.Permissions.Has(Capability.OtherUserProfiles), options.TempFolders, options.ExtraRoots);
        long recordedFiles = 0, events = 0;
        foreach (var group in files.GroupBy(r => r.File))
        {
            ct.ThrowIfCancellationRequested();
            var history = group.OrderBy(r => r.Usn).ToList();
            var places = history.Select(r => (Record: r, Path: resolver.Resolve(r.Parent, r.Name))).ToList();
            var matches = places.Select(p => (p.Record, p.Path, Match: scope.Match(p.Path.Path))).ToList();
            var relevant = matches.Any(m => m.Match.InScope && (RelevantExtensions.Contains(Path.GetExtension(m.Record.Name)) || m.Match.InMinecraftTree));
            if (!relevant)
            {
                continue;
            }

            recordedFiles++;
            foreach (var e in Lifecycle(context, drive, artifact, matches))
            {
                await context.Writer.AddEvidenceAsync(e, ct).ConfigureAwait(false);
                events++;
            }
        }

        var limitations = new List<Limitation>
        {
            new("USN.WINDOW", first is null
                ? "Журнал пуст: событий нет."
                : $"Журнал хранит только последние изменения: с {first.Value.ToString("u", Ru)} по {last!.Value.ToString("u", Ru)} (UTC). Отсутствие события раньше этого окна ничего не доказывает."),
        };
        if (stats.UnsupportedVersion > 0)
        {
            limitations.Add(new Limitation("USN.VERSION", $"{stats.UnsupportedVersion} записей версии 4 (отслеживание диапазонов) пропущено."));
        }

        if (stats.Resynchronised > 0)
        {
            limitations.Add(new Limitation("USN.DAMAGED", $"В {stats.Resynchronised} местах данные не похожи на записи; разбор продолжен со следующей границы."));
        }

        if (dropped > 0)
        {
            limitations.Add(new Limitation("USN.LIMIT", $"Журнал очень большой: {dropped.ToString("N0", Ru)} записей о файлах сверх {MaxRetained.ToString("N0", Ru)} не разобраны."));
        }

        if (readFailure is not null)
        {
            limitations.Add(new Limitation("USN.READ_FAILED", $"Чтение журнала прервано: {readFailure}. Разобрано то, что прочитано до сбоя."));
            await context.Writer.AddErrorAsync(new ModuleError($"{drive}: чтение журнала прервано: {readFailure}", null, artifact), ct).ConfigureAwait(false);
        }

        if (cache.Get(drive) is null)
        {
            limitations.Add(new Limitation("USN.NO_MFT", "Модуль MFT не выполнялся: пути восстановлены только по самому журналу и могут быть неполными."));
        }

        var created = info.CreatedUtc;
        await context.Writer.AddCoverageAsync(Coverage(context, artifact,
            dropped > 0 || stats.Resynchronised > 0 || readFailure is not null ? CollectionStatus.Partial : CollectionStatus.Collected,
            total,
            limitations,
            $"{artifact} (журнал {info.JournalId:X}{(created is null ? string.Empty : ", создан " + created.Value.ToString("u", Ru))})"), ct).ConfigureAwait(false);

        if (JournalRecreated(drive, info) is { } recreated)
        {
            await context.Writer.AddEvidenceAsync(Recreated(context, drive, artifact, info, recreated), ct).ConfigureAwait(false);
        }

        context.Progress.Report(new ModuleProgress(Id, ModuleState.Running,
            $"{drive}: записей журнала {total.ToString("N0", Ru)}; файлов записано {recordedFiles.ToString("N0", Ru)}, событий {events.ToString("N0", Ru)}."));
    }

    /// <summary>Stops at the first read failure instead of failing the module; the reason is reported.</summary>
    private static IEnumerable<ReadOnlyMemory<byte>> ReadSafely(IEnumerable<ReadOnlyMemory<byte>> blocks, Action<string> failed)
    {
        using var e = blocks.GetEnumerator();
        while (true)
        {
            ReadOnlyMemory<byte> current;
            try
            {
                if (!e.MoveNext())
                {
                    yield break;
                }

                current = e.Current;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            {
                failed(ex.Message);
                yield break;
            }

            yield return current;
        }
    }

    /// <summary>The journal was created well after the volume: it was deleted and recreated at some point.</summary>
    private DateTimeOffset? JournalRecreated(string drive, UsnJournalInfo info) =>
        info.CreatedUtc is { } created && cache.Formatted(drive) is { } formatted && created - formatted > TimeSpan.FromDays(1) ? created : null;

    private Evidence Recreated(AnalyzerContext context, string drive, string artifact, UsnJournalInfo info, DateTimeOffset created) => new()
    {
        EvidenceId = context.NewEvidenceId(),
        InvestigationId = context.InvestigationId,
        ModuleId = Id,
        Source = new SourceRef(EvidenceSourceKind.UsnJournal, artifact, ParserName, ParserVersion),
        Locator = $"USN {drive} журнал {info.JournalId:X}",
        EventType = EvidenceEventType.Created,
        Timestamp = new EvidenceTimestamp(created, "UsnJournal.Id", TimestampPrecision.HundredNanoseconds),
        Target = new ObjectRef { RecordedPath = drive + @"\$Extend\$UsnJrnl", FileName = "$UsnJrnl" },
        Confidence = Confidence.Low,
        Rationale = "Журнал изменений создан намного позже тома: его удаляли и создавали заново. Так делают программы очистки и вручную (fsutil usn deletejournal), но журнал может пересоздать и сама система или утилита обслуживания диска. Всё, что было до этой даты, журнал больше не показывает.",
        CollectionStatus = CollectionStatus.Collected,
        Description = $"Журнал изменений тома {drive} создан заново {created.ToString("u", Ru)} (UTC).",
        Attributes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Usn.JournalId"] = info.JournalId.ToString("X", CultureInfo.InvariantCulture),
            ["Usn.VolumeFormatted"] = cache.Formatted(drive)!.Value.ToString("O", CultureInfo.InvariantCulture),
        },
        CollectedAtUtc = context.Time.GetUtcNow(),
    };

    private IEnumerable<Evidence> Lifecycle(AnalyzerContext context, string drive, string artifact, List<(UsnRecord Record, ResolvedPath Path, ScopeMatch Match)> h)
    {
        (UsnRecord Record, ResolvedPath Path)? renameFrom = null;
        var createSeen = false;
        var dataChanges = new List<UsnRecord>();
        var basicChanges = new List<UsnRecord>();
        var streamChanges = new List<UsnRecord>();
        foreach (var (r, path, match) in h)
        {
            if ((r.Reason & UsnReason.FileCreate) != 0 && !createSeen)
            {
                createSeen = true;
                yield return Event(context, drive, artifact, r, path, match, EvidenceEventType.Created,
                    $"Создан {Kind(r)} {r.Name}: {path.Path}.", Confidence.Informational, Rationale, null);
            }

            if ((r.Reason & UsnReason.RenameOldName) != 0 && (r.Reason & UsnReason.RenameNewName) == 0)
            {
                renameFrom = (r, path);
            }

            if ((r.Reason & UsnReason.RenameNewName) != 0 && renameFrom is { } from && from.Record.Usn != r.Usn)
            {
                renameFrom = null;
                var moved = from.Record.Parent != r.Parent;
                var oldExt = Path.GetExtension(from.Record.Name);
                var newExt = Path.GetExtension(r.Name);
                var extensionChanged = !oldExt.Equals(newExt, StringComparison.OrdinalIgnoreCase)
                                       && (RelevantExtensions.Contains(oldExt) || RelevantExtensions.Contains(newExt));
                var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["Usn.OldName"] = from.Record.Name,
                    ["Usn.OldPath"] = from.Path.Path,
                    ["Usn.NewName"] = r.Name,
                };
                if (extensionChanged)
                {
                    attrs["Usn.ExtensionChanged"] = $"{oldExt} → {newExt}";
                }

                var what = moved ? "Перемещён" : "Переименован";
                yield return Event(context, drive, artifact, r, path, match, moved ? EvidenceEventType.Moved : EvidenceEventType.Renamed,
                    $"{what} {Kind(r)}: {from.Path.Path} → {path.Path}.",
                    extensionChanged ? Confidence.Low : Confidence.Informational,
                    extensionChanged
                        ? "Журнал изменений NTFS записал смену расширения архива или программы. Так прячут файл от поиска по расширению, но так же переименовывают по ошибке или из любопытства. Это повод сверить с другими источниками, не вывод."
                        : Rationale,
                    attrs);
            }

            if ((r.Reason & DataChange) != 0 && (r.Reason & UsnReason.Close) != 0)
            {
                dataChanges.Add(r);
            }

            if ((r.Reason & UsnReason.BasicInfoChange) != 0 && (r.Reason & UsnReason.Close) != 0)
            {
                basicChanges.Add(r);
            }

            if ((r.Reason & StreamChanges) != 0 && (r.Reason & UsnReason.Close) != 0)
            {
                streamChanges.Add(r);
            }

            if ((r.Reason & UsnReason.FileDelete) != 0)
            {
                yield return Event(context, drive, artifact, r, path, match, EvidenceEventType.Deleted,
                    $"Удалён {Kind(r)} {r.Name}: {path.Path}.", Confidence.Informational,
                    "Журнал изменений NTFS записал удаление в этот момент; время ставит система, программой его не изменить. Само удаление файла не говорит о нарушении.", null);
            }
        }

        if (dataChanges.Count > 0)
        {
            yield return Aggregate(context, drive, artifact, h, dataChanges, EvidenceEventType.Modified,
                "Содержимое менялось", "Usn.DataChanges");
        }

        if (basicChanges.Count > 0)
        {
            yield return Aggregate(context, drive, artifact, h, basicChanges, EvidenceEventType.Modified,
                "Менялись время или атрибуты (например, через SetFileTime или «Скрытый»)", "Usn.BasicInfoChanges");
        }

        if (streamChanges.Count > 0)
        {
            yield return Aggregate(context, drive, artifact, h, streamChanges, EvidenceEventType.Modified,
                "Менялись дополнительные потоки (например, Zone.Identifier — отметка о загрузке из интернета)", "Usn.StreamChanges");
        }
    }

    private const string Rationale = "Запись журнала изменений NTFS; время ставит система в момент события, программой его не изменить (только удалить журнал целиком).";

    private static string Kind(UsnRecord r) => "файл";

    private Evidence Aggregate(
        AnalyzerContext context,
        string drive,
        string artifact,
        List<(UsnRecord Record, ResolvedPath Path, ScopeMatch Match)> h,
        List<UsnRecord> changes,
        EvidenceEventType type,
        string what,
        string attribute)
    {
        var last = changes[^1];
        var place = h.Last(x => x.Record.Usn <= last.Usn);
        var firstTime = changes[0].TimeUtc;
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [attribute] = changes.Count.ToString(CultureInfo.InvariantCulture),
            ["Usn.FirstChange"] = firstTime?.ToString("O", CultureInfo.InvariantCulture) ?? "?",
            ["Usn.Reasons"] = string.Join(", ", changes.Select(c => c.Reason).Distinct().Select(r => r.ToString())),
        };
        return Event(context, drive, artifact, last, place.Path, place.Match, type,
            $"{what} {changes.Count} раз(а) у файла {last.Name}: {place.Path.Path}" +
            (firstTime is null || changes.Count == 1 ? "." : $", с {firstTime.Value.ToString("u", Ru)}."),
            Confidence.Informational, Rationale, attrs);
    }

    private Evidence Event(
        AnalyzerContext context,
        string drive,
        string artifact,
        UsnRecord r,
        ResolvedPath path,
        ScopeMatch match,
        EvidenceEventType type,
        string description,
        Confidence confidence,
        string rationale,
        Dictionary<string, string>? extra)
    {
        var attrs = extra ?? new Dictionary<string, string>(StringComparer.Ordinal);
        attrs["Usn.Reason"] = r.Reason.ToString();
        attrs["Usn"] = r.Usn.ToString(CultureInfo.InvariantCulture);
        if (match.MinecraftRoot is not null)
        {
            attrs["MinecraftRoot"] = match.MinecraftRoot;
        }

        var limitations = new List<Limitation>();
        if (path.Quality.HasFlag(PathQuality.ReusedAncestor) || path.Quality.HasFlag(PathQuality.Broken))
        {
            limitations.Add(new Limitation("PATH.PARTIAL", "Путь восстановлен не полностью: папка не найдена ни в MFT, ни в журнале; неизвестная часть показана как «?»."));
        }

        if (path.Quality.HasFlag(PathQuality.DeletedAncestor))
        {
            limitations.Add(new Limitation("PATH.DELETED_ANCESTOR", "Одна из папок пути удалена; её имя взято из журнала или из свободной записи MFT."));
        }

        var complete = !path.Quality.HasFlag(PathQuality.ReusedAncestor) && !path.Quality.HasFlag(PathQuality.Broken);
        return new Evidence
        {
            EvidenceId = context.NewEvidenceId(),
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = new SourceRef(EvidenceSourceKind.UsnJournal, artifact, ParserName, ParserVersion),
            Locator = $"USN {drive} 0x{r.Usn:X}",
            EventType = type,
            Timestamp = r.TimeUtc is { } t ? new EvidenceTimestamp(t, "Usn.TimeStamp", TimestampPrecision.HundredNanoseconds) : null,
            Target = new ObjectRef
            {
                RecordedPath = path.Path,
                NormalizedPath = complete ? PathNormalizer.Normalize(path.Path) : null,
                FileName = r.Name,
                VolumeSerial = cache.Serial(drive),
                MftEntry = r.File.Entry,
                MftSequence = r.File.Sequence,
            },
            Confidence = confidence,
            Rationale = rationale,
            CollectionStatus = complete ? CollectionStatus.Collected : CollectionStatus.Partial,
            Description = description,
            Limitations = limitations,
            Attributes = attrs,
            CollectedAtUtc = context.Time.GetUtcNow(),
        };
    }

    private SourceCoverage Coverage(AnalyzerContext context, string artifact, CollectionStatus status, long items, List<Limitation> limitations, string? scope = null) => new()
    {
        InvestigationId = context.InvestigationId,
        ModuleId = Id,
        Source = EvidenceSourceKind.UsnJournal,
        Scope = scope ?? artifact,
        Status = status,
        ItemsRead = items,
        Limitations = limitations,
    };
}

/// <summary>
/// Paths for journal records: a parent that is still live in the MFT gives the current path; otherwise the
/// folder names the journal itself recorded are used, then the free MFT record; what is left unknown is "?".
/// </summary>
internal sealed class UsnPathResolver(string drive, MftIndex? mft, Dictionary<FileReference, (string Name, FileReference Parent)> folders)
{
    private const int MaxDepth = 255;

    public ResolvedPath Resolve(FileReference parent, string name)
    {
        var folder = Folder(parent, 0, out var quality);
        return new ResolvedPath(folder + "\\" + name, quality);
    }

    private string Folder(FileReference reference, int depth, out PathQuality quality)
    {
        quality = PathQuality.Complete;
        if (reference.Entry == MftIndex.RootEntry)
        {
            return drive;
        }

        if (depth >= MaxDepth)
        {
            quality = PathQuality.Broken;
            return drive + "\\?";
        }

        var state = mft?.Check(reference) ?? ReferenceState.Missing;
        if (state == ReferenceState.Live)
        {
            var live = mft!.ResolveFolderPath(reference);
            quality = live.Quality;
            return live.Path;
        }

        if (folders.TryGetValue(reference, out var known))
        {
            var above = Folder(known.Parent, depth + 1, out var aboveQuality);
            quality = aboveQuality | PathQuality.DeletedAncestor;
            return above + "\\" + known.Name;
        }

        if (state == ReferenceState.Deleted)
        {
            var freed = mft!.ResolveFolderPath(reference);
            quality = freed.Quality | PathQuality.DeletedAncestor;
            return freed.Path;
        }

        quality = state == ReferenceState.Reused ? PathQuality.ReusedAncestor : PathQuality.Broken;
        return drive + "\\?";
    }
}
