using System.Globalization;
using XINSkan.Analyzers.History;
using XINSkan.Core.IO;
using XINSkan.Core.Paths;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.ExecutionFormats;
using XINSkan.Models;
using XINSkan.Ntfs;

namespace XINSkan.Analyzers.Execution;

/// <summary>
/// Prefetch: Windows writes a .pf file when a program runs — up to eight last run times, the run count, and the
/// files the program loaded in its first seconds (for java/javaw this includes the game's JARs).
/// </summary>
public sealed class PrefetchAnalyzer(HistoryOptions options, IDirectoryLister lister, IFileSource files, IVolumeDirectory volumes, IRegistryView machine) : IAnalyzer
{
    public const string ModuleId = "prefetch";
    private const string ParserName = "xinskan-prefetch";
    private const string ParserVersion = "1";
    private const int MaxJarsPerRun = 300;
    private const string ParametersKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters";

    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    public string Id => ModuleId;

    public string DisplayName => "Prefetch";

    public AnalyzerRequirements Requirements { get; } = new() { OptionalCapabilities = [Capability.Administrator, Capability.OtherUserProfiles] };

    public async Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var folder = ProgramRelevance.Join(options.WindowsFolder ?? (options.Volumes.Count > 0 ? options.Volumes[0] : "C:") + @"\Windows", "Prefetch");
        var resolver = new VolumeResolver(volumes.Volumes());
        var scope = new HistoryScope(options.UsersRoot, options.CurrentProfile, context.Permissions.Has(Capability.OtherUserProfiles), options.TempFolders, options.ExtraRoots);
        var limitations = new List<Limitation>
        {
            new("PREFETCH.WINDOW", "Prefetch хранит ограниченное число файлов (обычно до 1024) и только 8 последних запусков программы; файлы можно удалить. Отсутствие файла ничего не доказывает."),
        };

        var enabled = machine.Int(ParametersKey, "EnablePrefetcher"); // 0 off, 1 applications, 2 boot, 3 both
        if (enabled is 0 or 2)
        {
            limitations.Add(new Limitation("PREFETCH.DISABLED", $"Сбор Prefetch для программ выключен (EnablePrefetcher = {enabled}). Новые запуски не записываются."));
            await context.Writer.AddEvidenceAsync(PrefetchOff(context, enabled.Value), cancellationToken).ConfigureAwait(false);
        }

        // Prefetch is written by the SysMain (Superfetch) service: when it is disabled nothing new is recorded.
        if (machine.Int(@"SYSTEM\CurrentControlSet\Services\SysMain", "Start") == 4)
        {
            limitations.Add(new Limitation("PREFETCH.SYSMAIN_DISABLED", "Служба SysMain отключена: Prefetch не пополняется."));
            await context.Writer.AddEvidenceAsync(SysMainOff(context), cancellationToken).ConfigureAwait(false);
        }

        IReadOnlyList<FsEntry> entries;
        try
        {
            entries = lister.DirectoryExists(folder) ? lister.List(folder) : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            await context.Writer.AddErrorAsync(new ModuleError($"{folder}: {ex.Message}", ex.GetType().Name, folder), cancellationToken).ConfigureAwait(false);
            limitations.Add(new Limitation("PREFETCH.UNREADABLE", $"Папка Prefetch не прочитана: {ex.Message}. Нужны права администратора."));
            await Coverage(context, folder, CollectionStatus.Failed, 0, limitations, cancellationToken).ConfigureAwait(false);
            return;
        }

        long read = 0, damaged = 0, recorded = 0;
        DateTimeOffset? earliest = null, latest = null;
        foreach (var e in entries.Where(e => !e.IsDirectory && e.Name.EndsWith(".pf", StringComparison.OrdinalIgnoreCase)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            read++;
            var bytes = Read(e.FullPath);
            var pf = bytes is null ? null : PrefetchFile.Parse(bytes);
            if (pf is null || pf.Version == 0)
            {
                damaged++;
                continue;
            }

            foreach (var t in pf.LastRunTimes.Select(NtfsTime.ToUtc).OfType<DateTimeOffset>())
            {
                earliest = earliest is null || t < earliest ? t : earliest;
                latest = latest is null || t > latest ? t : latest;
            }

            foreach (var evidence in Interpret(context, e, pf, resolver, scope))
            {
                await context.Writer.AddEvidenceAsync(evidence, cancellationToken).ConfigureAwait(false);
                recorded++;
            }
        }

        if (entries.Count == 0)
        {
            limitations.Add(new Limitation("PREFETCH.EMPTY", "Папка Prefetch пуста или отсутствует (на серверных Windows сбор обычно выключен)."));
        }

        if (damaged > 0)
        {
            limitations.Add(new Limitation("PREFETCH.DAMAGED", $"{damaged} файлов .pf не прочитано или повреждено."));
        }

        await Coverage(context, folder, damaged > 0 ? CollectionStatus.Partial : CollectionStatus.Collected, read, limitations, cancellationToken, earliest, latest).ConfigureAwait(false);
        context.Progress.Report(new ModuleProgress(Id, ModuleState.Running, $"Файлов Prefetch {read.ToString("N0", Ru)}, записано {recorded.ToString("N0", Ru)}."));
    }

    private byte[]? Read(string path)
    {
        try
        {
            using var f = files.Open(path);
            if (f.Content.Length > PrefetchFile.MaxCompressed)
            {
                return null;
            }

            var b = new byte[f.Content.Length];
            var n = f.Content.ReadAtLeast(b, b.Length, throwOnEndOfStream: false);
            return b[..n];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private IEnumerable<Evidence> Interpret(AnalyzerContext context, FsEntry file, PrefetchFile pf, VolumeResolver resolver, HistoryScope scope)
    {
        // The program's own path is among the files it touched.
        var self = pf.Files.FirstOrDefault(f => ProgramRelevance.FileName(f.Path).Equals(pf.ExecutableName, StringComparison.OrdinalIgnoreCase));
        var (path, resolved, serial) = self is null ? (pf.ExecutableName, false, null) : resolver.Resolve(self.Path);
        var removable = resolved && resolver.IsRemovable(path);
        var why = self is null
            ? ProgramRelevance.IsKnown(pf.ExecutableName) ? "известная программа (Java или лаунчер Minecraft)" : null
            : ProgramRelevance.Why(pf.ExecutableName, path, resolved, removable, scope);
        var jars = pf.Files
            .Select(f => (File: f, Resolved: resolver.Resolve(f.Path)))
            .Where(x => x.File.Path.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
            .Where(x => !x.Resolved.Path.Contains(@"\libraries\", StringComparison.OrdinalIgnoreCase)) // the game's own libraries
            .ToList();
        if (why is null && jars.Count == 0)
        {
            yield break;
        }

        var times = pf.LastRunTimes.Select(NtfsTime.ToUtc).ToList();
        var last = times.FirstOrDefault();
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Prefetch.Version"] = pf.Version.ToString(CultureInfo.InvariantCulture),
            ["Prefetch.Hash"] = pf.Hash.ToString("X8", CultureInfo.InvariantCulture),
            ["Prefetch.RunCount"] = pf.RunCount.ToString(CultureInfo.InvariantCulture),
            ["Prefetch.Executable"] = pf.ExecutableName,
            ["Prefetch.Why"] = why ?? "запуск загружал JAR-файлы",
        };
        if (serial is not null)
        {
            attrs["Volume.Serial"] = serial;
        }

        if (jars.Count > 0)
        {
            attrs["Prefetch.Jars"] = string.Join(" | ", jars.Take(50).Select(j => j.Resolved.Path));
        }

        var limitations = new List<Limitation>();
        if (self is null)
        {
            limitations.Add(new Limitation("PREFETCH.NO_PATH", "В списке файлов запуска нет пути самой программы: известно только её имя."));
        }
        else if (!resolved)
        {
            limitations.Add(new Limitation("PATH.VOLUME_UNKNOWN", "Том из записи Prefetch сейчас не подключён (например, флешка): путь показан так, как его записала система."));
        }

        foreach (var p in pf.Problems.Take(3))
        {
            limitations.Add(new Limitation("PREFETCH.PARSE", p));
        }

        var others = times.Skip(1).Select((t, i) => (t, i)).Where(x => x.t is not null)
            .Select(x => new EvidenceTimestamp(x.t!.Value, $"Prefetch.LastRun[{x.i + 1}]", TimestampPrecision.HundredNanoseconds)).ToList();
        if (file.LastWriteTimeUtc.Year >= 1980)
        {
            others.Add(new EvidenceTimestamp(new DateTimeOffset(DateTime.SpecifyKind(file.LastWriteTimeUtc, DateTimeKind.Utc)), "Pf.FileModified", TimestampPrecision.HundredNanoseconds));
        }

        if (file.CreationTimeUtc.Year >= 1980)
        {
            others.Add(new EvidenceTimestamp(new DateTimeOffset(DateTime.SpecifyKind(file.CreationTimeUtc, DateTimeKind.Utc)), "Pf.FileCreated", TimestampPrecision.HundredNanoseconds));
        }

        yield return new Evidence
        {
            EvidenceId = context.NewEvidenceId(),
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = new SourceRef(EvidenceSourceKind.Prefetch, file.FullPath, ParserName, ParserVersion),
            Locator = file.FullPath,
            EventType = EvidenceEventType.Executed,
            Timestamp = last is null ? null : new EvidenceTimestamp(last.Value, "Prefetch.LastRun[0]", TimestampPrecision.HundredNanoseconds, null, TimeSpan.FromSeconds(10)),
            OtherTimestamps = others,
            Target = new ObjectRef
            {
                RecordedPath = path,
                NormalizedPath = resolved && self is not null ? PathNormalizer.Normalize(path) : null,
                FileName = pf.ExecutableName,
                MftEntry = self?.MftEntry,
                MftSequence = self?.MftSequence,
            },
            Confidence = Confidence.Informational,
            Rationale = "Prefetch пишет сама Windows при запуске программы: это след запуска. Время последнего запуска записывается примерно через 10 секунд после старта.",
            CollectionStatus = limitations.Count == 0 ? CollectionStatus.Collected : CollectionStatus.Partial,
            Description = $"Запускалась программа {pf.ExecutableName} ({path}), раз: {pf.RunCount}" +
                          (last is null ? "." : $", последний — {last.Value.ToString("u", Ru)}.") +
                          (jars.Count > 0 ? $" Загружала JAR-файлов: {jars.Count}." : string.Empty),
            Limitations = limitations,
            Attributes = attrs,
            CollectedAtUtc = context.Time.GetUtcNow(),
        };

        // JARs loaded by Java in the first seconds of a run: the game itself and its mods.
        foreach (var (jar, r) in jars.Take(MaxJarsPerRun))
        {
            var jarAttrs = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Prefetch.Executable"] = pf.ExecutableName,
                ["Prefetch.Hash"] = pf.Hash.ToString("X8", CultureInfo.InvariantCulture),
                ["Prefetch.RunCount"] = pf.RunCount.ToString(CultureInfo.InvariantCulture),
            };
            if (HistoryScope.MinecraftRoot(r.Path) is { } mc)
            {
                jarAttrs["MinecraftRoot"] = mc;
            }

            yield return new Evidence
            {
                EvidenceId = context.NewEvidenceId(),
                InvestigationId = context.InvestigationId,
                ModuleId = Id,
                Source = new SourceRef(EvidenceSourceKind.Prefetch, file.FullPath, ParserName, ParserVersion),
                Locator = $"{file.FullPath} → {jar.Path}",
                EventType = EvidenceEventType.Loaded,
                Timestamp = last is null ? null : new EvidenceTimestamp(last.Value, "Prefetch.LastRun[0]", TimestampPrecision.HundredNanoseconds, null, TimeSpan.FromSeconds(10)),
                Target = new ObjectRef
                {
                    RecordedPath = r.Path,
                    NormalizedPath = r.Resolved ? PathNormalizer.Normalize(r.Path) : null,
                    FileName = ProgramRelevance.FileName(r.Path),
                    MftEntry = jar.MftEntry,
                    MftSequence = jar.MftSequence,
                },
                Confidence = Confidence.Informational,
                Rationale = ProgramRelevance.IsJava(pf.ExecutableName)
                    ? "Java открывала этот JAR в первые секунды запуска (по Prefetch): так загружаются игра и её моды. Это вывод из списка файлов запуска Java, а не отдельная запись о запуске JAR."
                    : $"{pf.ExecutableName} открывала этот JAR в первые секунды запуска (по Prefetch).",
                CollectionStatus = r.Resolved ? CollectionStatus.Collected : CollectionStatus.Partial,
                Description = $"{pf.ExecutableName} загружала {r.Path}" + (last is null ? "." : $" (последний запуск {last.Value.ToString("u", Ru)})."),
                Limitations = r.Resolved ? [] : [new Limitation("PATH.VOLUME_UNKNOWN", "Том сейчас не подключён: путь показан так, как его записала система.")],
                Attributes = jarAttrs,
                CollectedAtUtc = context.Time.GetUtcNow(),
            };
        }
    }

    private Evidence PrefetchOff(AnalyzerContext context, int value) => new()
    {
        EvidenceId = context.NewEvidenceId(),
        InvestigationId = context.InvestigationId,
        ModuleId = Id,
        Source = new SourceRef(EvidenceSourceKind.Prefetch, @"HKLM\" + ParametersKey, ParserName, ParserVersion),
        Locator = @"HKLM\" + ParametersKey + @"\EnablePrefetcher",
        EventType = EvidenceEventType.Observed,
        Target = new ObjectRef { RecordedPath = @"HKLM\" + ParametersKey, FileName = "EnablePrefetcher" },
        Confidence = Confidence.Low,
        Rationale = "На обычной Windows 10/11 Prefetch включён по умолчанию; его выключают, чтобы не оставлять следов запуска, но так же делают некоторые «оптимизаторы» и на серверных системах это норма.",
        CollectionStatus = CollectionStatus.Collected,
        Description = $"Сбор Prefetch для программ выключен (EnablePrefetcher = {value}).",
        Attributes = new Dictionary<string, string>(StringComparer.Ordinal) { ["Prefetch.EnablePrefetcher"] = value.ToString(CultureInfo.InvariantCulture) },
        CollectedAtUtc = context.Time.GetUtcNow(),
    };

    private Evidence SysMainOff(AnalyzerContext context) => new()
    {
        EvidenceId = context.NewEvidenceId(),
        InvestigationId = context.InvestigationId,
        ModuleId = Id,
        Source = new SourceRef(EvidenceSourceKind.Prefetch, @"HKLM\SYSTEM\CurrentControlSet\Services\SysMain", ParserName, ParserVersion),
        Locator = @"HKLM\SYSTEM\CurrentControlSet\Services\SysMain\Start",
        EventType = EvidenceEventType.Observed,
        Target = new ObjectRef { RecordedPath = @"HKLM\SYSTEM\CurrentControlSet\Services\SysMain", FileName = "Start" },
        Confidence = Confidence.Low,
        Rationale = "Служба SysMain пишет Prefetch; по умолчанию она включена. Её отключают, чтобы не оставлять следов запуска, но также по советам «ускорить SSD» и в сборках-«твиках».",
        CollectionStatus = CollectionStatus.Collected,
        Description = "Служба SysMain отключена (Start = 4): новые запуски программ в Prefetch не записываются.",
        Attributes = new Dictionary<string, string>(StringComparer.Ordinal) { ["SysMain.Start"] = "4" },
        CollectedAtUtc = context.Time.GetUtcNow(),
    };

    private async Task Coverage(AnalyzerContext context, string folder, CollectionStatus status, long items, List<Limitation> limitations, CancellationToken ct, DateTimeOffset? earliest = null, DateTimeOffset? latest = null) =>
        await context.Writer.AddCoverageAsync(new SourceCoverage
        {
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = EvidenceSourceKind.Prefetch,
            Scope = folder,
            Status = status,
            ItemsRead = items,
            EarliestUtc = earliest,
            LatestUtc = latest,
            Limitations = limitations,
        }, ct).ConfigureAwait(false);
}
