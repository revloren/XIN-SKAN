using System.Globalization;
using XINSkan.Analyzers.History;
using XINSkan.Core.Paths;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.ExecutionFormats;
using XINSkan.Models;
using XINSkan.Ntfs;

namespace XINSkan.Analyzers.Execution;

/// <summary>
/// Amcache.hve: the inventory Windows keeps of programs present on the system — path, SHA-1, size, version,
/// publisher — and when each entry was written. Since Windows 10 an entry shows that a file existed and was
/// inventoried, not that it ran.
/// </summary>
public sealed class AmcacheAnalyzer(HistoryOptions options, IProtectedFileSource files, IVolumeDirectory volumes) : IAnalyzer
{
    public const string ModuleId = "amcache";
    private const string ParserName = "xinskan-regf";
    private const string ParserVersion = "1";
    private const long MaxHive = 256L * 1024 * 1024;

    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    public string Id => ModuleId;

    public string DisplayName => "Amcache";

    public AnalyzerRequirements Requirements { get; } = new() { OptionalCapabilities = [Capability.Administrator, Capability.RawVolumeRead, Capability.OtherUserProfiles] };

    internal sealed record Entry(string Path, string Key, long LastWrite, string? Sha1, long? Size, IReadOnlyDictionary<string, string> Attributes, FileReference? Reference);

    public async Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var windows = options.WindowsFolder ?? (options.Volumes.Count > 0 ? options.Volumes[0] : "C:") + @"\Windows";
        var path = ProgramRelevance.Join(windows, "AppCompat", "Programs", "Amcache.hve");
        var limitations = new List<Limitation>
        {
            new("AMCACHE.MEANING", "Запись Amcache показывает, что Windows видела и учла файл (установка, запуск, проверка совместимости), а не что он запускался. Время — последняя запись ключа."),
            new("AMCACHE.SHA1", "SHA-1 в Amcache посчитан Windows по первым 31,4 МБ файла; для больших файлов он не совпадает с хешем всего файла."),
        };

        var hiveFile = files.Read(path, MaxHive);
        if (hiveFile is null)
        {
            limitations.Add(new Limitation("AMCACHE.ABSENT", "Файла Amcache.hve нет (Windows 7 без обновлений или файл удалён)."));
            await Coverage(context, path, CollectionStatus.Skipped, 0, null, null, limitations, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (hiveFile.Data.Length == 0)
        {
            await context.Writer.AddErrorAsync(new ModuleError($"{path}: {string.Join(" ", hiveFile.Problems)}", "AmcacheUnreadable", path), cancellationToken).ConfigureAwait(false);
            limitations.Add(new Limitation("AMCACHE.UNREADABLE", "Amcache.hve не прочитан: " + string.Join(" ", hiveFile.Problems)));
            await Coverage(context, path, CollectionStatus.Failed, 0, null, null, limitations, cancellationToken).ConfigureAwait(false);
            return;
        }

        var logs = new List<byte[]>();
        foreach (var log in new[] { path + ".LOG1", path + ".LOG2" })
        {
            if (files.Read(log, MaxHive) is { Data.Length: > 0 } l)
            {
                logs.Add(l.Data);
            }
        }

        var hive = RegistryHive.Open(hiveFile.Data, [.. logs]);
        if (hive?.Root is not { } root)
        {
            limitations.Add(new Limitation("AMCACHE.DAMAGED", "Amcache.hve повреждён: " + string.Join(" ", hive?.Problems ?? ["нет подписи regf"])));
            await Coverage(context, path, CollectionStatus.Failed, 0, null, null, limitations, cancellationToken).ConfigureAwait(false);
            return;
        }

        foreach (var p in hiveFile.Problems)
        {
            limitations.Add(new Limitation("AMCACHE.READ", p));
        }

        if (hive.RecoveryIncomplete)
        {
            limitations.Add(new Limitation("AMCACHE.DIRTY", "Куст не был полностью записан на диск, а журналы применены не полностью: последние записи могут отсутствовать."));
        }

        if (hive.Problems.Count > 0)
        {
            limitations.Add(new Limitation("AMCACHE.PARSE", $"Проблем разбора: {hive.Problems.Count}. Первая: {hive.Problems[0]}"));
        }

        var entries = root.Open(@"Root\InventoryApplicationFile") is { } inventory ? NewFormat(root, inventory) : OldFormat(root);
        var resolver = new VolumeResolver(volumes.Volumes());
        var scope = new HistoryScope(options.UsersRoot, options.CurrentProfile, context.Permissions.Has(Capability.OtherUserProfiles), options.TempFolders, options.ExtraRoots);
        long recorded = 0;
        DateTimeOffset? earliest = null, latest = null;
        foreach (var e in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var time = NtfsTime.ToUtc(e.LastWrite);
            if (time is { } t)
            {
                earliest = earliest is null || t < earliest ? t : earliest;
                latest = latest is null || t > latest ? t : latest;
            }

            var fileName = ProgramRelevance.FileName(e.Path);
            var why = ProgramRelevance.Why(fileName, e.Path, true, resolver.IsRemovable(e.Path), scope);
            if (why is null)
            {
                continue;
            }

            var attrs = new Dictionary<string, string>(e.Attributes, StringComparer.Ordinal)
            {
                ["Amcache.Why"] = why,
                ["Amcache.Key"] = e.Key,
                ["Amcache.ReadMethod"] = hiveFile.Method,
            };
            if (e.Sha1 is not null)
            {
                attrs["Amcache.Sha1"] = e.Sha1;
            }

            await context.Writer.AddEvidenceAsync(new Evidence
            {
                EvidenceId = context.NewEvidenceId(),
                InvestigationId = context.InvestigationId,
                ModuleId = Id,
                Source = new SourceRef(EvidenceSourceKind.Amcache, path, ParserName, ParserVersion),
                Locator = $@"{path}\{e.Key}",
                EventType = EvidenceEventType.Existed,
                Timestamp = time is null ? null : new EvidenceTimestamp(time.Value, "Amcache.KeyLastWrite", TimestampPrecision.HundredNanoseconds),
                Target = new ObjectRef
                {
                    RecordedPath = e.Path,
                    NormalizedPath = PathNormalizer.Normalize(e.Path),
                    FileName = fileName,
                    Size = e.Size,
                    MftEntry = e.Reference?.Entry,
                    MftSequence = e.Reference?.Sequence,
                },
                Confidence = Confidence.Informational,
                Rationale = "Amcache ведёт сама Windows. Запись показывает, что файл был на диске и Windows его учла; это не доказательство запуска, но SHA-1 позволяет узнать файл, даже если он удалён или переименован.",
                CollectionStatus = CollectionStatus.Collected,
                Description = $"Windows учла программу {fileName} ({e.Path})" + (e.Sha1 is null ? string.Empty : $", SHA-1 {e.Sha1}") +
                              (time is null ? "." : $"; запись обновлена {time.Value.ToString("u", Ru)}."),
                Attributes = attrs,
                CollectedAtUtc = context.Time.GetUtcNow(),
            }, cancellationToken).ConfigureAwait(false);
            recorded++;
        }

        var status = limitations.Any(l => l.Code is "AMCACHE.DIRTY" or "AMCACHE.READ" or "AMCACHE.PARSE") ? CollectionStatus.Partial : CollectionStatus.Collected;
        await Coverage(context, path, status, entries.Count, earliest, latest, limitations, cancellationToken).ConfigureAwait(false);
        context.Progress.Report(new ModuleProgress(Id, ModuleState.Running,
            $"Записей Amcache {entries.Count.ToString("N0", Ru)}, записано {recorded.ToString("N0", Ru)}" + (hive.LogEntriesApplied > 0 ? $", применено записей журнала {hive.LogEntriesApplied}." : ".")));
    }

    /// <summary>Windows 10/11: Root\InventoryApplicationFile, one key per file; programs in InventoryApplication.</summary>
    internal static List<Entry> NewFormat(HiveKey root, HiveKey inventory)
    {
        var programs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in root.Open(@"Root\InventoryApplication")?.SubKeys() ?? [])
        {
            if (p.Value("Name")?.AsString() is { Length: > 0 } name)
            {
                programs[p.Name] = name;
            }
        }

        var list = new List<Entry>();
        foreach (var k in inventory.SubKeys())
        {
            var path = k.Value("LowerCaseLongPath")?.AsString();
            if (string.IsNullOrEmpty(path))
            {
                continue;
            }

            var attrs = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var (name, attr) in new[] { ("Name", "Amcache.Name"), ("Publisher", "Amcache.Publisher"), ("Version", "Amcache.Version"), ("ProductName", "Amcache.ProductName"), ("LinkDate", "Amcache.LinkDate"), ("BinaryType", "Amcache.BinaryType"), ("OriginalFileName", "Amcache.OriginalFileName") })
            {
                if (k.Value(name)?.AsString() is { Length: > 0 } v)
                {
                    attrs[attr] = v;
                }
            }

            if (k.Value("IsOsComponent")?.AsNumber() is { } os)
            {
                attrs["Amcache.IsOsComponent"] = os.ToString(CultureInfo.InvariantCulture);
            }

            if (k.Value("ProgramId")?.AsString() is { Length: > 0 } programId)
            {
                attrs["Amcache.ProgramId"] = programId;
                if (programs.TryGetValue(programId, out var program))
                {
                    attrs["Amcache.Program"] = program;
                }
            }

            list.Add(new Entry(path, @"Root\InventoryApplicationFile\" + k.Name, k.LastWriteTime, Sha1(k.Value("FileId")?.AsString()), k.Value("Size")?.AsNumber(), attrs, null));
        }

        return list;
    }

    /// <summary>Windows 8, 8.1, Server 2012 R2 (and 7 with updates): Root\File\{volume}\{file reference}.</summary>
    internal static List<Entry> OldFormat(HiveKey root)
    {
        var list = new List<Entry>();
        foreach (var volume in root.Open(@"Root\File")?.SubKeys() ?? [])
        {
            foreach (var k in volume.SubKeys())
            {
                var path = k.Value("15")?.AsString();
                if (string.IsNullOrEmpty(path))
                {
                    continue;
                }

                var attrs = new Dictionary<string, string>(StringComparer.Ordinal) { ["Amcache.Volume"] = volume.Name };
                foreach (var (name, attr) in new[] { ("0", "Amcache.ProductName"), ("1", "Amcache.Publisher"), ("5", "Amcache.Version"), ("c", "Amcache.Description") })
                {
                    if (k.Value(name)?.AsString() is { Length: > 0 } v)
                    {
                        attrs[attr] = v;
                    }
                }

                FileReference? reference = ulong.TryParse(k.Name, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var r)
                    ? new FileReference(r & 0xFFFF_FFFF_FFFF, (ushort)(r >> 48))
                    : null;
                list.Add(new Entry(path, $@"Root\File\{volume.Name}\{k.Name}", k.LastWriteTime, Sha1(k.Value("101")?.AsString()), k.Value("6")?.AsNumber(), attrs, reference));
            }
        }

        return list;
    }

    /// <summary>Amcache stores SHA-1 as "0000" followed by 40 hex digits.</summary>
    private static string? Sha1(string? fileId) =>
        fileId is { Length: 44 } && fileId.StartsWith("0000", StringComparison.Ordinal) ? fileId[4..].ToLowerInvariant()
        : fileId is { Length: 40 } ? fileId.ToLowerInvariant()
        : null;

    private async Task Coverage(AnalyzerContext context, string path, CollectionStatus status, long items, DateTimeOffset? earliest, DateTimeOffset? latest, List<Limitation> limitations, CancellationToken ct) =>
        await context.Writer.AddCoverageAsync(new SourceCoverage
        {
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = EvidenceSourceKind.Amcache,
            Scope = path,
            Status = status,
            ItemsRead = items,
            EarliestUtc = earliest,
            LatestUtc = latest,
            Limitations = limitations,
        }, ct).ConfigureAwait(false);
}
