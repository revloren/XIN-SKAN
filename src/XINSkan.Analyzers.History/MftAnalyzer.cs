using System.Globalization;
using System.Security.Cryptography;
using XINSkan.Analyzers.FileHunter.Content;
using XINSkan.Analyzers.FileHunter.Scanning;
using XINSkan.Core.Paths;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;
using XINSkan.Ntfs;

namespace XINSkan.Analyzers.History;

/// <summary>Opens a volume for raw reading, for example "C:" → \\.\C:.</summary>
public interface IVolumeOpener
{
    IRawVolume Open(string drive);
}

/// <summary>What the MFT pass learned about each volume, for the analyzers that run after it (USN Journal).</summary>
public sealed class VolumeHistoryCache
{
    private readonly Dictionary<string, MftIndex> _indexes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _formatted = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ulong> _serials = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Volume serial as Windows reports it (low 32 bits of the NTFS serial).</summary>
    public void SetSerial(string drive, ulong serial) => _serials[drive] = serial;

    public ulong? Serial(string drive) => _serials.TryGetValue(drive, out var s) ? s : null;

    public void Set(string drive, MftIndex index) => _indexes[drive] = index;

    public MftIndex? Get(string drive) => _indexes.GetValueOrDefault(drive);

    /// <summary>Creation time of $MFT itself (record 0): when the volume was formatted, usually the Windows install.</summary>
    public void SetFormatted(string drive, DateTimeOffset time) => _formatted[drive] = time;

    public DateTimeOffset? Formatted(string drive) => _formatted.TryGetValue(drive, out var t) ? t : null;
}

public sealed record HistoryOptions
{
    /// <summary>NTFS volumes to read, as drive letters ("C:").</summary>
    public required IReadOnlyList<string> Volumes { get; init; }

    public required string UsersRoot { get; init; }

    public required string CurrentProfile { get; init; }

    public IReadOnlyList<string> TempFolders { get; init; } = [];

    public IReadOnlyList<string> ExtraRoots { get; init; } = [];

    public static HistoryOptions From(XINSkan.Analyzers.FileHunter.FileHunterOptions fileHunter)
    {
        ArgumentNullException.ThrowIfNull(fileHunter);
        var system = Path.GetPathRoot(fileHunter.UsersRoot)?.TrimEnd('\\', '/') ?? "C:";
        return new HistoryOptions
        {
            Volumes = [system],
            UsersRoot = fileHunter.UsersRoot,
            CurrentProfile = fileHunter.CurrentProfile,
            TempFolders = fileHunter.TempFolders,
            ExtraRoots = fileHunter.ExtraRoots,
        };
    }
}

/// <summary>
/// Reads $MFT of each volume record by record and records (1) deleted files and folders whose last name and
/// place matter for the check, and (2) live archives and executables in Minecraft folders and download
/// locations, with the times NTFS keeps in $FILE_NAME and a comparison against $STANDARD_INFORMATION.
/// </summary>
/// <remarks>
/// Interpretation rules (docs/HISTORY_ENGINE.md): a free record proves the object existed and was deleted, not
/// when; the time of deletion comes only from the USN Journal. A time mismatch between $STANDARD_INFORMATION and
/// $FILE_NAME is a reason to look closer (Low), never proof: archive extraction, copying tools and NTFS
/// "tunnelling" produce the same picture.
/// </remarks>
public sealed class MftAnalyzer(HistoryOptions options, IVolumeOpener volumes, VolumeHistoryCache cache) : IAnalyzer
{
    public const string ModuleId = "mft";
    private const string ParserName = "xinskan-ntfs-mft";
    private const string ParserVersion = "1";

    private static readonly HashSet<string> RelevantExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jar", ".zip", ".exe", ".dll", ".mrpack", ".class",
    };

    private static readonly HashSet<string> MinecraftSpecific = new(StringComparer.OrdinalIgnoreCase) { ".jar", ".mrpack", ".class" };

    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    public string Id => ModuleId;

    public string DisplayName => "MFT";

    public AnalyzerRequirements Requirements { get; } = new()
    {
        RequiredCapabilities = [Capability.RawVolumeRead],
        OptionalCapabilities = [Capability.OtherUserProfiles],
    };

    /// <summary>A record kept during the pass; decided on once all folder names are known.</summary>
    private sealed record Candidate(MftRecord Record, Sha256Hash RecordHash, bool RelevantName);

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
        var artifact = $@"\\.\{drive}\$MFT";
        IRawVolume? volume = null;
        try
        {
            await RunVolumeAsync(context, drive, artifact, () => volume = volumes.Open(drive), ct).ConfigureAwait(false);
        }
        finally
        {
            (volume as IDisposable)?.Dispose();
        }
    }

    private async Task RunVolumeAsync(AnalyzerContext context, string drive, string artifact, Func<IRawVolume> open, CancellationToken ct)
    {
        MftReader reader;
        try
        {
            reader = MftReader.Open(open());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or System.ComponentModel.Win32Exception)
        {
            await context.Writer.AddErrorAsync(new ModuleError($"{drive}: $MFT не открыт: {ex.Message}", ex.GetType().Name, artifact), ct).ConfigureAwait(false);
            await context.Writer.AddCoverageAsync(Coverage(context, artifact, CollectionStatus.Failed, 0,
                [new Limitation("MFT.UNAVAILABLE", $"$MFT тома {drive} не прочитан: {ex.Message}")]), ct).ConfigureAwait(false);
            return;
        }

        var serial = reader.Boot.VolumeSerial & 0xFFFF_FFFF;
        cache.SetSerial(drive, serial);
        var scope = new HistoryScope(options.UsersRoot, options.CurrentProfile, context.Permissions.Has(Capability.OtherUserProfiles), options.TempFolders, options.ExtraRoots);
        var index = new MftIndex(reader.RecordCount, drive);
        var candidates = new List<Candidate>();
        long parsed = 0, empty = 0, invalid = 0, torn = 0;
        foreach (var raw in reader.ReadRecords(ct))
        {
            var r = MftRecord.Parse(raw.Bytes.Span, raw.Entry);
            switch (r.State)
            {
                case MftRecordState.Empty:
                    empty++;
                    continue;
                case MftRecordState.Invalid:
                    invalid++;
                    continue;
            }

            parsed++;
            if (r.Entry == 0 && r.StandardInformation is { } mftInfo && NtfsTime.ToUtc(mftInfo.Times.Created) is { } formatted)
            {
                cache.SetFormatted(drive, formatted);
            }

            if (!r.FixupOk)
            {
                torn++;
            }

            index.Add(r);
            if (r.IsExtension || r.PrimaryName is not { } name || r.Entry < 24)
            {
                continue;
            }

            var relevantName = RelevantExtensions.Contains(Path.GetExtension(name.Name));
            if (r.InUse && (!relevantName || r.IsDirectory))
            {
                continue;
            }

            // Folders usually precede their contents in the table, so most records can be decided now and
            // dropped. Only those whose folders are not known yet are kept until the end of the pass.
            var early = index.Resolve(name.Parent, name.Name);
            if (!early.Quality.HasFlag(PathQuality.Broken) && Decide(r, relevantName, scope.Match(early.Path), early.Quality) == Decision.Skip)
            {
                continue;
            }

            candidates.Add(new Candidate(r, Sha256Hash.FromBytes(SHA256.HashData(raw.Bytes.Span)), relevantName));

            if (reader.Statistics.Records % 200_000 == 0)
            {
                context.Progress.Report(new ModuleProgress(Id, ModuleState.Running,
                    $"{drive}: прочитано записей MFT {reader.Statistics.Records.ToString("N0", Ru)} из {reader.RecordCount.ToString("N0", Ru)}"));
            }
        }

        cache.Set(drive, index);
        var finalScope = new HistoryScope(options.UsersRoot, options.CurrentProfile, context.Permissions.Has(Capability.OtherUserProfiles), options.TempFolders, options.ExtraRoots);
        long deletedRecorded = 0, liveRecorded = 0, anomalies = 0;
        foreach (var c in candidates)
        {
            ct.ThrowIfCancellationRequested();
            var r = c.Record;
            var name = r.PrimaryName!;
            var path = index.Resolve(name.Parent, name.Name);
            var match = finalScope.Match(path.Path);
            Evidence evidence;
            switch (Decide(r, c.RelevantName, match, path.Quality))
            {
                case Decision.Deleted:
                    evidence = Deleted(context, drive, artifact, serial, c, path, match);
                    deletedRecorded++;
                    break;
                case Decision.Live:
                    var anomaly = TimeAnomalies(r);
                    evidence = Live(context, drive, artifact, serial, c, path, match, anomaly);
                    liveRecorded++;
                    anomalies += anomaly.Count > 0 ? 1 : 0;
                    break;
                default:
                    continue;
            }

            await context.Writer.AddEvidenceAsync(evidence, ct).ConfigureAwait(false);
        }

        var limitations = new List<Limitation>
        {
            new("MFT.REUSE", "Запись удалённого файла существует, пока NTFS не отдаст её новому объекту. Отсутствие записи не значит, что файла не было."),
        };
        if (reader.Statistics.UnreadableBytes > 0)
        {
            limitations.Add(new Limitation("MFT.UNREADABLE", $"Не прочитано {reader.Statistics.UnreadableBytes.ToString("N0", Ru)} байт $MFT."));
        }

        if (reader.Problems.Count > 0)
        {
            limitations.Add(new Limitation("MFT.LAYOUT", string.Join(" ", reader.Problems)));
        }

        if (torn > 0)
        {
            limitations.Add(new Limitation("MFT.TORN", $"{torn} записей с несошедшейся проверкой секторов (запись прервана); их данные могут быть неполными."));
        }

        if (scope.ExcludedOtherProfiles + finalScope.ExcludedOtherProfiles > 0)
        {
            limitations.Add(new Limitation("SCOPE.OTHER_PROFILES", $"{(scope.ExcludedOtherProfiles + finalScope.ExcludedOtherProfiles).ToString("N0", Ru)} записей в профилях других пользователей пропущено: доступ к ним не подтверждён."));
        }

        var status = reader.Statistics.UnreadableBytes > 0 || reader.Problems.Count > 0 ? CollectionStatus.Partial : CollectionStatus.Collected;
        await context.Writer.AddCoverageAsync(Coverage(context, artifact, status, reader.Statistics.Records, limitations), ct).ConfigureAwait(false);
        context.Progress.Report(new ModuleProgress(Id, ModuleState.Running,
            $"{drive}: записей MFT {reader.Statistics.Records.ToString("N0", Ru)} (разобрано {parsed.ToString("N0", Ru)}, пустых {empty.ToString("N0", Ru)}, повреждённых {invalid.ToString("N0", Ru)}); " +
            $"записано удалённых {deletedRecorded.ToString("N0", Ru)}, существующих {liveRecorded.ToString("N0", Ru)}, из них с расхождением времени {anomalies.ToString("N0", Ru)}."));
    }

    private Evidence Deleted(AnalyzerContext context, string drive, string artifact, ulong serial, Candidate c, ResolvedPath path, ScopeMatch match)
    {
        var r = c.Record;
        var name = r.PrimaryName!;
        var attrs = CommonAttributes(r, match);
        attrs["Mft.State"] = "deleted";
        attrs["Mft.RecordSequence"] = r.Sequence.ToString(CultureInfo.InvariantCulture);
        var limitations = new List<Limitation>
        {
            new("MFT.DELETE_TIME_UNKNOWN", "MFT не хранит время удаления. Его может показать USN Journal, если запись об удалении ещё не вытеснена."),
        };
        AddPathLimitations(path, limitations);
        AddRecordLimitations(r, limitations);

        Sha256Hash? contentHash = null;
        if (r.MainData is { NonResident: false, ResidentValue: { } content })
        {
            contentHash = Sha256Hash.FromBytes(SHA256.HashData(content));
            attrs["Mft.Content"] = "resident";
            if (ContentSniffer.Detect(content, content.Length) is var type and not ContentType.Unknown)
            {
                attrs["Content"] = type.ToString();
            }
        }

        AddZone(r, attrs);
        var what = r.IsDirectory ? "Удалённая папка" : "Удалённый файл";
        var where = match.InMinecraftTree ? " в папке Minecraft" : match.InDropLocation ? " в месте загрузок" : string.Empty;
        return Build(context, drive, artifact, serial, c, path,
            EvidenceEventType.Deleted,
            timestamp: null,
            target: PreviousReference(r),
            contentHash,
            Confidence.Informational,
            "Запись MFT свободна: объект с этим именем и в этом месте существовал и был удалён. Когда — MFT не хранит. Само удаление файла не говорит о нарушении.",
            $"{what} {name.Name}{where}: {path.Path} (запись MFT {r.Entry}).",
            attrs,
            limitations);
    }

    private Evidence Live(AnalyzerContext context, string drive, string artifact, ulong serial, Candidate c, ResolvedPath path, ScopeMatch match, List<string> anomaly)
    {
        var r = c.Record;
        var name = r.PrimaryName!;
        var attrs = CommonAttributes(r, match);
        attrs["Mft.State"] = "live";
        var limitations = new List<Limitation>();
        AddPathLimitations(path, limitations);
        AddRecordLimitations(r, limitations);
        AddZone(r, attrs);

        string rationale;
        var confidence = Confidence.Informational;
        if (anomaly.Count > 0)
        {
            attrs["Mft.TimeAnomaly"] = string.Join(",", anomaly);
            confidence = Confidence.Low;
            rationale = "Время в $STANDARD_INFORMATION (его видят программы и его можно изменить) не согласуется со временем в $FILE_NAME (его ставит NTFS): " +
                        string.Join("; ", anomaly.Select(Explain)) +
                        ". Так бывает при подмене времени, но и при распаковке архива, копировании с сохранением дат и «туннелировании» NTFS (файл удалён и сразу создан с тем же именем). Это повод сверить с USN Journal, не вывод.";
        }
        else
        {
            rationale = "Существующий файл; время из $FILE_NAME ставит NTFS при создании, переименовании или перемещении имени, программы его обычно не меняют.";
        }

        var fnCreated = NtfsTime.ToUtc(name.Times.Created);
        return Build(context, drive, artifact, serial, c, path,
            EvidenceEventType.Existed,
            fnCreated is null ? null : new EvidenceTimestamp(fnCreated.Value, "$FN.Created", TimestampPrecision.HundredNanoseconds),
            target: new FileReference(r.Entry, r.Sequence),
            contentHash: null,
            confidence,
            rationale,
            $"Файл {name.Name}{(match.InMinecraftTree ? " в папке Minecraft" : match.InDropLocation ? " в месте загрузок" : string.Empty)}: {path.Path}" +
            (anomaly.Count > 0 ? " — время в двух атрибутах MFT расходится." : "."),
            attrs,
            limitations);
    }

    private enum Decision
    {
        Skip,
        Deleted,
        Live,
    }

    /// <summary>
    /// Deleted: an archive or executable anywhere in scope, or anything inside a Minecraft folder.
    /// Live (only archives and executables reach here): in a Minecraft folder or a download location, or with
    /// a time mismatch anywhere in scope. Everything else live is File Hunter's.
    /// </summary>
    private static Decision Decide(MftRecord r, bool relevantName, ScopeMatch match, PathQuality quality)
    {
        if (!match.InScope)
        {
            // Location unknown (a folder record was reused): a deleted Java archive or class is still worth
            // recording; deleted DLLs and executables of unknown location are mostly Windows updates.
            var unknownPlace = quality.HasFlag(PathQuality.ReusedAncestor) || quality.HasFlag(PathQuality.Broken);
            return unknownPlace && !r.InUse && MinecraftSpecific.Contains(Path.GetExtension(r.PrimaryName!.Name))
                ? Decision.Deleted
                : Decision.Skip;
        }

        if (!r.InUse)
        {
            return relevantName || match.InMinecraftTree ? Decision.Deleted : Decision.Skip;
        }

        return match.InMinecraftTree || match.InDropLocation || TimeAnomalies(r).Count > 0 ? Decision.Live : Decision.Skip;
    }

    /// <summary>Indicators of times set by a program rather than by NTFS. Each has innocent explanations.</summary>
    internal static List<string> TimeAnomalies(MftRecord r)
    {
        var list = new List<string>();
        if (r.StandardInformation is not { } si || r.PrimaryName is not { } fn)
        {
            return list;
        }

        // $SI.Created earlier than $FN.Created by more than a second.
        if (si.Times.Created > 0 && fn.Times.Created > 0 && fn.Times.Created - si.Times.Created > TimeSpan.TicksPerSecond)
        {
            list.Add("SI_CREATED_BEFORE_FN");
        }

        // Whole-second $SI.Created while $FN.Created has a fraction: tools that set times often write whole seconds.
        if (NtfsTime.HasZeroFraction(si.Times.Created) && !NtfsTime.HasZeroFraction(fn.Times.Created))
        {
            list.Add("SI_CREATED_WHOLE_SECOND");
        }

        return list;
    }

    private static string Explain(string code) => code switch
    {
        "SI_CREATED_BEFORE_FN" => "время создания в $STANDARD_INFORMATION раньше, чем в $FILE_NAME",
        "SI_CREATED_WHOLE_SECOND" => "время создания в $STANDARD_INFORMATION — ровно целая секунда, а в $FILE_NAME — нет",
        _ => code,
    };

    private static Dictionary<string, string> CommonAttributes(MftRecord r, ScopeMatch match)
    {
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Mft.Entry"] = r.Entry.ToString(CultureInfo.InvariantCulture),
            ["Mft.IsDirectory"] = r.IsDirectory ? "true" : "false",
        };
        if (match.MinecraftRoot is not null)
        {
            attrs["MinecraftRoot"] = match.MinecraftRoot;
        }

        if (match.Profile is not null)
        {
            attrs["Profile"] = match.Profile;
        }

        if (r.FileNames.Count > 1)
        {
            attrs["Mft.Names"] = string.Join(" | ", r.FileNames.Select(f => $"{f.Name} [{f.Namespace}] в {f.Parent}"));
        }

        var streams = r.Data.Where(d => d.Name.Length > 0).Select(d => d.Name).Distinct(StringComparer.Ordinal).ToList();
        if (streams.Count > 0)
        {
            attrs["Mft.Streams"] = string.Join(",", streams);
        }

        if (r.HasReparsePoint)
        {
            attrs["Mft.ReparsePoint"] = "true";
        }

        return attrs;
    }

    private static void AddZone(MftRecord r, Dictionary<string, string> attrs)
    {
        var zone = r.Data.FirstOrDefault(d => d.Name.Equals("Zone.Identifier", StringComparison.OrdinalIgnoreCase) && d.ResidentValue is not null);
        if (zone?.ResidentValue is null)
        {
            return;
        }

        if (ZoneInfo.Parse(zone.ResidentValue) is not { } info)
        {
            return;
        }

        if (info.ZoneId is { } id)
        {
            attrs["Zone.Id"] = id.ToString(CultureInfo.InvariantCulture);
        }

        if (info.HostUrl is { } host)
        {
            attrs["Zone.HostUrl"] = host;
        }

        if (info.ReferrerUrl is { } referrer)
        {
            attrs["Zone.ReferrerUrl"] = referrer;
        }
    }

    private static void AddPathLimitations(ResolvedPath path, List<Limitation> limitations)
    {
        if (path.Quality.HasFlag(PathQuality.ReusedAncestor))
        {
            limitations.Add(new Limitation("PATH.REUSED_ANCESTOR", "Запись одной из папок пути теперь принадлежит другому объекту: начало пути неизвестно и показано как «?»."));
        }

        if (path.Quality.HasFlag(PathQuality.DeletedAncestor))
        {
            limitations.Add(new Limitation("PATH.DELETED_ANCESTOR", "Одна из папок пути тоже удалена; её имя и место взяты из её свободной записи."));
        }

        if (path.Quality.HasFlag(PathQuality.Broken))
        {
            limitations.Add(new Limitation("PATH.BROKEN", "Путь восстановлен не полностью: запись папки отсутствует, повреждена или ссылается сама на себя."));
        }
    }

    private static void AddRecordLimitations(MftRecord r, List<Limitation> limitations)
    {
        if (!r.FixupOk)
        {
            limitations.Add(new Limitation("MFT.TORN", "Проверка секторов записи не сошлась: запись могла быть сохранена не полностью."));
        }

        if (r.HasRemnantAttributes)
        {
            limitations.Add(new Limitation("MFT.REMNANT", "Часть атрибутов лежит за занятым размером свободной записи — это остатки удалённого объекта."));
        }

        if (r.HasNonResidentAttributeList)
        {
            limitations.Add(new Limitation("MFT.ATTRIBUTE_LIST", "Список атрибутов хранится вне записи и не прочитан; часть потоков может быть не учтена."));
        }

        foreach (var p in r.Problems.Take(3))
        {
            limitations.Add(new Limitation("MFT.PARSE", p));
        }
    }

    /// <summary>
    /// The reference a deleted object had while it existed: NTFS increments the sequence when freeing a record.
    /// </summary>
    private static FileReference PreviousReference(MftRecord r) =>
        new(r.Entry, r.Sequence switch { 0 => 0, 1 => ushort.MaxValue, _ => (ushort)(r.Sequence - 1) });

    private Evidence Build(
        AnalyzerContext context,
        string drive,
        string artifact,
        ulong serial,
        Candidate c,
        ResolvedPath path,
        EvidenceEventType eventType,
        EvidenceTimestamp? timestamp,
        FileReference target,
        Sha256Hash? contentHash,
        Confidence confidence,
        string rationale,
        string description,
        Dictionary<string, string> attrs,
        List<Limitation> limitations)
    {
        var r = c.Record;
        var name = r.PrimaryName!;
        var complete = path.Quality is PathQuality.Complete or PathQuality.DeletedAncestor;
        return new Evidence
        {
            EvidenceId = context.NewEvidenceId(),
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = new SourceRef(EvidenceSourceKind.Mft, artifact, ParserName, ParserVersion),
            Locator = $"MFT {drive} запись {r.Entry}, sequence {r.Sequence}",
            EventType = eventType,
            Timestamp = timestamp,
            OtherTimestamps = Times(r, timestamp),
            Target = new ObjectRef
            {
                RecordedPath = path.Path,
                NormalizedPath = complete ? PathNormalizer.Normalize(path.Path) : null,
                FileName = name.Name,
                VolumeSerial = serial,
                MftEntry = target.Entry,
                MftSequence = target.Sequence,
                Size = r.IsDirectory ? null : r.MainData?.Size ?? name.RealSize,
            },
            ObjectSha256 = contentHash,
            ArtifactSha256 = c.RecordHash,
            Confidence = confidence,
            Rationale = rationale,
            CollectionStatus = limitations.Any(l => l.Code.StartsWith("PATH.", StringComparison.Ordinal) || l.Code is "MFT.TORN" or "MFT.PARSE")
                ? CollectionStatus.Partial
                : CollectionStatus.Collected,
            Description = description,
            Limitations = limitations,
            Attributes = attrs,
            CollectedAtUtc = context.Time.GetUtcNow(),
        };
    }

    private static List<EvidenceTimestamp> Times(MftRecord r, EvidenceTimestamp? main)
    {
        var list = new List<EvidenceTimestamp>();
        void Add(long value, string field)
        {
            if (NtfsTime.ToUtc(value) is { } t && field != main?.Field)
            {
                list.Add(new EvidenceTimestamp(t, field, TimestampPrecision.HundredNanoseconds));
            }
        }

        if (r.StandardInformation is { } si)
        {
            Add(si.Times.Created, "$SI.Created");
            Add(si.Times.Modified, "$SI.Modified");
            Add(si.Times.MftModified, "$SI.MftModified");
            Add(si.Times.Accessed, "$SI.Accessed");
        }

        if (r.PrimaryName is { } fn)
        {
            Add(fn.Times.Created, "$FN.Created");
            Add(fn.Times.Modified, "$FN.Modified");
            Add(fn.Times.MftModified, "$FN.MftModified");
            Add(fn.Times.Accessed, "$FN.Accessed");
        }

        return list;
    }

    private SourceCoverage Coverage(AnalyzerContext context, string artifact, CollectionStatus status, long items, List<Limitation> limitations) => new()
    {
        InvestigationId = context.InvestigationId,
        ModuleId = Id,
        Source = EvidenceSourceKind.Mft,
        Scope = artifact,
        Status = status,
        ItemsRead = items,
        Limitations = limitations,
    };
}
