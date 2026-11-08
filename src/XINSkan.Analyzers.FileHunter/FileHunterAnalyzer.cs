using System.Globalization;
using System.Security.Cryptography;
using System.Threading.Channels;
using XINSkan.Analyzers.FileHunter.Content;
using XINSkan.Analyzers.FileHunter.Scanning;
using XINSkan.Core.IO;
using XINSkan.Core.Paths;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;

namespace XINSkan.Analyzers.FileHunter;

public sealed record FileHunterOptions
{
    public required string UsersRoot { get; init; }

    public required string CurrentProfile { get; init; }

    public IReadOnlyList<string> TempFolders { get; init; } = [];

    public IReadOnlyList<string> ExtraRoots { get; init; } = [];

    /// <summary>Files larger than this are recorded without a hash (stated as a limitation).</summary>
    public long MaxHashBytes { get; init; } = 256L * 1024 * 1024;

    public ArchiveLimits Archive { get; init; } = new();

    public int Workers { get; init; } = Math.Clamp(Environment.ProcessorCount / 2, 1, 4);

    /// <summary>At most this many individual errors are written; the rest are counted in coverage.</summary>
    public int MaxReportedErrors { get; init; } = 50;

    /// <summary>Default scope for the machine XIN SKAN runs on.</summary>
    public static FileHunterOptions ForCurrentSystem(IReadOnlyList<string>? extraRoots = null)
    {
        var drive = (Environment.GetEnvironmentVariable("SystemDrive") ?? "C:")[..2];
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return new FileHunterOptions
        {
            UsersRoot = drive + @"\Users",
            CurrentProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            TempFolders = string.IsNullOrEmpty(windows) ? [] : [Path.Combine(windows, "Temp")],
            ExtraRoots = extraRoots ?? [],
        };
    }
}

/// <summary>
/// File Hunter: records existing files and folders that can matter for a Minecraft check, with their content
/// type, SHA-256, NTFS identity, embedded metadata, signature status and download origin.
/// Existence alone is never treated as a violation: every record is Informational.
/// </summary>
public sealed class FileHunterAnalyzer : IAnalyzer
{
    public const string ModuleId = "file-hunter";
    private const string ParserName = "xinskan-file-hunter";
    private const string ParserVersion = "1";

    private static readonly Limitation TimesLimitation = new(
        "FS.SI_TIMES",
        "Время взято из файловой системы ($STANDARD_INFORMATION) и может быть изменено программно; сверка с $FILE_NAME выполняется в History Engine.");

    private readonly FileHunterOptions _options;
    private readonly IDirectoryLister _lister;
    private readonly IFileSource _files;
    private readonly ISignatureVerifier _signatures;

    public FileHunterAnalyzer(FileHunterOptions options, IDirectoryLister lister, IFileSource files, ISignatureVerifier signatures)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _lister = lister ?? throw new ArgumentNullException(nameof(lister));
        _files = files ?? throw new ArgumentNullException(nameof(files));
        _signatures = signatures ?? throw new ArgumentNullException(nameof(signatures));
    }

    public string Id => ModuleId;

    public string DisplayName => "File Hunter";

    public AnalyzerRequirements Requirements { get; } = new()
    {
        OptionalCapabilities = [Capability.Administrator, Capability.OtherUserProfiles],
    };

    private sealed record WorkItem(FsEntry Entry, Selection Selection, string? MinecraftRoot, ScopeRoot Root);

    private sealed class RootCounters
    {
        public long Entries;
        public long Directories;
        public long Inaccessible;
        public long LinksNotFollowed;
        public long Selected;
    }

    public async Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var scope = ScopeBuilder.Build(
            _lister,
            _options.UsersRoot,
            _options.CurrentProfile,
            context.Permissions.Has(Capability.OtherUserProfiles),
            _options.TempFolders,
            _options.ExtraRoots);

        await context.Writer.AddCoverageAsync(new SourceCoverage
        {
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = EvidenceSourceKind.FileSystem,
            Scope = "Область поиска: " + string.Join("; ", scope.Roots.Select(r => r.Path)),
            Status = scope.Excluded.Count == 0 ? CollectionStatus.Collected : CollectionStatus.Partial,
            ItemsRead = scope.Roots.Count,
            Limitations = scope.Excluded.Select(x => new Limitation("SCOPE.EXCLUDED", x)).ToList(),
        }, cancellationToken).ConfigureAwait(false);

        var errorsReported = 0;
        var errorLock = new Lock();
        async ValueTask ReportError(string message, Exception? ex, string location)
        {
            bool write;
            lock (errorLock)
            {
                write = errorsReported++ < _options.MaxReportedErrors;
            }

            if (write)
            {
                await context.Writer.AddErrorAsync(new ModuleError(message, ex?.GetType().Name, location), cancellationToken).ConfigureAwait(false);
            }
        }

        var channel = Channel.CreateBounded<WorkItem>(new BoundedChannelOptions(1024) { SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
        var counters = scope.Roots.ToDictionary(r => r, _ => new RootCounters());

        // A failing consumer must stop the walker, or the walker would wait forever on a full channel.
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var producer = Task.Run(
            async () =>
            {
                try
                {
                    foreach (var root in scope.Roots)
                    {
                        await WalkAsync(root, counters[root], channel.Writer, context, ReportError, linked.Token).ConfigureAwait(false);
                    }
                }
                finally
                {
                    channel.Writer.TryComplete();
                }
            },
            linked.Token);

        var consumers = Parallel.ForEachAsync(
            channel.Reader.ReadAllAsync(linked.Token),
            new ParallelOptions { MaxDegreeOfParallelism = _options.Workers, CancellationToken = linked.Token },
            async (item, ct) =>
            {
                var evidence = Process(item, context);
                if (evidence is not null)
                {
                    Interlocked.Increment(ref counters[item.Root].Selected);
                    await context.Writer.AddEvidenceAsync(evidence, ct).ConfigureAwait(false);
                }
            });

        Exception? consumerFailure = null;
        try
        {
            await consumers.ConfigureAwait(false);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            consumerFailure = ex;
            await linked.CancelAsync().ConfigureAwait(false);
        }

        try
        {
            await producer.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (consumerFailure is not null)
        {
            // Stopped because a consumer failed; that failure is rethrown below.
        }

        if (consumerFailure is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw(consumerFailure);
        }

        foreach (var (root, c) in counters)
        {
            var limitations = new List<Limitation>();
            if (c.Inaccessible > 0)
            {
                limitations.Add(new Limitation("FS.INACCESSIBLE", $"{c.Inaccessible} папок не удалось прочитать; их содержимое не проверено."));
            }

            if (c.LinksNotFollowed > 0)
            {
                limitations.Add(new Limitation("FS.LINKS", $"{c.LinksNotFollowed} ссылок на другие папки (junction, symlink) не пройдены, чтобы не проверять одно место дважды и не уходить из области поиска."));
            }

            await context.Writer.AddCoverageAsync(new SourceCoverage
            {
                InvestigationId = context.InvestigationId,
                ModuleId = Id,
                Source = EvidenceSourceKind.FileSystem,
                Scope = root.Path,
                Status = limitations.Count == 0 ? CollectionStatus.Collected : CollectionStatus.Partial,
                ItemsRead = c.Entries,
                Limitations = limitations,
            }, cancellationToken).ConfigureAwait(false);
        }

        if (errorsReported > _options.MaxReportedErrors)
        {
            await context.Writer.AddErrorAsync(
                new ModuleError($"Ещё {errorsReported - _options.MaxReportedErrors} ошибок доступа не записаны по отдельности; их число учтено в покрытии."),
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WalkAsync(
        ScopeRoot root,
        RootCounters c,
        ChannelWriter<WorkItem> writer,
        AnalyzerContext context,
        Func<string, Exception?, string, ValueTask> reportError,
        CancellationToken ct)
    {
        var stack = new Stack<(string Dir, string? Minecraft)>();
        stack.Push((root.Path, null));
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (dir, minecraft) = stack.Pop();

            IReadOnlyList<FsEntry> entries;
            try
            {
                entries = _lister.List(dir);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
            {
                c.Inaccessible++;
                await reportError($"Папку не удалось прочитать: {ex.Message}", ex, dir).ConfigureAwait(false);
                continue;
            }

            c.Directories++;
            if (minecraft is null && Relevance.IsMinecraftRoot(Path.GetFileName(dir.TrimEnd('\\', '/')), entries))
            {
                minecraft = dir;
            }

            var drop = Relevance.IsDropLocation(root, dir);
            foreach (var e in entries)
            {
                c.Entries++;
                if (c.Entries % 5000 == 0)
                {
                    context.Progress.Report(new ModuleProgress(Id, ModuleState.Running, $"Просмотрено объектов: {c.Entries.ToString("N0", CultureInfo.GetCultureInfo("ru-RU"))} — {dir}"));
                }

                if (e.IsDirectory)
                {
                    var childMinecraft = minecraft;
                    if (childMinecraft is null && e.Name.Equals(".minecraft", StringComparison.OrdinalIgnoreCase))
                    {
                        childMinecraft = e.FullPath;
                    }

                    if (childMinecraft is not null)
                    {
                        await writer.WriteAsync(new WorkItem(e, Selection.MinecraftTree, childMinecraft, root), ct).ConfigureAwait(false);
                    }

                    if (e.IsReparsePoint)
                    {
                        c.LinksNotFollowed++;
                        continue;
                    }

                    stack.Push((e.FullPath, childMinecraft));
                    continue;
                }

                Selection? selection = minecraft is not null ? Selection.MinecraftTree
                    : Relevance.IsExecutableOrArchiveByName(e.Name) ? Selection.ExecutableOrArchive
                    : drop ? Selection.DropLocationContent
                    : null;

                if (selection is not null)
                {
                    await writer.WriteAsync(new WorkItem(e, selection.Value, minecraft, root), ct).ConfigureAwait(false);
                }
            }
        }
    }

    /// <summary>Builds the evidence for one entry; null when a drop-location file turns out to be ordinary content.</summary>
    private Evidence? Process(WorkItem item, AnalyzerContext context)
    {
        var e = item.Entry;
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Selection"] = item.Selection.ToString(),
        };
        var limitations = new List<Limitation> { TimesLimitation };
        if (item.MinecraftRoot is not null)
        {
            attrs["MinecraftRoot"] = item.MinecraftRoot;
        }

        if (e.IsHidden || e.IsSystem || e.IsReparsePoint)
        {
            attrs["FileAttributes"] = e.Attributes.ToString();
        }

        if (e.IsDirectory)
        {
            return Build(context, e, item, attrs, limitations, null, null, CollectionStatus.Collected,
                e.IsReparsePoint ? $"Ссылка на папку в каталоге Minecraft: {e.Name} (не пройдена)." : $"Папка в каталоге Minecraft: {e.Name}.");
        }

        if (e.IsReparsePoint)
        {
            limitations.Add(new Limitation("LINK.NOT_FOLLOWED", "Файл является ссылкой; его содержимое не читалось, чтобы не выйти за область поиска."));
            return Build(context, e, item, attrs, limitations, null, null, CollectionStatus.Partial, $"Ссылка на файл: {e.Name}.");
        }

        IOpenedFile opened;
        try
        {
            opened = _files.Open(e.FullPath);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            if (item.Selection == Selection.DropLocationContent)
            {
                // Its content was the only reason to look at it; without content there is nothing to record.
                return null;
            }

            limitations.Add(new Limitation(ex is UnauthorizedAccessException ? "CONTENT.ACCESS_DENIED" : "CONTENT.UNREADABLE",
                $"Содержимое не прочитано: {ex.Message}"));
            return Build(context, e, item, attrs, limitations, null, null, CollectionStatus.Partial, Describe(e, ContentType.Unknown, null, null, false));
        }

        using (opened)
        {
            var stream = opened.Content;
            var header = new byte[ContentSniffer.HeaderSize];
            var headerLength = stream.ReadAtLeast(header, header.Length, throwOnEndOfStream: false);
            var content = ContentSniffer.Detect(header.AsSpan(0, headerLength), e.Length);
            if (item.Selection == Selection.DropLocationContent && content is not (ContentType.Zip or ContentType.PortableExecutable or ContentType.JavaClass))
            {
                return null;
            }

            attrs["Content"] = content.ToString();
            var implied = ContentSniffer.ImpliedBy(Path.GetExtension(e.Name));
            var mismatch = content is ContentType.Zip or ContentType.PortableExecutable or ContentType.JavaClass && implied != content;
            if (mismatch)
            {
                attrs["ExtensionMismatch"] = "true";
            }

            Sha256Hash? hash = null;
            var status = CollectionStatus.Collected;
            if (e.Length <= _options.MaxHashBytes)
            {
                stream.Position = 0;
                hash = Sha256Hash.FromBytes(SHA256.HashData(stream));
                if (stream.Length != e.Length)
                {
                    limitations.Add(new Limitation("CONTENT.CHANGING", $"Размер файла изменился во время проверки ({e.Length} → {stream.Length} байт); хеш относится к прочитанному содержимому."));
                }
            }
            else
            {
                status = CollectionStatus.Partial;
                limitations.Add(new Limitation("HASH.SIZE_LIMIT", $"Файл больше {_options.MaxHashBytes / (1024 * 1024)} МБ; хеш не вычислялся."));
            }

            ArchiveFacts? archive = null;
            PeFacts? pe = null;
            if (content == ContentType.Zip)
            {
                archive = ArchiveInspector.Inspect(stream, _options.Archive);
                AddArchiveAttributes(attrs, archive);
                if (archive.Problems.Count > 0)
                {
                    status = CollectionStatus.Partial;
                    limitations.Add(new Limitation("ARCHIVE.PARTIAL", "Архив прочитан не полностью: " + string.Join(" ", archive.Problems.Take(3))));
                }
            }
            else if (content == ContentType.PortableExecutable)
            {
                pe = PeInspector.Inspect(stream);
                AddPeAttributes(attrs, pe);
                if (pe.Problems.Count > 0)
                {
                    limitations.Add(new Limitation("PE.PARTIAL", string.Join(" ", pe.Problems)));
                }

                var signature = pe.HasEmbeddedSignature
                    ? VerifySignature(e.FullPath)
                    : new SignatureResult(SignatureStatus.NotSigned, "Встроенной подписи нет (таблица сертификатов пуста).");
                attrs["Signature"] = signature.Status.ToString();
                attrs["SignatureDetail"] = signature.Detail;
            }

            AddZoneAttributes(attrs, e.FullPath, limitations);

            return Build(context, e, item, attrs, limitations, opened.Identity, hash, status, Describe(e, content, archive, pe, mismatch));
        }
    }

    private SignatureResult VerifySignature(string path)
    {
        try
        {
            return _signatures.Verify(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new SignatureResult(SignatureStatus.Error, ex.Message);
        }
    }

    private void AddZoneAttributes(Dictionary<string, string> attrs, string path, List<Limitation> limitations)
    {
        try
        {
            using var zone = _files.TryOpenStream(path, "Zone.Identifier");
            if (zone is null)
            {
                return;
            }

            var buffer = new byte[ZoneInfo.MaxBytes];
            var n = zone.Content.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
            var info = ZoneInfo.Parse(buffer.AsSpan(0, n));
            if (info is null)
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
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            limitations.Add(new Limitation("ZONE.UNREADABLE", $"Отметка источника загрузки (Zone.Identifier) не прочитана: {ex.Message}"));
        }
    }

    private static void AddArchiveAttributes(Dictionary<string, string> attrs, ArchiveFacts a)
    {
        attrs["Archive.Entries"] = a.DeclaredEntries.ToString(CultureInfo.InvariantCulture);
        attrs["Archive.Classes"] = a.ClassCount.ToString(CultureInfo.InvariantCulture);
        if (a.TopPackages.Count > 0)
        {
            attrs["Jar.TopPackages"] = string.Join(", ", a.TopPackages);
        }

        for (var i = 0; i < a.Mods.Count && i < 5; i++)
        {
            var m = a.Mods[i];
            var p = i == 0 ? "Mod" : $"Mod{i + 1}";
            attrs[p + ".Loader"] = m.Loader;
            if (m.Id is not null)
            {
                attrs[p + ".Id"] = m.Id;
            }

            if (m.Name is not null)
            {
                attrs[p + ".Name"] = m.Name;
            }

            if (m.Version is not null)
            {
                attrs[p + ".Version"] = m.Version;
            }
        }

        if (a.Manifest is not null)
        {
            foreach (var (k, v) in a.Manifest)
            {
                attrs["Manifest." + k] = v;
            }
        }

        if (a.NestedJars.Count > 0)
        {
            attrs["Jar.Nested"] = string.Join(", ", a.NestedJars.Take(20));
        }

        if (a.NestedMods.Count > 0)
        {
            attrs["Jar.NestedMods"] = string.Join(", ", a.NestedMods.Take(20).Select(m => $"{m.Loader}:{m.Id ?? "?"}"));
        }
    }

    private static void AddPeAttributes(Dictionary<string, string> attrs, PeFacts pe)
    {
        if (pe.Machine is not null)
        {
            attrs["Pe.Machine"] = pe.Machine;
        }

        attrs["Pe.Kind"] = pe.IsDll ? "DLL" : "EXE";
        if (pe.IsDotNet)
        {
            attrs["Pe.DotNet"] = "true";
        }

        if (pe.FixedFileVersion is not null)
        {
            attrs["Pe.FileVersion"] = pe.FixedFileVersion;
        }

        foreach (var (k, v) in pe.Version)
        {
            attrs["Pe." + k] = v;
        }
    }

    private static string Describe(FsEntry e, ContentType content, ArchiveFacts? archive, PeFacts? pe, bool mismatch)
    {
        var kind = content switch
        {
            ContentType.Zip when archive is { IsJavaArchive: true } => "Java-архив (JAR)",
            ContentType.Zip => "ZIP-архив",
            ContentType.PortableExecutable => pe is { IsDll: true } ? "библиотека Windows (DLL)" : "программа Windows (EXE)",
            ContentType.JavaClass => "класс Java",
            ContentType.Empty => "пустой файл",
            _ => "файл",
        };

        var text = $"{kind} {e.Name}, {FormatSize(e.Length)}";
        if (archive?.Mods.Count > 0)
        {
            var m = archive.Mods[0];
            text += $"; мод {LoaderName(m.Loader)} «{m.Name ?? m.Id ?? "без имени"}»" + (m.Version is null ? string.Empty : $" версии {m.Version}");
        }

        if (archive?.Manifest is { } mf && (mf.ContainsKey("Premain-Class") || mf.ContainsKey("Agent-Class") || mf.ContainsKey("Launcher-Agent-Class")))
        {
            text += "; объявлен как Java-агент (может подключаться к запущенной JVM)";
        }

        if (pe?.Version.TryGetValue("OriginalFilename", out var original) == true
            && !string.Equals(original, e.Name, StringComparison.OrdinalIgnoreCase))
        {
            text += $"; исходное имя по ресурсу версии — {original}";
        }

        if (mismatch)
        {
            text += $"; содержимое не соответствует расширению «{Path.GetExtension(e.Name)}»";
        }

        return text + ".";
    }

    private static string LoaderName(string loader) => loader switch
    {
        "fabric" => "Fabric",
        "quilt" => "Quilt",
        "forge" => "Forge",
        "neoforge" => "NeoForge",
        "forge-legacy" => "Forge (старый формат)",
        _ => loader,
    };

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} Б",
        < 1024 * 1024 => (bytes / 1024.0).ToString("0.#", CultureInfo.GetCultureInfo("ru-RU")) + " КБ",
        _ => (bytes / (1024.0 * 1024)).ToString("0.#", CultureInfo.GetCultureInfo("ru-RU")) + " МБ",
    };

    private static string Rationale(Selection s) => s switch
    {
        Selection.MinecraftTree => "Объект находится в каталоге Minecraft и записан полностью. Наличие файла или папки само по себе не означает использования или нарушения; запись нужна для сопоставления с историей и сигнатурами.",
        Selection.ExecutableOrArchive => "Архив или исполняемый файл в области поиска. Наличие файла само по себе ничего не доказывает; хеш, метаданные и идентификатор записи MFT сохранены для сопоставления.",
        _ => "Файл в месте, куда обычно попадают загрузки, и по содержимому является архивом или исполняемым файлом. Наличие файла само по себе ничего не доказывает.",
    };

    private Evidence Build(
        AnalyzerContext context,
        FsEntry e,
        WorkItem item,
        Dictionary<string, string> attrs,
        List<Limitation> limitations,
        FileIdentity? identity,
        Sha256Hash? hash,
        CollectionStatus status,
        string description)
    {
        var others = new List<EvidenceTimestamp>();
        if (Utc(e.CreationTimeUtc) is { } created)
        {
            others.Add(new EvidenceTimestamp(created, "FileSystem.Created", TimestampPrecision.HundredNanoseconds));
        }

        if (Utc(e.LastAccessTimeUtc) is { } accessed)
        {
            others.Add(new EvidenceTimestamp(accessed, "FileSystem.LastAccess", TimestampPrecision.HundredNanoseconds));
        }

        var written = Utc(e.LastWriteTimeUtc);
        return new Evidence
        {
            EvidenceId = context.NewEvidenceId(),
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = new SourceRef(EvidenceSourceKind.FileSystem, e.FullPath, ParserName, ParserVersion),
            Locator = e.FullPath,
            EventType = EvidenceEventType.Existed,
            Timestamp = written is null ? null : new EvidenceTimestamp(written.Value, "FileSystem.LastWrite", TimestampPrecision.HundredNanoseconds),
            OtherTimestamps = others,
            Target = new ObjectRef
            {
                RecordedPath = e.FullPath,
                NormalizedPath = PathNormalizer.Normalize(e.FullPath),
                FileName = e.Name,
                VolumeSerial = identity?.VolumeSerial,
                MftEntry = identity?.MftEntry,
                MftSequence = identity?.MftSequence,
                Size = e.IsDirectory ? null : e.Length,
            },
            ObjectSha256 = hash,
            Confidence = Confidence.Informational,
            Rationale = Rationale(item.Selection),
            CollectionStatus = status,
            Description = description,
            Limitations = limitations,
            Attributes = attrs,
            CollectedAtUtc = context.Time.GetUtcNow(),
        };
    }

    /// <summary>Timestamps before 1980 are file-system placeholders (FILETIME 0 is 1601), not real times.</summary>
    private static DateTimeOffset? Utc(DateTime t) =>
        t.Year < 1980 ? null : new DateTimeOffset(DateTime.SpecifyKind(t, DateTimeKind.Utc));
}
