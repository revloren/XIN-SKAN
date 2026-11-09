using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using XINSkan.Analyzers.FileHunter.Scanning;
using XINSkan.Core.IO;
using XINSkan.Core.Paths;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;

namespace XINSkan.Analyzers.History;

/// <summary>What one game log says about one launch. Only facts printed by the game or the mod loader.</summary>
public sealed class MinecraftLogFacts
{
    public string? GameVersion { get; set; }

    public string? Loader { get; set; }

    public string? LoaderVersion { get; set; }

    /// <summary>Mods the loader listed as loaded (id, version, nested inside another mod).</summary>
    public List<(string Id, string Version, bool Nested)> Mods { get; } = [];

    /// <summary>Mod files the loader reported finding (Forge/NeoForge).</summary>
    public List<string> ModFiles { get; } = [];

    public string? User { get; set; }

    public List<string> Servers { get; } = [];

    /// <summary>Time of the first and last line, as printed (local time of the game).</summary>
    public TimeSpan? FirstTime { get; set; }

    public TimeSpan? LastTime { get; set; }

    /// <summary>Date printed in lines (Forge/NeoForge format); vanilla and Fabric print only the time.</summary>
    public DateOnly? PrintedDate { get; set; }

    public int Lines { get; set; }

    public bool Truncated { get; set; }
}

/// <summary>Parses latest.log / debug.log / *.log.gz of vanilla, Fabric, Quilt, Forge and NeoForge.</summary>
public static partial class MinecraftLogParser
{
    public const int MaxLines = 400_000;
    public const int MaxMods = 2_000;

    [GeneratedRegex(@"^\[(\d{2}):(\d{2}):(\d{2})\]")]
    private static partial Regex VanillaTime();

    [GeneratedRegex(@"^\[(\d{2})([A-Za-z]{3})(\d{4}) (\d{2}):(\d{2}):(\d{2})")]
    private static partial Regex ForgeTime();

    [GeneratedRegex(@"Loading Minecraft (\S+) with (Fabric|Quilt) Loader (\S+)")]
    private static partial Regex FabricStart();

    [GeneratedRegex(@"Loading (\d+) mods:")]
    private static partial Regex ModCount();

    [GeneratedRegex(@"^\s*(?:-|\|--|\\--)\s+(\S+)\s+(\S+)\s*$")]
    private static partial Regex FabricModLine();

    [GeneratedRegex(@"^\s+(?:\||\\)?\s*(?:\|--|\\--)\s+(\S+)\s+(\S+)\s*$")]
    private static partial Regex FabricNestedLine();

    [GeneratedRegex(@"--fml\.(neoForgeVersion|forgeVersion),\s*([^,\]\s]+)")]
    private static partial Regex ForgeVersionArg();

    [GeneratedRegex(@"--fml\.mcVersion,\s*([^,\]\s]+)")]
    private static partial Regex ForgeMcArg();

    [GeneratedRegex(@"Forge mod loading, version (\S+), for MC (\S+)")]
    private static partial Regex OldForge();

    [GeneratedRegex(@"Found mod file ""?([^""\s]+\.jar)""? of type MOD")]
    private static partial Regex ForgeModFile();

    [GeneratedRegex(@"Setting user: (\S+)")]
    private static partial Regex User();

    [GeneratedRegex(@"Connecting to ([^\s,]+),\s*(\d+)")]
    private static partial Regex Connect();

    public static MinecraftLogFacts Parse(TextReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var f = new MinecraftLogFacts();
        var inModList = false;
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (++f.Lines > MaxLines)
            {
                f.Truncated = true;
                break;
            }

            if (VanillaTime().Match(line) is { Success: true } vt)
            {
                var t = new TimeSpan(int.Parse(vt.Groups[1].ValueSpan, CultureInfo.InvariantCulture), int.Parse(vt.Groups[2].ValueSpan, CultureInfo.InvariantCulture), int.Parse(vt.Groups[3].ValueSpan, CultureInfo.InvariantCulture));
                f.FirstTime ??= t;
                f.LastTime = t;
                inModList = false;
            }
            else if (ForgeTime().Match(line) is { Success: true } ft)
            {
                if (DateOnly.TryParseExact($"{ft.Groups[1].Value}{ft.Groups[2].Value}{ft.Groups[3].Value}", "ddMMMyyyy", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d))
                {
                    f.PrintedDate ??= d;
                }

                var t = new TimeSpan(int.Parse(ft.Groups[4].ValueSpan, CultureInfo.InvariantCulture), int.Parse(ft.Groups[5].ValueSpan, CultureInfo.InvariantCulture), int.Parse(ft.Groups[6].ValueSpan, CultureInfo.InvariantCulture));
                f.FirstTime ??= t;
                f.LastTime = t;
                inModList = false;
            }
            else if (inModList && f.Mods.Count < MaxMods)
            {
                // Fabric/Quilt list mods on the lines that follow, without a timestamp.
                if (FabricNestedLine().Match(line) is { Success: true } nested)
                {
                    f.Mods.Add((nested.Groups[1].Value, nested.Groups[2].Value, true));
                    continue;
                }

                if (FabricModLine().Match(line) is { Success: true } mod)
                {
                    f.Mods.Add((mod.Groups[1].Value, mod.Groups[2].Value, false));
                    continue;
                }

                inModList = false;
            }

            if (FabricStart().Match(line) is { Success: true } fs)
            {
                f.GameVersion = fs.Groups[1].Value;
                f.Loader = fs.Groups[2].Value.ToLowerInvariant();
                f.LoaderVersion = fs.Groups[3].Value;
            }

            if (ModCount().IsMatch(line))
            {
                inModList = true;
            }

            if (ForgeVersionArg().Match(line) is { Success: true } fv)
            {
                f.Loader = fv.Groups[1].Value == "neoForgeVersion" ? "neoforge" : "forge";
                f.LoaderVersion = fv.Groups[2].Value;
                if (ForgeMcArg().Match(line) is { Success: true } mc)
                {
                    f.GameVersion = mc.Groups[1].Value;
                }
            }

            if (OldForge().Match(line) is { Success: true } of)
            {
                f.Loader = "forge";
                f.LoaderVersion = of.Groups[1].Value;
                f.GameVersion = of.Groups[2].Value;
            }

            if (ForgeModFile().Match(line) is { Success: true } mf && f.ModFiles.Count < MaxMods)
            {
                f.ModFiles.Add(mf.Groups[1].Value);
            }

            if (User().Match(line) is { Success: true } u)
            {
                f.User = u.Groups[1].Value;
            }

            if (Connect().Match(line) is { Success: true } c)
            {
                var server = $"{c.Groups[1].Value}:{c.Groups[2].Value}";
                if (!f.Servers.Contains(server, StringComparer.OrdinalIgnoreCase))
                {
                    f.Servers.Add(server);
                }
            }
        }

        return f;
    }

    /// <summary>The date a rotated log belongs to, from its name ("2026-11-08-1.log.gz").</summary>
    public static DateOnly? DateFromName(string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        return fileName.Length >= 10 && DateOnly.TryParseExact(fileName[..10], "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : null;
    }
}

/// <summary>
/// Reads the logs of every Minecraft game folder in the checked area: which game version and mod loader were
/// started, which mods the loader listed as loaded, which account, which servers — per launch, with time.
/// </summary>
/// <remarks>
/// A log is written by the game, so a mod listed as loaded is evidence that the mod was loaded in that
/// launch (EventType Loaded). Logs are plain text: they can be edited or deleted, which is stated.
/// </remarks>
public sealed class MinecraftLogsAnalyzer(HistoryOptions options, IDirectoryLister lister, IFileSource files, TimeZoneInfo machineZone) : IAnalyzer
{
    public const string ModuleId = "minecraft-logs";
    private const string ParserName = "xinskan-minecraft-log";
    private const string ParserVersion = "1";
    private const long MaxDecompressed = 64L * 1024 * 1024;
    private const int MaxDepth = 12;

    public string Id => ModuleId;

    public string DisplayName => "Логи Minecraft";

    public AnalyzerRequirements Requirements { get; } = new()
    {
        OptionalCapabilities = [Capability.OtherUserProfiles],
    };

    public async Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var roots = new List<string> { options.CurrentProfile };
        if (context.Permissions.Has(Capability.OtherUserProfiles))
        {
            roots.AddRange(OtherProfiles());
        }

        roots.AddRange(options.ExtraRoots);
        var games = new List<string>();
        foreach (var root in roots.Where(lister.DirectoryExists).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            FindGameFolders(root, games, cancellationToken);
        }

        long logs = 0, unreadable = 0;
        foreach (var game in games.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var logDir = Path.Combine(game, "logs");
            if (!lister.DirectoryExists(logDir))
            {
                continue;
            }

            IReadOnlyList<FsEntry> entries;
            try
            {
                entries = lister.List(logDir);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                await context.Writer.AddErrorAsync(new ModuleError($"{logDir}: {ex.Message}", ex.GetType().Name, logDir), cancellationToken).ConfigureAwait(false);
                continue;
            }

            foreach (var log in entries.Where(e => !e.IsDirectory && IsLog(e.Name)).OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                logs++;
                var (facts, problem) = Read(log);
                if (facts is null)
                {
                    unreadable++;
                    await context.Writer.AddErrorAsync(new ModuleError($"{log.FullPath}: {problem}", null, log.FullPath), cancellationToken).ConfigureAwait(false);
                    continue;
                }

                if (facts.Lines == 0)
                {
                    continue;
                }

                await context.Writer.AddEvidenceAsync(Build(context, game, log, facts), cancellationToken).ConfigureAwait(false);
            }
        }

        var limitations = new List<Limitation>
        {
            new("LOG.EDITABLE", "Логи — обычные текстовые файлы: их можно удалить или изменить. Отсутствие лога ничего не доказывает; Minecraft хранит архив логов за ограниченный срок."),
        };
        if (unreadable > 0)
        {
            limitations.Add(new Limitation("LOG.UNREADABLE", $"{unreadable} логов не прочитано."));
        }

        await context.Writer.AddCoverageAsync(new SourceCoverage
        {
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = EvidenceSourceKind.MinecraftLog,
            Scope = games.Count == 0 ? "Папки Minecraft не найдены" : "Папки Minecraft: " + string.Join("; ", games),
            Status = unreadable > 0 ? CollectionStatus.Partial : CollectionStatus.Collected,
            ItemsRead = logs,
            Limitations = limitations,
        }, cancellationToken).ConfigureAwait(false);
    }

    private IEnumerable<string> OtherProfiles()
    {
        IReadOnlyList<FsEntry> profiles;
        try
        {
            profiles = lister.List(options.UsersRoot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        foreach (var p in profiles.Where(p => p.IsDirectory && !p.IsReparsePoint && !ScopeBuilder.IsSystemProfile(p.Name)))
        {
            yield return p.FullPath;
        }
    }

    private void FindGameFolders(string root, List<string> found, CancellationToken ct)
    {
        var stack = new Stack<(string Dir, int Depth)>();
        stack.Push((root, 0));
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (dir, depth) = stack.Pop();
            IReadOnlyList<FsEntry> children;
            try
            {
                children = lister.List(dir);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            if (Relevance.IsMinecraftRoot(Path.GetFileName(dir.TrimEnd('\\', '/')), children))
            {
                found.Add(dir);
                continue; // a game folder's own subfolders are not searched for more game folders
            }

            if (depth >= MaxDepth)
            {
                continue;
            }

            foreach (var c in children.Where(c => c.IsDirectory && !c.IsReparsePoint))
            {
                stack.Push((c.FullPath, depth + 1));
            }
        }
    }

    private static bool IsLog(string name) =>
        name.EndsWith(".log", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".log.gz", StringComparison.OrdinalIgnoreCase);

    private (MinecraftLogFacts? Facts, string? Problem) Read(FsEntry log)
    {
        try
        {
            using var opened = files.Open(log.FullPath);
            Stream s = opened.Content;
            GZipStream? gz = null;
            if (log.Name.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            {
                gz = new GZipStream(s, CompressionMode.Decompress, leaveOpen: true);
                s = new LimitedStream(gz, MaxDecompressed);
            }

            using (gz)
            using (var reader = new StreamReader(s, Encoding.UTF8, detectEncodingFromByteOrderMarks: true))
            {
                return (MinecraftLogParser.Parse(reader), null);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return (null, ex.Message);
        }
    }

    private Evidence Build(AnalyzerContext context, string game, FsEntry log, MinecraftLogFacts f)
    {
        var limitations = new List<Limitation>();
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["MinecraftRoot"] = game,
            ["Log.Lines"] = f.Lines.ToString(CultureInfo.InvariantCulture),
        };
        Put(attrs, "Game.Version", f.GameVersion);
        Put(attrs, "Game.Loader", f.Loader);
        Put(attrs, "Game.LoaderVersion", f.LoaderVersion);
        Put(attrs, "Game.User", f.User);
        if (f.Mods.Count > 0)
        {
            attrs["Game.Mods"] = string.Join(", ", f.Mods.Where(m => !m.Nested).Select(m => $"{m.Id}@{m.Version}"));
            attrs["Game.ModCount"] = f.Mods.Count(m => !m.Nested).ToString(CultureInfo.InvariantCulture);
            if (f.Mods.Any(m => m.Nested))
            {
                attrs["Game.NestedMods"] = string.Join(", ", f.Mods.Where(m => m.Nested).Select(m => $"{m.Id}@{m.Version}"));
            }
        }

        if (f.ModFiles.Count > 0)
        {
            attrs["Game.ModFiles"] = string.Join(", ", f.ModFiles);
        }

        if (f.Servers.Count > 0)
        {
            attrs["Game.Servers"] = string.Join(", ", f.Servers);
        }

        if (f.Truncated)
        {
            limitations.Add(new Limitation("LOG.TRUNCATED", $"Лог длиннее {MinecraftLogParser.MaxLines} строк; разобрано начало."));
        }

        // The date: printed in lines (Forge), from the rotated file name, or — for latest.log — the day the
        // file was last written, which is wrong if the session crossed midnight.
        var date = f.PrintedDate ?? MinecraftLogParser.DateFromName(log.Name);
        var dateFromWriteTime = false;
        if (date is null && log.LastWriteTimeUtc.Year >= 1980)
        {
            date = DateOnly.FromDateTime(TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(log.LastWriteTimeUtc, DateTimeKind.Utc), machineZone));
            dateFromWriteTime = true;
        }

        EvidenceTimestamp? start = null;
        if (date is { } d && f.FirstTime is { } first)
        {
            var local = d.ToDateTime(TimeOnly.FromTimeSpan(first));
            var utc = new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(local, DateTimeKind.Unspecified), machineZone), TimeSpan.Zero);
            start = new EvidenceTimestamp(utc, "Log.FirstLine", TimestampPrecision.Seconds, machineZone.Id,
                dateFromWriteTime ? TimeSpan.FromDays(1) : null);
            if (dateFromWriteTime)
            {
                limitations.Add(new Limitation("LOG.DATE_FROM_FILE", "В строках лога только время; дата взята из времени записи файла и может отличаться на сутки."));
            }
        }

        var loader = f.Loader is null ? "без загрузчика модов в логе" : $"{f.Loader} {f.LoaderVersion}";
        var description = $"Запуск Minecraft {f.GameVersion ?? "(версия не указана)"} ({loader})" +
                          (f.Mods.Count > 0 ? $", модов загружено: {f.Mods.Count(m => !m.Nested)}" : string.Empty) +
                          (f.Servers.Count > 0 ? $", серверы: {string.Join(", ", f.Servers)}" : string.Empty) +
                          $" — лог {log.FullPath}.";

        return new Evidence
        {
            EvidenceId = context.NewEvidenceId(),
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = new SourceRef(EvidenceSourceKind.MinecraftLog, log.FullPath, ParserName, ParserVersion),
            Locator = log.FullPath,
            EventType = f.Mods.Count > 0 || f.ModFiles.Count > 0 ? EvidenceEventType.Loaded : EvidenceEventType.Observed,
            Timestamp = start,
            Target = new ObjectRef
            {
                RecordedPath = game,
                NormalizedPath = PathNormalizer.Normalize(game),
                FileName = Path.GetFileName(game.TrimEnd('\\', '/')),
            },
            Confidence = Confidence.Informational,
            Rationale = "Лог пишет сама игра и загрузчик модов: список загруженных модов — их собственная запись о запуске. Лог можно изменить, поэтому он сверяется с файлами и другими источниками.",
            CollectionStatus = f.Truncated ? CollectionStatus.Partial : CollectionStatus.Collected,
            Description = description,
            Limitations = limitations,
            Attributes = attrs,
            CollectedAtUtc = context.Time.GetUtcNow(),
        };
    }

    private static void Put(Dictionary<string, string> attrs, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            attrs[key] = value;
        }
    }

    /// <summary>Stops a decompression bomb: reads at most <c>limit</c> bytes, then reports end of data.</summary>
    private sealed class LimitedStream(Stream inner, long limit) : Stream
    {
        private long _read;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => _read; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var allowed = (int)Math.Min(count, limit - _read);
            if (allowed <= 0)
            {
                return 0;
            }

            var n = inner.Read(buffer, offset, allowed);
            _read += n;
            return n;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
