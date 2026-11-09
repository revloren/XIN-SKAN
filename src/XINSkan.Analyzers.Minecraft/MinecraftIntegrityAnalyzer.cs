using System.Globalization;
using XINSkan.Analyzers.FileHunter.Scanning;
using XINSkan.Core.IO;
using XINSkan.Core.Paths;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;

namespace XINSkan.Analyzers.Minecraft;

public sealed record MinecraftOptions
{
    public required string UsersRoot { get; init; }

    public required string CurrentProfile { get; init; }

    /// <summary>Operator folders: portable launchers (MultiMC, Prism) found here directly or one level down.</summary>
    public IReadOnlyList<string> ExtraRoots { get; init; } = [];

    /// <summary>How many bytes of game and library files may be hashed in one investigation.</summary>
    public long HashBudgetBytes { get; init; } = 4L * 1024 * 1024 * 1024;
}

/// <summary>
/// Minecraft Integrity: which launchers and instances exist, what version and loader each runs, which JVM options
/// they add, and whether the game's own files are what its version files say. Records are facts
/// (Informational) or indirect signs (Low); a client JAR that differs from Mojang's published hash is Medium.
/// </summary>
public sealed class MinecraftIntegrityAnalyzer(MinecraftOptions options, IDirectoryLister lister, IFileSource files) : IAnalyzer
{
    public const string ModuleId = "minecraft-integrity";
    private const string ParserName = "xinskan-minecraft";
    private const string ParserVersion = "1";
    private const int MaxLibraryRecords = 50;

    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    public string Id => ModuleId;

    public string DisplayName => "Minecraft Integrity";

    public AnalyzerRequirements Requirements { get; } = new() { OptionalCapabilities = [Capability.OtherUserProfiles] };

    public async Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var reader = new Reader(lister, files);
        var integrity = new VersionIntegrity(reader, options.HashBudgetBytes);
        var limitations = new List<Limitation>
        {
            new("MC.LOCAL_HASHES", "Файлы сверяются с хешами из локальных файлов версий. Их тоже можно изменить; сверка с хешами, опубликованными Mojang, — задача проверенной базы (этап 9)."),
            new("MC.FORMATS", "Форматы Prism/MultiMC, CurseForge, ATLauncher и Modrinth App проверены на образцах, составленных по их документации и исходному коду, а не на настоящих установках."),
        };
        var allowed = context.Permissions.Has(Capability.OtherUserProfiles);
        var profiles = Profiles(reader, allowed, out var skipped);
        if (skipped > 0)
        {
            limitations.Add(new Limitation("MC.OTHER_USERS", $"Профили других пользователей ({skipped}) не проверены: нет разрешения на чужие профили."));
        }

        long instances = 0, versions = 0, recorded = 0;
        var homesFound = new List<string>();
        var roots = new List<(string Root, string Launcher, bool Prism)>();
        foreach (var (profile, user) in profiles)
        {
            foreach (var home in InstanceFinder.Homes(reader, profile))
            {
                homesFound.Add($"{home.Launcher}: {home.Folder}");
                foreach (var inst in InstanceFinder.Read(reader, home))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    instances++;
                    foreach (var e in Instance(context, inst, user))
                    {
                        await context.Writer.AddEvidenceAsync(e, cancellationToken).ConfigureAwait(false);
                        recorded++;
                    }
                }

                switch (home.Launcher)
                {
                    case "Официальный лаунчер":
                        roots.Add((home.Folder, home.Launcher, false));
                        break;
                    case "CurseForge":
                        roots.Add((InstanceFinder.Combine(home.Folder, "Install"), home.Launcher, false));
                        break;
                    case "Prism Launcher" or "PolyMC" or "MultiMC":
                        roots.Add((home.Folder, home.Launcher, true));
                        break;
                }
            }
        }

        foreach (var home in Portable(reader, options.ExtraRoots))
        {
            homesFound.Add($"{home.Launcher}: {home.Folder}");
            foreach (var inst in InstanceFinder.Read(reader, home))
            {
                instances++;
                foreach (var e in Instance(context, inst, null))
                {
                    await context.Writer.AddEvidenceAsync(e, cancellationToken).ConfigureAwait(false);
                    recorded++;
                }
            }

            roots.Add((home.Folder, home.Launcher, home.Launcher != "Официальный лаунчер"));
        }

        foreach (var (root, launcher, prism) in roots.DistinctBy(r => r.Root, StringComparer.OrdinalIgnoreCase))
        {
            context.Progress.Report(new ModuleProgress(Id, ModuleState.Running, $"Сверка файлов игры: {root}"));
            var reports = prism ? PrismMeta(reader, integrity, root) : integrity.CheckAll(root);
            foreach (var report in reports)
            {
                cancellationToken.ThrowIfCancellationRequested();
                versions++;
                foreach (var e in Version(context, report, launcher, root))
                {
                    await context.Writer.AddEvidenceAsync(e, cancellationToken).ConfigureAwait(false);
                    recorded++;
                }
            }
        }

        if (integrity.BudgetExhausted)
        {
            limitations.Add(new Limitation("MC.BUDGET", $"Прочитано {integrity.BytesRead / (1024 * 1024)} МБ файлов игры — это предел модуля; остальные файлы не сверены."));
        }

        if (homesFound.Count == 0)
        {
            limitations.Add(new Limitation("MC.NONE", "Ни одного известного лаунчера или папки игры в проверенных профилях не найдено."));
        }

        await context.Writer.AddCoverageAsync(new SourceCoverage
        {
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = EvidenceSourceKind.Launcher,
            Scope = homesFound.Count == 0 ? "Лаунчеры не найдены" : string.Join("; ", homesFound),
            Status = integrity.BudgetExhausted || skipped > 0 ? CollectionStatus.Partial : CollectionStatus.Collected,
            ItemsRead = instances + versions,
            Limitations = limitations,
        }, cancellationToken).ConfigureAwait(false);
        context.Progress.Report(new ModuleProgress(Id, ModuleState.Running,
            $"Экземпляров {instances.ToString("N0", Ru)}, версий {versions.ToString("N0", Ru)}, записано {recorded.ToString("N0", Ru)}, прочитано {integrity.BytesRead / (1024 * 1024)} МБ."));
    }

    private List<(string Profile, string? User)> Profiles(Reader reader, bool allowed, out int skipped)
    {
        var list = new List<(string, string?)> { (options.CurrentProfile, null) };
        skipped = 0;
        foreach (var e in reader.List(options.UsersRoot).Where(e => e.IsDirectory && !e.IsReparsePoint && !ScopeBuilder.IsSystemProfile(e.Name)))
        {
            if (string.Equals(e.FullPath.TrimEnd('\\', '/'), options.CurrentProfile.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (allowed)
            {
                list.Add((e.FullPath, e.Name));
            }
            else
            {
                skipped++;
            }
        }

        return list;
    }

    /// <summary>Portable launchers and game folders in operator folders, at the top or one level down.</summary>
    private static IEnumerable<LauncherHome> Portable(Reader reader, IReadOnlyList<string> roots)
    {
        foreach (var root in roots)
        {
            foreach (var dir in new[] { root }.Concat(reader.List(root).Where(e => e.IsDirectory && !e.IsReparsePoint).Select(e => e.FullPath)))
            {
                var names = reader.List(dir).Select(e => e.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
                if (names.Contains("instances") && names.Overlaps(["prismlauncher.cfg", "multimc.cfg", "polymc.cfg"]))
                {
                    yield return new LauncherHome(names.Contains("prismlauncher.cfg") ? "Prism Launcher" : names.Contains("polymc.cfg") ? "PolyMC" : "MultiMC", dir);
                }
                else if (names.Contains("versions") && names.Contains("launcher_profiles.json"))
                {
                    yield return new LauncherHome("Официальный лаунчер", dir);
                }
            }
        }
    }

    /// <summary>Prism keeps version files in meta\&lt;uid&gt;\&lt;version&gt;.json and shared libraries.</summary>
    private static List<VersionReport> PrismMeta(Reader reader, VersionIntegrity integrity, string home)
    {
        var meta = InstanceFinder.Combine(home, "meta");
        var libraries = InstanceFinder.Combine(home, "libraries");
        var list = new List<VersionReport>();
        foreach (var uid in reader.List(meta).Where(e => e.IsDirectory && !e.IsReparsePoint))
        {
            foreach (var f in reader.List(uid.FullPath).Where(e => !e.IsDirectory && e.Name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                                                                  && e.Name is not ("index.json" or "package.json")))
            {
                if (integrity.Check(InstanceFinder.Combine(home, "versions"), libraries, $"{uid.Name} {f.Name[..^5]}", f.FullPath) is { } r)
                {
                    list.Add(r);
                }
            }
        }

        return list;
    }

    private IEnumerable<Evidence> Instance(AnalyzerContext context, MinecraftInstance inst, string? user)
    {
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Launcher"] = inst.Launcher,
            ["Instance.Name"] = inst.Name,
            ["Instance.Source"] = inst.Source,
        };
        Put(attrs, "Instance.Version", inst.Version);
        Put(attrs, "Instance.Loader", inst.Loader is null ? null : $"{inst.Loader} {inst.LoaderVersion}".Trim());
        Put(attrs, "Instance.JavaArgs", inst.JavaArgs);
        Put(attrs, "Instance.JavaPath", inst.JavaPath);
        Put(attrs, "Instance.User", user);
        if (inst.GameDir is not null && inst.GameDir.Contains(".minecraft", StringComparison.OrdinalIgnoreCase))
        {
            attrs["MinecraftRoot"] = inst.GameDir;
        }

        yield return Make(context, inst.Source, inst.GameDir ?? inst.Source, inst.Name, EvidenceEventType.Observed,
            inst.LastUsed is { } t ? new EvidenceTimestamp(t, "Launcher.LastUsed", TimestampPrecision.Milliseconds) : null,
            Confidence.Informational,
            "Описание экземпляра из файла настроек лаунчера; время — последний запуск по данным лаунчера (его можно изменить, сверяется с логами и Prefetch).",
            $"{inst.Launcher}: «{inst.Name}»" + (inst.Version is null ? string.Empty : $", версия {inst.Version}") +
            (inst.Loader is null ? string.Empty : $", {inst.Loader} {inst.LoaderVersion}") + (inst.LastUsed is { } lu ? $", последний запуск {lu.ToString("u", Ru)}" : string.Empty) + ".",
            attrs, inst.Problems);

        foreach (var flag in JvmArguments.Find(JvmArguments.Split(inst.JavaArgs)))
        {
            yield return Flag(context, flag, inst.Source, $"профиль «{inst.Name}» ({inst.Launcher})", user);
        }
    }

    private IEnumerable<Evidence> Version(AnalyzerContext context, VersionReport r, string launcher, string root)
    {
        var libs = r.Libraries;
        var matched = libs.Count(l => l.Status == HashStatus.Match);
        var mismatched = libs.Where(l => l.Status == HashStatus.Mismatch).ToList();
        var missing = libs.Count(l => l.Status == HashStatus.Missing);
        var notRead = libs.Count(l => l.Status == HashStatus.NotRead) + (r.Client?.Status == HashStatus.NotRead ? 1 : 0);
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Launcher"] = launcher,
            ["Version.Id"] = r.Id,
            ["Version.Libraries"] = libs.Count.ToString(CultureInfo.InvariantCulture),
            ["Version.LibrariesMatched"] = matched.ToString(CultureInfo.InvariantCulture),
            ["Version.LibrariesMismatched"] = mismatched.Count.ToString(CultureInfo.InvariantCulture),
            ["Version.LibrariesMissing"] = missing.ToString(CultureInfo.InvariantCulture),
            ["MinecraftRoot"] = root,
        };
        Put(attrs, "Version.InheritsFrom", r.InheritsFrom);
        Put(attrs, "Version.MainClass", r.MainClass);
        Put(attrs, "Version.Client", r.Client?.Status.ToString());
        var problems = r.Problems.ToList();
        if (notRead > 0)
        {
            problems.Add($"Не прочитано файлов: {notRead} (слишком большие или исчерпан бюджет чтения).");
        }

        yield return Make(context, r.JsonPath, r.JsonPath, r.Id, EvidenceEventType.Observed, null, Confidence.Informational,
            "Сверка файлов версии с хешами из её собственного файла версии.",
            $"Версия {r.Id}: клиент — {ClientText(r.Client)}; библиотек {libs.Count}, совпало {matched}, отличается {mismatched.Count}, отсутствует {missing}.",
            attrs, problems);

        if (r.Client is { Status: HashStatus.Mismatch } c)
        {
            yield return Make(context, r.JsonPath, c.Path, Path.GetFileName(c.Path.Replace('\\', '/')), EvidenceEventType.Observed, null,
                r.ClientFromMojang ? Confidence.Medium : Confidence.Low,
                r.ClientFromMojang
                    ? "Файл версии указывает загрузку с серверов Mojang и её SHA-1, а JAR клиента на диске другой: клиент изменён после загрузки. Так делают «взломанные» клиенты; безобидные причины — старые моды, встраиваемые прямо в JAR (до 1.6), повреждение файла."
                    : "JAR клиента не совпадает с хешем из файла версии стороннего лаунчера или сборки. Это может быть и изменённый клиент, и собственная сборка лаунчера.",
                $"JAR клиента версии {r.Id} отличается от указанного в файле версии: SHA-1 {c.ActualSha1} вместо {c.ExpectedSha1}.",
                Hashes(c, r.Id, launcher, root), [], c.ActualSize);
        }

        foreach (var lib in mismatched.Take(MaxLibraryRecords))
        {
            yield return Make(context, r.JsonPath, lib.Path, Path.GetFileName(lib.Path.Replace('\\', '/')), EvidenceEventType.Observed, null, Confidence.Low,
                "Библиотека не совпадает с хешем из файла версии. Так подменяют библиотеки (например, authlib в «пиратских» лаунчерах или для внедрения кода); безобидные причины — обновлённая библиотека, собственная сборка лаунчера, повреждение.",
                $"Библиотека {lib.Path} версии {r.Id} отличается от указанной: SHA-1 {lib.ActualSha1} вместо {lib.ExpectedSha1}.",
                Hashes(lib, r.Id, launcher, root), [], lib.ActualSize);
        }

        if (!r.MainClassKnown)
        {
            yield return Make(context, r.JsonPath, r.JsonPath, r.Id, EvidenceEventType.Observed, null, Confidence.Low,
                "Главный класс запуска не из известных (Minecraft, Fabric, Quilt, Forge, NeoForge, LaunchWrapper). Так запускают клиенты со своей точкой входа; безобидная причина — новый или редкий загрузчик.",
                $"Версия {r.Id} запускается через класс {r.MainClass}.",
                new Dictionary<string, string>(StringComparer.Ordinal) { ["Version.Id"] = r.Id, ["Version.MainClass"] = r.MainClass ?? string.Empty, ["Launcher"] = launcher, ["MinecraftRoot"] = root }, []);
        }

        foreach (var flag in r.JvmFlags)
        {
            yield return Flag(context, flag, r.JsonPath, $"файл версии {r.Id}", null);
        }
    }

    private static string ClientText(CheckedFile? c) => c?.Status switch
    {
        null => "не задан в этом файле версии",
        HashStatus.Match => "совпадает",
        HashStatus.Mismatch => "отличается",
        HashStatus.Missing => "JAR отсутствует",
        HashStatus.NoHash => "хеш не указан",
        _ => "не прочитан",
    };

    private static Dictionary<string, string> Hashes(CheckedFile f, string version, string launcher, string root)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Version.Id"] = version,
            ["Launcher"] = launcher,
            ["MinecraftRoot"] = root,
            ["Sha1.Expected"] = f.ExpectedSha1 ?? string.Empty,
            ["Sha1.Actual"] = f.ActualSha1 ?? string.Empty,
        };
        Put(d, "Download.Url", f.Url);
        return d;
    }

    private Evidence Flag(AnalyzerContext context, JvmFlag flag, string source, string where, string? user)
    {
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Jvm.Flag"] = flag.Kind,
            ["Jvm.Option"] = flag.Option,
            ["Jvm.Where"] = where,
        };
        Put(attrs, "Instance.User", user);
        return Make(context, source, flag.Path ?? source, flag.Path is null ? flag.Option : Path.GetFileName(flag.Path.Replace('\\', '/')), EvidenceEventType.Observed, null, Confidence.Low,
            $"Параметр JVM {flag.Kind} {flag.Meaning}. Так внедряют чит-клиенты и обходы; так же подключают профилировщики, отладчики и агенты оптимизации.",
            $"В {where} задан параметр {flag.Option}.", attrs, []);
    }

    private Evidence Make(AnalyzerContext context, string artifact, string target, string? name, EvidenceEventType type, EvidenceTimestamp? time, Confidence confidence,
        string rationale, string description, Dictionary<string, string> attrs, IReadOnlyList<string> problems, long? size = null) => new()
    {
        EvidenceId = context.NewEvidenceId(),
        InvestigationId = context.InvestigationId,
        ModuleId = Id,
        Source = new SourceRef(EvidenceSourceKind.Launcher, artifact, ParserName, ParserVersion),
        Locator = artifact == target ? artifact : $"{artifact} → {target}",
        EventType = type,
        Timestamp = time,
        Target = new ObjectRef
        {
            RecordedPath = target,
            NormalizedPath = target.Length > 2 && target[1] == ':' ? PathNormalizer.Normalize(target) : null,
            FileName = name,
            Size = size,
        },
        Confidence = confidence,
        Rationale = rationale,
        CollectionStatus = problems.Count == 0 ? CollectionStatus.Collected : CollectionStatus.Partial,
        Description = description,
        Limitations = problems.Select(p => new Limitation("MC.READ", p)).ToList(),
        Attributes = attrs,
        CollectedAtUtc = context.Time.GetUtcNow(),
    };

    private static void Put(Dictionary<string, string> d, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            d[key] = value;
        }
    }
}
