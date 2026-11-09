using System.Globalization;
using XINSkan.Analyzers.History;
using XINSkan.Core.Paths;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;

namespace XINSkan.Analyzers.Execution;

/// <summary>
/// Windows event logs: cleared logs, Microsoft Defender detections and changes to its protection, crashes of
/// Java and launchers (with the module that crashed), services and drivers installed from user folders, and
/// process creation when the system audits it.
/// </summary>
public sealed class EventLogAnalyzer(HistoryOptions options, IEventLogSource logs, IVolumeDirectory volumes) : IAnalyzer
{
    public const string ModuleId = "eventlogs";
    public const string Defender = "Microsoft-Windows-Windows Defender/Operational";
    private const string ParserName = "xinskan-evtxml";
    private const string ParserVersion = "1";
    private const int MaxPerQuery = 50_000;

    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    /// <summary>Channel → XPath filter → what is read from it.</summary>
    internal static readonly (string Channel, int[] Ids)[] Queries =
    [
        ("System", [104, 7045]),
        ("Security", [1102, 4688]),
        ("Application", [1000]),
        (Defender, [1116, 1117, 5001, 5007]),
    ];

    public string Id => ModuleId;

    public string DisplayName => "Журналы событий";

    public AnalyzerRequirements Requirements { get; } = new() { OptionalCapabilities = [Capability.Administrator, Capability.SecurityEventLog, Capability.OtherUserProfiles] };

    private sealed record Context(AnalyzerContext Run, VolumeResolver Resolver, HistoryScope Scope);

    public async Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var ctx = new Context(context, new VolumeResolver(volumes.Volumes()),
            new HistoryScope(options.UsersRoot, options.CurrentProfile, context.Permissions.Has(Capability.OtherUserProfiles), options.TempFolders, options.ExtraRoots));
        long totalRecorded = 0;
        foreach (var (channel, ids) in Queries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var xpath = "*[System[(" + string.Join(" or ", ids.Select(i => $"EventID={i}")) + ")]]";
            var result = logs.Query(channel, xpath, MaxPerQuery);
            var limitations = new List<Limitation>
            {
                new("EVENTLOG.WINDOW", "Журнал хранит события, пока не заполнится (обычно 20 МБ), затем старые затираются; журнал можно очистить. Отсутствие события ничего не доказывает."),
            };
            if (result.Failure is { } failure)
            {
                limitations.Add(new Limitation(result.ChannelMissing ? "EVENTLOG.MISSING" : "EVENTLOG.UNREADABLE", $"{channel}: {failure}"));
                await Coverage(context, channel, result.ChannelMissing ? CollectionStatus.Skipped : CollectionStatus.Failed, 0, null, limitations, cancellationToken).ConfigureAwait(false);
                continue;
            }

            if (result.Truncated)
            {
                limitations.Add(new Limitation("EVENTLOG.TRUNCATED", $"Прочитаны первые {MaxPerQuery:N0} подходящих событий."));
            }

            long damaged = 0, recorded = 0, processEvents = 0;
            foreach (var xml in result.Events)
            {
                if (EventXml.Parse(xml) is not { } e)
                {
                    damaged++;
                    continue;
                }

                processEvents += e.EventId == 4688 ? 1 : 0;
                foreach (var evidence in Interpret(ctx, channel, e))
                {
                    await context.Writer.AddEvidenceAsync(evidence, cancellationToken).ConfigureAwait(false);
                    recorded++;
                }
            }

            if (damaged > 0)
            {
                limitations.Add(new Limitation("EVENTLOG.DAMAGED", $"{damaged} событий не разобрано."));
            }

            if (channel == "Security" && processEvents == 0)
            {
                limitations.Add(new Limitation("EVENTLOG.NO_PROCESS_AUDIT", "Событий создания процессов (4688) нет: аудит запуска процессов на этой системе обычно выключен."));
            }

            totalRecorded += recorded;
            await Coverage(context, channel, damaged > 0 || result.Truncated ? CollectionStatus.Partial : CollectionStatus.Collected, result.Events.Count, logs.Oldest(channel), limitations, cancellationToken).ConfigureAwait(false);
        }

        context.Progress.Report(new ModuleProgress(Id, ModuleState.Running, $"Журналы событий прочитаны, записано {totalRecorded.ToString("N0", Ru)}."));
    }

    private IEnumerable<Evidence> Interpret(Context c, string channel, EventRecord e) => (channel, e.EventId) switch
    {
        ("System", 104) or ("Security", 1102) => [LogCleared(c, channel, e)],
        ("System", 7045) => Service(c, e),
        ("Security", 4688) => ProcessCreated(c, e),
        ("Application", 1000) => Crash(c, e),
        (Defender, 1116 or 1117) => Detection(c, e),
        (Defender, 5001) => [Make(c, channel, e, EvidenceEventType.Observed, new ObjectRef { RecordedPath = "Microsoft Defender", FileName = "RealTimeProtection" }, Confidence.Low,
            "Защиту в реальном времени выключают, чтобы запустить то, что Защитник удаляет; но также при установке другого антивируса, по политике или вручную ненадолго.",
            "Защита Microsoft Defender в реальном времени выключена.", new())],
        (Defender, 5007) => DefenderConfig(c, e),
        _ => [],
    };

    private Evidence LogCleared(Context c, string channel, EventRecord e)
    {
        var who = e.Get("SubjectUserName") is { } user ? $"{e.Get("SubjectDomainName")}\\{user}" : null;
        var cleared = e.Get("Channel") ?? channel;
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal) { ["EventLog.ClearedChannel"] = cleared };
        if (who is not null)
        {
            attrs["EventLog.User"] = who;
        }

        return Make(c, channel, e, EvidenceEventType.Observed, new ObjectRef { RecordedPath = cleared, FileName = cleared }, Confidence.Low,
            "Журнал очищают, чтобы скрыть события, но также администраторы и программы обслуживания. Сама запись об очистке показывает, когда это было и кто это сделал.",
            $"Журнал «{cleared}» очищен" + (who is null ? "." : $" пользователем {who}."), attrs);
    }

    private IEnumerable<Evidence> Service(Context c, EventRecord e)
    {
        var image = ExecutablePath(e.Get("ImagePath"));
        if (image is null)
        {
            yield break;
        }

        var (path, resolved, _) = c.Resolver.Resolve(image);
        var file = ProgramRelevance.FileName(path);
        if (ProgramRelevance.Why(file, path, resolved, resolved && c.Resolver.IsRemovable(path), c.Scope) is not { } why)
        {
            yield break;
        }

        var driver = (e.Get("ServiceType") ?? string.Empty).Contains("driver", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".sys", StringComparison.OrdinalIgnoreCase);
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Service.Name"] = e.Get("ServiceName") ?? string.Empty,
            ["Service.ImagePath"] = e.Get("ImagePath") ?? string.Empty,
            ["Service.Type"] = e.Get("ServiceType") ?? string.Empty,
            ["Service.StartType"] = e.Get("StartType") ?? string.Empty,
            ["EventLog.Why"] = why,
        };
        yield return Make(c, "System", e, EvidenceEventType.Observed, Target(path, resolved), driver ? Confidence.Low : Confidence.Informational,
            driver
                ? "Драйвер, установленный из папки пользователя, — косвенный признак: так ставятся драйверы читов и обходов античитов, но и утилиты мониторинга железа, эмуляторы, драйверы игровых устройств."
                : "Служба установлена из папки пользователя; это записано, чтобы сверить с другими источниками.",
            $"Установлен{(driver ? " драйвер" : "а служба")} «{e.Get("ServiceName")}»: {path}.", attrs);
    }

    private IEnumerable<Evidence> ProcessCreated(Context c, EventRecord e)
    {
        if (e.Get("NewProcessName") is not { } image)
        {
            yield break;
        }

        var (path, resolved, _) = c.Resolver.Resolve(image);
        var file = ProgramRelevance.FileName(path);
        if (ProgramRelevance.Why(file, path, resolved, resolved && c.Resolver.IsRemovable(path), c.Scope) is not { } why)
        {
            yield break;
        }

        var attrs = new Dictionary<string, string>(StringComparer.Ordinal) { ["EventLog.Why"] = why };
        foreach (var (name, attr) in new[] { ("CommandLine", "Process.CommandLine"), ("ParentProcessName", "Process.Parent"), ("NewProcessId", "Process.Id") })
        {
            if (e.Get(name) is { } v)
            {
                attrs[attr] = v;
            }
        }

        yield return Make(c, "Security", e, EvidenceEventType.Executed, Target(path, resolved), Confidence.Informational,
            "Событие 4688 записывает сама Windows при создании процесса, если включён аудит: это след запуска с точным временем.",
            $"Запущен {path}" + (attrs.TryGetValue("Process.CommandLine", out var cmd) ? $": {cmd}" : "."), attrs, e.Get("SubjectUserSid"));
    }

    private IEnumerable<Evidence> Crash(Context c, EventRecord e)
    {
        var app = e.Get("AppName") ?? e.Get("0");
        var appPath = e.Get("AppPath") ?? e.Get("10");
        var module = e.Get("ModuleName") ?? e.Get("3");
        var modulePath = e.Get("ModulePath") ?? e.Get("11");
        if (app is null)
        {
            yield break;
        }

        var (path, resolved, _) = appPath is null ? (app, false, (string?)null) : c.Resolver.Resolve(appPath);
        var why = appPath is null
            ? ProgramRelevance.IsKnown(app) ? "известная программа (Java или лаунчер Minecraft)" : null
            : ProgramRelevance.Why(app, path, resolved, resolved && c.Resolver.IsRemovable(path), c.Scope);
        if (why is null)
        {
            yield break;
        }

        var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Crash.Module"] = module ?? string.Empty,
            ["Crash.ModulePath"] = modulePath ?? string.Empty,
            ["Crash.ExceptionCode"] = e.Get("ExceptionCode") ?? e.Get("6") ?? string.Empty,
            ["EventLog.Why"] = why,
        };
        yield return Make(c, "Application", e, EvidenceEventType.Executed, Target(path, resolved && appPath is not null), Confidence.Informational,
            "Сбой программы записывает Windows; раз программа упала, она работала. Модуль сбоя показывает, в чьём коде это произошло.",
            $"Сбой {app}" + (module is null ? "." : $" в модуле {module}."), attrs);

        // A crash inside a DLL from a user folder: that DLL was loaded into the program (injection is one reason).
        if (modulePath is not null)
        {
            var (mPath, mResolved, _) = c.Resolver.Resolve(modulePath);
            var m = c.Scope.Match(mPath);
            if (m.InScope || !mResolved)
            {
                yield return Make(c, "Application", e, EvidenceEventType.Loaded, Target(mPath, mResolved), Confidence.Informational,
                    "Модуль, в котором упала программа, лежит в папке пользователя: он был загружен в процесс. Так бывает с внедрёнными DLL, но и с модами и нативными библиотеками самих лаунчеров.",
                    $"{app} загрузил {mPath} и упал в нём.",
                    new Dictionary<string, string>(StringComparer.Ordinal) { ["Crash.Application"] = app, ["Crash.ApplicationPath"] = appPath ?? string.Empty });
            }
        }
    }

    private IEnumerable<Evidence> Detection(Context c, EventRecord e)
    {
        var raw = e.Get("Path") ?? string.Empty;
        var path = DefenderPath(raw);
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Defender.Threat"] = e.Get("Threat Name") ?? string.Empty,
            ["Defender.Category"] = e.Get("Category Name") ?? string.Empty,
            ["Defender.Severity"] = e.Get("Severity Name") ?? string.Empty,
            ["Defender.Paths"] = raw,
            ["Defender.Process"] = e.Get("Process Name") ?? string.Empty,
            ["Defender.User"] = e.Get("Detection User") ?? string.Empty,
        };
        if (e.Get("Action Name") is { } action)
        {
            attrs["Defender.Action"] = action;
        }

        var (resolvedPath, resolved, _) = path is null ? (string.Empty, false, (string?)null) : c.Resolver.Resolve(path);
        yield return Make(c, Defender, e, EvidenceEventType.Observed,
            path is null ? new ObjectRef { RecordedPath = raw } : Target(resolvedPath, resolved), Confidence.Informational,
            "Обнаружение записывает Microsoft Defender: название угрозы — его классификация, а не вывод о чите. Многие читы определяются как HackTool или PUA, но так же определяются и безобидные утилиты.",
            (e.EventId == 1117 ? "Defender принял меры против " : "Defender обнаружил ") + $"«{attrs["Defender.Threat"]}»: {(path ?? raw)}" +
            (attrs.TryGetValue("Defender.Action", out var a) ? $" ({a})." : "."), attrs);
    }

    private IEnumerable<Evidence> DefenderConfig(Context c, EventRecord e)
    {
        var newValue = e.Get("New Value") ?? string.Empty;
        var oldValue = e.Get("Old Value") ?? string.Empty;
        var added = newValue.Contains(@"\Exclusions\", StringComparison.OrdinalIgnoreCase);
        if (!added && !oldValue.Contains(@"\Exclusions\", StringComparison.OrdinalIgnoreCase))
        {
            yield break;
        }

        var value = added ? newValue : oldValue;
        var at = value.IndexOf(@"\Exclusions\", StringComparison.OrdinalIgnoreCase);
        var rest = value[(at + 12)..];
        var slash = rest.IndexOf('\\', StringComparison.Ordinal);
        var kind = slash < 0 ? rest : rest[..slash];
        var target = slash < 0 ? string.Empty : rest[(slash + 1)..];
        var eq = target.LastIndexOf(" = ", StringComparison.Ordinal);
        target = eq < 0 ? target : target[..eq];
        yield return Make(c, Defender, e, EvidenceEventType.Observed, new ObjectRef { RecordedPath = target, FileName = ProgramRelevance.FileName(target) }, added ? Confidence.Low : Confidence.Informational,
            added
                ? "Исключение Защитника не даёт ему проверять папку или файл. Так прячут читы от удаления, но исключения добавляют и для игр, сборок модов, программ разработки."
                : "Исключение Защитника удалено; записано для хронологии.",
            $"{(added ? "Добавлено" : "Удалено")} исключение Microsoft Defender ({kind}): {target}.",
            new Dictionary<string, string>(StringComparer.Ordinal) { ["Defender.ExclusionType"] = kind, ["Defender.Change"] = added ? "added" : "removed" });
    }

    /// <summary>The first file path of a Defender detection ("file:_C:\…; containerfile:_C:\…").</summary>
    internal static string? DefenderPath(string raw)
    {
        foreach (var part in raw.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var p = part.StartsWith("file:_", StringComparison.OrdinalIgnoreCase) ? part[6..]
                : part.StartsWith("containerfile:_", StringComparison.OrdinalIgnoreCase) ? part[15..]
                : null;
            if (p is not null)
            {
                var arrow = p.IndexOf("->", StringComparison.Ordinal);
                return arrow < 0 ? p : p[..arrow];
            }
        }

        return null;
    }

    /// <summary>The executable of a service command line: without "\??\", quotes and arguments.</summary>
    internal static string? ExecutablePath(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return null;
        }

        var s = command.Trim();
        if (s.StartsWith('"'))
        {
            var end = s.IndexOf('"', 1);
            s = end < 0 ? s[1..] : s[1..end];
        }
        else
        {
            foreach (var ext in new[] { ".exe", ".sys", ".dll" })
            {
                var i = s.IndexOf(ext, StringComparison.OrdinalIgnoreCase);
                if (i > 0)
                {
                    s = s[..(i + ext.Length)];
                    break;
                }
            }
        }

        if (s.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            s = s[4..];
        }

        if (s.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase) || s.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase))
        {
            return null; // Windows' own folder
        }

        return s;
    }

    private static ObjectRef Target(string path, bool resolved) => new()
    {
        RecordedPath = path,
        NormalizedPath = resolved && path.Length > 2 && path[1] == ':' ? PathNormalizer.Normalize(path) : null,
        FileName = ProgramRelevance.FileName(path),
    };

    private Evidence Make(Context c, string channel, EventRecord e, EvidenceEventType type, ObjectRef target, Confidence confidence, string rationale, string description, Dictionary<string, string> attrs, string? sid = null)
    {
        attrs["EventLog.Channel"] = channel;
        attrs["EventLog.EventId"] = e.EventId.ToString(CultureInfo.InvariantCulture);
        if (e.Provider is not null)
        {
            attrs["EventLog.Provider"] = e.Provider;
        }

        if (e.RecordId is { } r)
        {
            attrs["EventLog.RecordId"] = r.ToString(CultureInfo.InvariantCulture);
        }

        return new Evidence
        {
            EvidenceId = c.Run.NewEvidenceId(),
            InvestigationId = c.Run.InvestigationId,
            ModuleId = Id,
            Source = new SourceRef(EvidenceSourceKind.EventLog, channel, ParserName, ParserVersion),
            Locator = $"{channel}#{e.RecordId?.ToString(CultureInfo.InvariantCulture) ?? "?"} (EventID {e.EventId})",
            EventType = type,
            Timestamp = e.TimeCreated is { } t ? new EvidenceTimestamp(t, "Event.TimeCreated", TimestampPrecision.HundredNanoseconds) : null,
            Target = target,
            UserSid = sid ?? e.UserSid,
            Confidence = confidence,
            Rationale = rationale,
            CollectionStatus = CollectionStatus.Collected,
            Description = description,
            Attributes = attrs,
            CollectedAtUtc = c.Run.Time.GetUtcNow(),
        };
    }

    private async Task Coverage(AnalyzerContext context, string channel, CollectionStatus status, long items, DateTimeOffset? earliest, List<Limitation> limitations, CancellationToken ct) =>
        await context.Writer.AddCoverageAsync(new SourceCoverage
        {
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = EvidenceSourceKind.EventLog,
            Scope = channel,
            Status = status,
            ItemsRead = items,
            EarliestUtc = earliest,
            Limitations = limitations,
        }, ct).ConfigureAwait(false);
}
