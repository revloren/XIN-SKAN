using System.Globalization;
using XINSkan.Core.Paths;
using XINSkan.Models;

namespace XINSkan.Correlation;

/// <summary>
/// Links records that describe the same file and applies the published rules (docs/CORRELATION.md).
/// Records are only read; objects and findings reference them by ID.
/// </summary>
/// <remarks>
/// Confidence policy: a rule gives Low; Medium only when its basis spans at least two independent source families
/// (Finding.Validate enforces this); High is never produced here, because it needs a verified identification of
/// the object (stage 9). No rule names a cheat.
/// </remarks>
public sealed class CorrelationEngine(Ulid investigationId, DateTimeOffset investigationStart, TimeProvider time)
{
    /// <summary>Concealment events closer than this to each other form one cluster.</summary>
    public static readonly TimeSpan ClusterWindow = TimeSpan.FromHours(2);

    private const int MaxContext = 50;
    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    private int _ambiguous;

    public CorrelationResult Run(IReadOnlyList<EvidenceFacts> facts) => Run(facts, []);

    /// <param name="matches">Records that matched the signature database (stage 9).</param>
    public CorrelationResult Run(IReadOnlyList<EvidenceFacts> facts, IReadOnlyList<SignatureMatch> matches)
    {
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(matches);
        var groups = Link(facts);
        var objects = new List<CorrelatedObject>();
        var objectFacts = new Dictionary<Ulid, List<(EvidenceFacts Fact, LinkKind Link)>>();
        foreach (var g in groups.Where(g => g.Count >= 2))
        {
            var o = BuildObject(g);
            objects.Add(o);
            objectFacts[o.ObjectId] = g;
        }

        var findings = new List<Finding>();
        foreach (var o in objects)
        {
            var members = objectFacts[o.ObjectId].Select(m => m.Fact).ToList();
            findings.AddRange(ObjectRules(o, members));
        }

        findings.AddRange(SignatureFindings(facts, matches, objects, objectFacts));
        findings.AddRange(ExclusionRule(facts, objects, objectFacts));
        findings.AddRange(ConcealmentClusters(facts));
        findings.AddRange(RemovableRuns(facts));

        foreach (var f in findings)
        {
            var problems = f.Validate();
            if (problems.Count > 0)
            {
                throw new InvalidOperationException($"Rule {f.RuleId} produced an invalid finding: {string.Join(" ", problems)}");
            }
        }

        var limitations = new List<Limitation>
        {
            new("CORR.NO_IDENTIFICATION", "Корреляция связывает записи и находит закономерности. Что объект — известный клиент, она узнаёт только из базы сигнатур: High ставится лишь при точном хеше или компоненте, подтверждённом исходным кодом проекта, вместе с двумя другими независимыми источниками."),
            new("CORR.SHORT_NAMES", "Короткие имена 8.3 (RUNNER~1), переменные окружения и точки соединения не раскрываются: такие пути связываются только по номеру записи MFT."),
        };
        if (_ambiguous > 0)
        {
            limitations.Add(new Limitation("CORR.AMBIGUOUS_PATH", $"{_ambiguous} записей без номера MFT не привязаны: по их пути в разное время были разные файлы."));
        }

        return new CorrelationResult(objects, findings, limitations);
    }

    // ----- Linking -----

    private sealed class Sets(int n)
    {
        private readonly int[] _parent = Enumerable.Range(0, n).ToArray();

        public int Find(int x)
        {
            while (_parent[x] != x)
            {
                _parent[x] = _parent[_parent[x]];
                x = _parent[x];
            }

            return x;
        }

        public void Union(int a, int b) => _parent[Find(a)] = Find(b);
    }

    /// <summary>
    /// First by MFT reference (volume, entry, sequence), then by path where no two different references would be
    /// joined. A path that belonged to different files at different times keeps them apart.
    /// </summary>
    private List<List<(EvidenceFacts Fact, LinkKind Link)>> Link(IReadOnlyList<EvidenceFacts> facts)
    {
        var candidates = facts.Where(IsObjectFact).ToList();
        var drives = DriveOfSerial(candidates);
        var sets = new Sets(candidates.Count);
        var refOf = new string?[candidates.Count];
        var linkedByRef = new bool[candidates.Count];

        var byRef = new Dictionary<string, int>(StringComparer.Ordinal);
        for (var i = 0; i < candidates.Count; i++)
        {
            if (Reference(candidates[i], drives) is not { } key)
            {
                continue;
            }

            refOf[i] = key;
            if (byRef.TryGetValue(key, out var first))
            {
                sets.Union(i, first);
                linkedByRef[i] = linkedByRef[first] = true;
            }
            else
            {
                byRef[key] = i;
            }
        }

        // The reference each set carries (one at most: sets so far are joined by reference only).
        var setRef = new Dictionary<int, string>();
        for (var i = 0; i < candidates.Count; i++)
        {
            if (refOf[i] is { } r)
            {
                setRef[sets.Find(i)] = r;
            }
        }

        var byPath = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        for (var i = 0; i < candidates.Count; i++)
        {
            foreach (var p in Paths(candidates[i]))
            {
                if (!byPath.TryGetValue(p, out var list))
                {
                    byPath[p] = list = [];
                }

                list.Add(i);
            }
        }

        var linkedByPath = new bool[candidates.Count];
        foreach (var (_, members) in byPath)
        {
            var roots = members.Select(sets.Find).Distinct().ToList();
            if (roots.Count < 2)
            {
                continue;
            }

            var refs = roots.Where(setRef.ContainsKey).Select(r => setRef[r]).Distinct(StringComparer.Ordinal).ToList();
            if (refs.Count > 1)
            {
                // Several files had this path at different times; which one a referenceless record means cannot be decided.
                _ambiguous += roots.Count(r => !setRef.ContainsKey(r));
                continue;
            }

            var target = roots.FirstOrDefault(setRef.ContainsKey, roots[0]);
            foreach (var r in roots.Where(r => r != target))
            {
                sets.Union(r, target);
            }

            var newRoot = sets.Find(target);
            if (refs.Count == 1)
            {
                setRef[newRoot] = refs[0];
            }

            foreach (var m in members)
            {
                linkedByPath[m] = true;
            }
        }

        return candidates
            .Select((f, i) => (Fact: f, Index: i))
            .GroupBy(x => sets.Find(x.Index))
            .Select(g => g.Select(x => (x.Fact, linkedByRef[x.Index] ? LinkKind.MftReference : LinkKind.Path)).ToList())
            .ToList();
    }

    /// <summary>Records about a file; system state (a cleared log, a setting) is not an object.</summary>
    internal static bool IsObjectFact(EvidenceFacts f)
    {
        if (f.Source == EvidenceSourceKind.EventLog && f.Attr("EventLog.EventId") is "104" or "1102" or "5001" or "5007")
        {
            return false;
        }

        if (f.Source == EvidenceSourceKind.UsnJournal && f.FileName == "$UsnJrnl")
        {
            return false;
        }

        return f.MftEntry is not null || f.NormalizedPath is not null;
    }

    private static Dictionary<ulong, string> DriveOfSerial(List<EvidenceFacts> facts)
    {
        var map = new Dictionary<ulong, string>();
        foreach (var f in facts)
        {
            if (f.VolumeSerial is { } s && Drive(f.NormalizedPath) is { } d)
            {
                map.TryAdd(s, d);
            }
        }

        return map;
    }

    private static string? Drive(string? normalized) =>
        normalized is { Length: >= 2 } && normalized[1] == ':' && char.IsAsciiLetter(normalized[0]) ? normalized[..2] : null;

    private static string? Reference(EvidenceFacts f, Dictionary<ulong, string> drives)
    {
        if (f.MftEntry is not { } entry || f.MftSequence is not { } seq)
        {
            return null;
        }

        var volume = Drive(f.NormalizedPath)
            ?? (f.VolumeSerial is { } s ? drives.GetValueOrDefault(s) ?? s.ToString("X8", CultureInfo.InvariantCulture) : null);
        return volume is null ? null : string.Create(CultureInfo.InvariantCulture, $"{volume}|{entry}|{seq}");
    }

    private static IEnumerable<string> Paths(EvidenceFacts f)
    {
        if (f.NormalizedPath is { } p)
        {
            yield return p;
        }

        if (PathNormalizer.Normalize(EvidenceFacts.PathOnly(f.Attr("Usn.OldPath"))) is { } old)
        {
            yield return old;
        }
    }

    private CorrelatedObject BuildObject(List<(EvidenceFacts Fact, LinkKind Link)> g)
    {
        var facts = g.Select(m => m.Fact).ToList();
        var times = facts.Where(f => f.Time is not null).Select(f => f.Time!.Value).ToList();
        var display = facts.Where(f => f.RecordedPath is not null)
            .GroupBy(f => f.RecordedPath!, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(x => x.Count())
            .ThenByDescending(x => x.Max(f => f.Time ?? DateTimeOffset.MinValue))
            .Select(x => x.Key)
            .FirstOrDefault();
        var normalized = PathNormalizer.Normalize(EvidenceFacts.PathOnly(display)) ?? facts.Select(f => f.NormalizedPath).FirstOrDefault(p => p is not null);
        var reference = facts.FirstOrDefault(f => f.MftEntry is not null && f.MftSequence is not null);
        return new CorrelatedObject
        {
            ObjectId = Ulid.NewUlid(time.GetUtcNow()),
            InvestigationId = investigationId,
            DisplayPath = display,
            NormalizedPath = normalized,
            FileName = facts.Select(f => f.FileName).FirstOrDefault(n => n is not null) ?? PathNormalizer.FileName(normalized),
            Volume = Drive(normalized) ?? reference?.VolumeSerial?.ToString("X8", CultureInfo.InvariantCulture),
            MftEntry = reference?.MftEntry,
            MftSequence = reference?.MftSequence,
            Sha256 = facts.Select(f => f.Sha256).FirstOrDefault(h => h is not null),
            OtherPaths = facts.SelectMany(Paths).Distinct(StringComparer.Ordinal).Where(p => p != normalized).Take(20).ToList(),
            FirstUtc = times.Count == 0 ? null : times.Min(),
            LastUtc = times.Count == 0 ? null : times.Max(),
            SourceFamilies = facts.Select(Family).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList(),
            Members = g.Select(m => new ObjectMember(m.Fact.Id, m.Link)).ToList(),
        };
    }

    /// <summary>Sources that do not share a writer or a structure count as independent.</summary>
    public static string Family(EvidenceFacts f) => f.Source switch
    {
        EvidenceSourceKind.FileSystem or EvidenceSourceKind.ZoneIdentifier => "files",
        EvidenceSourceKind.Mft => "mft",
        EvidenceSourceKind.UsnJournal => "usn",
        EvidenceSourceKind.RecycleBin => "recycle-bin",
        EvidenceSourceKind.Lnk or EvidenceSourceKind.JumpList or EvidenceSourceKind.ShellBags => "shell",
        EvidenceSourceKind.Prefetch => "prefetch",
        EvidenceSourceKind.Bam => "bam",
        EvidenceSourceKind.UserAssist => "userassist",
        EvidenceSourceKind.Amcache => "amcache",
        EvidenceSourceKind.EventLog when (f.Attr("EventLog.Channel") ?? string.Empty).Contains("Defender", StringComparison.OrdinalIgnoreCase) => "defender",
        EvidenceSourceKind.EventLog => "eventlog",
        EvidenceSourceKind.MinecraftLog => "minecraft-log",
        _ => f.Source.ToString().ToLowerInvariant(),
    };

    private static bool IsExecution(EvidenceFacts f) => f.Type is EvidenceEventType.Executed or EvidenceEventType.ExecutedLikely or EvidenceEventType.Loaded;

    // ----- Rules about one object -----

    private IEnumerable<Finding> ObjectRules(CorrelatedObject o, List<EvidenceFacts> facts)
    {
        var name = o.DisplayPath ?? o.FileName ?? "объект";
        var executions = facts.Where(IsExecution).ToList();

        // TIMESTOMP_CONFIRMED: $SI/$FN disagree, and the change journal recorded a time change on the same file.
        var anomalies = facts.Where(f => f.Source == EvidenceSourceKind.Mft && f.Attr("Mft.TimeAnomaly") is not null).ToList();
        var timeChanges = facts.Where(f => f.Source == EvidenceSourceKind.UsnJournal && f.Attr("Usn.BasicInfoChanges") is not null).ToList();
        if (anomalies.Count > 0 && timeChanges.Count > 0)
        {
            yield return Make("TIMESTOMP_CONFIRMED", Confidence.Medium, o, [.. anomalies, .. timeChanges], [],
                "Время файла установлено программно",
                $"Время файла {name} изменено программой: в MFT время создания расходится с временем NTFS ({anomalies[0].Attr("Mft.TimeAnomaly")}), а журнал изменений записал смену времени.",
                "Два независимых источника — запись MFT и журнал изменений — показывают, что время файла поставлено программой (SetFileTime), а не системой. Так подделывают даты, чтобы файл выглядел старым, но так же поступают архиваторы при распаковке с сохранением дат и программы копирования.");
        }

        // RAN_THEN_DELETED: a source shows the file ran or was loaded, another that it was deleted afterwards.
        var deletions = facts.Where(f => f.Type == EvidenceEventType.Deleted).ToList();
        if (executions.Count > 0 && deletions.Count > 0)
        {
            var firstRun = executions.Where(e => e.Time is not null).Select(e => e.Time!.Value).DefaultIfEmpty(DateTimeOffset.MinValue).Min();
            var after = deletions.Where(d => d.Time is null || d.Time >= firstRun - TimeSpan.FromMinutes(1)).ToList();
            if (after.Count > 0)
            {
                var deletedAt = after.Where(d => d.Time is not null).Select(d => d.Time!.Value).DefaultIfEmpty().Max();
                var recent = deletedAt != default && investigationStart - deletedAt < TimeSpan.FromDays(1);
                yield return Make("RAN_THEN_DELETED", Confidence.Low, o, [.. executions.Take(MaxContext), .. after], [],
                    "Запускался, затем удалён",
                    $"{name} запускался или загружался ({string.Join(", ", executions.Select(Family).Distinct())}), а затем был удалён ({string.Join(", ", after.Select(Family).Distinct())})" +
                    (deletedAt == default ? "." : $" {deletedAt.ToString("u", Ru)}{(recent ? " — меньше чем за сутки до проверки" : string.Empty)}."),
                    "Удаление использованной программы или мода — обычное дело (обновление, удаление ненужного). Это закономерность, а не признак нарушения сама по себе; она важна вместе с другими находками.");
            }
        }

        // HIDDEN_BY_RENAME: the file lost its telling extension (.jar → .txt), and it is a file that ran or was loaded.
        var hidingRenames = facts.Where(f => f.Source == EvidenceSourceKind.UsnJournal && f.Attr("Usn.ExtensionChanged") is not null && f.Confidence == Confidence.Low).ToList();
        if (hidingRenames.Count > 0 && executions.Count > 0)
        {
            yield return Make("HIDDEN_BY_RENAME", Confidence.Medium, o, [.. hidingRenames, .. executions.Take(MaxContext)], [],
                "Использованный файл переименован так, чтобы не выглядеть программой",
                $"{name}: расширение изменено ({hidingRenames[0].Attr("Usn.ExtensionChanged")}), и этот же файл запускался или загружался ({string.Join(", ", executions.Select(Family).Distinct())}).",
                "Журнал изменений показывает потерю расширения, независимый источник — что файл использовался. Так прячут моды и программы от беглой проверки; безобидные причины — ручное отключение мода переименованием, резервная копия.");
        }

        // DEFENDER_FLAGGED_AND_RAN: Microsoft Defender classified the file, and another source shows it ran.
        var detections = facts.Where(f => f.Attr("Defender.Threat") is not null).ToList();
        var otherRuns = executions.Where(e => Family(e) != "defender").ToList();
        if (detections.Count > 0 && otherRuns.Count > 0)
        {
            yield return Make("DEFENDER_FLAGGED_AND_RAN", Confidence.Medium, o, [.. detections, .. otherRuns.Take(MaxContext)], [],
                "Файл, отмеченный Защитником, запускался",
                $"Microsoft Defender определил {name} как «{detections[0].Attr("Defender.Threat")}», и этот файл запускался или загружался ({string.Join(", ", otherRuns.Select(Family).Distinct())}).",
                "Классификация Защитника и след запуска — независимые источники. Название угрозы — мнение Защитника: под HackTool и PUA попадают и читы, и безобидные утилиты.");
        }

        // AGENT_CONFIRMED: a launcher setting loads this file into the game, and another source shows it was loaded.
        var injections = facts.Where(f => f.Source == EvidenceSourceKind.Launcher && f.Attr("Jvm.Flag") is "javaagent" or "agentpath" or "bootclasspath" or "extramods").ToList();
        var loads = executions.Where(e => Family(e) != "launcher").ToList();
        if (injections.Count > 0 && loads.Count > 0)
        {
            yield return Make("AGENT_CONFIRMED", Confidence.Medium, o, [.. injections, .. loads.Take(MaxContext)], [],
                "Агент из настроек лаунчера действительно загружался",
                $"{name} подключается к игре параметром JVM ({injections[0].Attr("Jvm.Flag")}, {injections[0].Attr("Jvm.Where")}), и независимый источник показывает его загрузку ({string.Join(", ", loads.Select(Family).Distinct())}).",
                "Настройка лаунчера и след загрузки — независимые источники: агент не только прописан, но и работал. Так внедряют чит-клиенты; так же работают профилировщики и агенты оптимизации.");
        }

        // MODIFIED_FILE_LOADED: the game's own file differs from its version file, and it was loaded.
        var modified = facts.Where(f => f.Source == EvidenceSourceKind.Launcher && f.Attr("Sha1.Actual") is { Length: > 0 }).ToList();
        if (modified.Count > 0 && loads.Count > 0)
        {
            yield return Make("MODIFIED_FILE_LOADED", Confidence.Medium, o, [.. modified, .. loads.Take(MaxContext)], [],
                "Изменённый файл игры загружался",
                $"{name} отличается от хеша в файле версии {modified[0].Attr("Version.Id")} и загружался ({string.Join(", ", loads.Select(Family).Distinct())}).",
                "Несовпадение хеша (файлы игры) и загрузка (независимый источник). Безобидные причины — старые моды, встраиваемые в JAR, собственные сборки лаунчеров.");
        }
    }

    // ----- Signature database (stage 9) -----

    private static bool Identifies(SignatureMatch m) =>
        m.EntryStatus == "verified" && m.Kind is SignatureMatchKind.ExactHashMatch or SignatureMatchKind.VerifiedComponentMatch;

    /// <summary>
    /// One finding per database entry and object (or record outside objects), with the strongest kind of match;
    /// then KNOWN_CLIENT_ACTIVITY where a verified identification meets activity from other sources.
    /// </summary>
    private IEnumerable<Finding> SignatureFindings(IReadOnlyList<EvidenceFacts> facts, IReadOnlyList<SignatureMatch> matches, List<CorrelatedObject> objects, Dictionary<Ulid, List<(EvidenceFacts Fact, LinkKind Link)>> objectFacts)
    {
        if (matches.Count == 0)
        {
            yield break;
        }

        var byId = facts.ToDictionary(f => f.Id);
        var objectOf = new Dictionary<Ulid, CorrelatedObject>();
        foreach (var o in objects)
        {
            foreach (var m in o.Members)
            {
                objectOf[m.EvidenceId] = o;
            }
        }

        foreach (var g in matches.Where(m => byId.ContainsKey(m.EvidenceId))
                     .GroupBy(m => (m.ClientId, Key: objectOf.TryGetValue(m.EvidenceId, out var o) ? o.ObjectId : m.EvidenceId)))
        {
            var best = g.MaxBy(m => Strength(m.Kind))!;
            var basis = g.Select(m => byId[m.EvidenceId]).DistinctBy(f => f.Id).ToList();
            var o = objectOf.GetValueOrDefault(best.EvidenceId);
            var confidence = best.Kind switch
            {
                SignatureMatchKind.ExactHashMatch or SignatureMatchKind.VerifiedComponentMatch when best.EntryStatus == "verified" => Confidence.Medium,
                SignatureMatchKind.NameMatch when best.ClientKind is not ("launcher" or "generic") => Confidence.Low,
                _ => Confidence.Informational,
            };
            var status = best.EntryStatus switch
            {
                "verified" => "запись проверена по собственному источнику проекта",
                "candidate" => "кандидат, ещё не проверен по источникам",
                _ => "запись из списка заказчика, ещё не проверена по источникам",
            };
            var finding = Make("SIGNATURE_MATCH", confidence, o, basis, [],
                $"{KindText(best.Kind)}: {best.ClientName}",
                $"{best.Detail} {best.ClientName} — {ClientKindText(best.ClientKind)}; {status}." + (g.Count() > 1 ? $" Совпадений по этому объекту: {g.Count()}." : string.Empty),
                confidence switch
                {
                    Confidence.Medium => "Прямое опознание одного объекта: точный SHA-256 файла из указанного источника или компонент (идентификатор мода, пакет, класс запуска), подтверждённый исходным кодом проекта. Само по себе — не вывод о нарушении: файл мог лежать без использования, а некоторые проекты легальны в одиночной игре.",
                    Confidence.Low => "Совпадение по имени: файл можно переименовать, а безобидный файл — назвать так же. Это повод проверить объект, а не доказательство.",
                    _ => best.ClientKind is "launcher" or "generic"
                        ? "Название лаунчера или общий термин само по себе нарушением не считается."
                        : "Возможное совпадение: общеупотребительное слово или непроверенная запись; учтено только в связи с Minecraft.",
                },
                directIdentification: Identifies(best));
            yield return finding with { MatchKind = best.Kind, ClientId = best.ClientId, VerifiedIdentification = Identifies(best) };
        }

        // KNOWN_CLIENT_ACTIVITY: a verified identification and, on the same object, activity from other sources.
        foreach (var o in objects)
        {
            var members = objectFacts[o.ObjectId].Select(m => m.Fact).ToList();
            var ids = members.Select(f => f.Id).ToHashSet();
            var identification = matches.Where(m => ids.Contains(m.EvidenceId) && Identifies(m)).OrderByDescending(m => Strength(m.Kind)).FirstOrDefault();
            if (identification is null)
            {
                continue;
            }

            var identified = byId[identification.EvidenceId];
            var activity = members.Where(f => f.Id != identified.Id && Family(f) != Family(identified)
                                             && (IsExecution(f) || f.Type is EvidenceEventType.Deleted or EvidenceEventType.Renamed or EvidenceEventType.Moved || f.Attr("Jvm.Flag") is not null))
                .ToList();
            if (activity.Count == 0)
            {
                continue;
            }

            var families = activity.Select(Family).Append(Family(identified)).Distinct(StringComparer.Ordinal).Count();
            var confidence = families >= Finding.MinFamiliesForHigh ? Confidence.High : Confidence.Medium;
            var what = string.Join(", ", activity.Select(f => IsExecution(f) ? "запуск или загрузка" : f.Type == EvidenceEventType.Deleted ? "удаление" : f.Attr("Jvm.Flag") is not null ? "подключение через параметр JVM" : "переименование").Distinct());
            var finding = Make("KNOWN_CLIENT_ACTIVITY", confidence, o, [identified, .. activity.Take(MaxContext)], [],
                $"Опознанный {ClientKindText(identification.ClientKind)} {identification.ClientName}: следы использования",
                $"{o.DisplayPath ?? o.FileName} опознан как {identification.ClientName} ({KindText(identification.Kind)}: {identification.Matched}); по независимым источникам: {what} ({string.Join(", ", activity.Select(Family).Distinct())}).",
                confidence == Confidence.High
                    ? "Опознание по точному хешу или подтверждённому компоненту и следы использования минимум из двух других независимых источников. Это наиболее сильная форма вывода XIN SKAN, но решение о нарушении принимает человек: в одиночной игре и на некоторых серверах такие клиенты разрешены."
                    : "Опознание по точному хешу или подтверждённому компоненту и след использования из одного независимого источника.");
            yield return finding with { VerifiedIdentification = true, MatchKind = identification.Kind, ClientId = identification.ClientId };
        }
    }

    private static int Strength(SignatureMatchKind k) => k switch
    {
        SignatureMatchKind.ExactHashMatch => 5,
        SignatureMatchKind.VerifiedComponentMatch => 4,
        SignatureMatchKind.MultipleFeatureMatch => 3,
        SignatureMatchKind.NameMatch => 2,
        SignatureMatchKind.PossibleMatch => 1,
        _ => 0,
    };

    private static string KindText(SignatureMatchKind k) => k switch
    {
        SignatureMatchKind.ExactHashMatch => "Exact Hash Match — точный хеш",
        SignatureMatchKind.VerifiedComponentMatch => "Verified Component Match — подтверждённый компонент",
        SignatureMatchKind.MultipleFeatureMatch => "Multiple Feature Match — несколько признаков функций",
        SignatureMatchKind.NameMatch => "Name Match — совпадение имени",
        SignatureMatchKind.PossibleMatch => "Possible Match — возможное совпадение",
        _ => "Unknown",
    };

    private static string ClientKindText(string kind) => kind switch
    {
        "client" => "клиент",
        "utility" => "утилита автоматизации",
        "dll" => "внедряемая библиотека",
        "launcher" => "лаунчер",
        "loader" => "загрузчик",
        "tool" => "сторонний инструмент",
        "feature" => "название функции",
        _ => "общий термин",
    };

    // ----- Rules across objects -----

    /// <summary>EXCLUDED_AND_RAN: Defender was told not to scan a folder from which something ran.</summary>
    private IEnumerable<Finding> ExclusionRule(IReadOnlyList<EvidenceFacts> facts, List<CorrelatedObject> objects, Dictionary<Ulid, List<(EvidenceFacts Fact, LinkKind Link)>> members)
    {
        var exclusions = facts
            .Where(f => f.Attr("EventLog.EventId") == "5007" && f.Attr("Defender.Change") == "added" && f.Attr("Defender.ExclusionType") is "Paths" or "TemporaryPaths")
            .Select(f => (Fact: f, Folder: PathNormalizer.Normalize(EvidenceFacts.PathOnly(f.RecordedPath))))
            .Where(x => x.Folder is { Length: > 3 }) // not a whole drive ("C:\"): that is a sign of its own, not about one file
            .ToList();
        var inObjects = members.Values.SelectMany(m => m.Select(x => x.Fact.Id)).ToHashSet();
        var standalone = facts.Where(f => IsExecution(f) && IsObjectFact(f) && !inObjects.Contains(f.Id))
            .Select(f => (Object: (CorrelatedObject?)null, Runs: new List<EvidenceFacts> { f }, Path: f.NormalizedPath));
        var linked = objects.Select(o => (Object: (CorrelatedObject?)o, Runs: members[o.ObjectId].Select(m => m.Fact).Where(IsExecution).ToList(), Path: o.NormalizedPath));
        foreach (var (folder, items) in exclusions.GroupBy(x => x.Folder!).Select(g => (g.Key, g.Select(x => x.Fact).ToList())))
        {
            var runs = linked.Concat(standalone)
                .Where(x => x.Runs.Count > 0 && PathNormalizer.IsUnder(x.Path, folder))
                .ToList();
            if (runs.Count == 0)
            {
                continue;
            }

            var basis = items.Concat(runs.SelectMany(r => r.Runs)).Take(MaxContext + items.Count).ToList();
            yield return Make("EXCLUDED_AND_RAN", Confidence.Medium, runs.Count == 1 ? runs[0].Object : null, basis, [],
                "Из папки, исключённой из проверки Защитника, запускались программы",
                $"Защитнику запретили проверять {items[0].RecordedPath}, и оттуда запускалось или загружалось: {string.Join(", ", runs.Select(r => r.Path).Distinct().Take(5))}{(runs.Count > 5 ? $" и ещё {runs.Count - 5}" : string.Empty)}.",
                "Исключение (журнал Защитника) и запуск из этой папки (независимый источник). Так прячут читы от удаления; исключения ставят и для игр, сборок модов, программ разработки.");
        }
    }

    /// <summary>CONCEALMENT_CLUSTER: concealment events from different sources close together in time.</summary>
    private IEnumerable<Finding> ConcealmentClusters(IReadOnlyList<EvidenceFacts> facts)
    {
        var events = facts.Where(f => f.Time is not null && ConcealmentKind(f) is not null).OrderBy(f => f.Time).ToList();
        var used = new HashSet<Ulid>();
        for (var i = 0; i < events.Count; i++)
        {
            if (used.Contains(events[i].Id))
            {
                continue;
            }

            var start = events[i].Time!.Value;
            var cluster = events.Skip(i).TakeWhile(e => e.Time!.Value - start <= ClusterWindow).Where(e => !used.Contains(e.Id)).ToList();
            var families = cluster.Select(Family).Distinct(StringComparer.Ordinal).ToList();
            if (families.Count < Finding.MinFamiliesForMedium)
            {
                continue;
            }

            foreach (var e in cluster)
            {
                used.Add(e.Id);
            }

            var end = cluster[^1].Time!.Value;
            var context = facts
                .Where(f => f.Type == EvidenceEventType.Deleted && f.Time is { } t && t >= start - ClusterWindow && t <= end + ClusterWindow)
                .OrderBy(f => f.Time)
                .Take(MaxContext)
                .ToList();
            yield return Make("CONCEALMENT_CLUSTER", Confidence.Medium, null, cluster, context,
                "Несколько признаков сокрытия в одно время",
                $"С {start.ToString("u", Ru)} по {end.ToString("u", Ru)}: {string.Join("; ", cluster.Select(e => ConcealmentKind(e)).Distinct())}." +
                (context.Count > 0 ? $" В это же время удалено файлов: {context.Count}." : string.Empty),
                "Признаки из разных независимых источников совпали по времени (окно 2 часа). Каждый по отдельности бывает безобидным — обслуживание системы, установка программ, работа администратора; совпадение — повод проверить, что происходило в это время.");
        }
    }

    internal static string? ConcealmentKind(EvidenceFacts f) => f switch
    {
        { Source: EvidenceSourceKind.EventLog } when f.Attr("EventLog.EventId") is "104" or "1102" => $"очищен журнал «{f.Attr("EventLog.ClearedChannel") ?? f.Attr("EventLog.Channel")}»",
        { Source: EvidenceSourceKind.EventLog } when f.Attr("EventLog.EventId") == "5001" => "выключена защита Защитника в реальном времени",
        { Source: EvidenceSourceKind.EventLog } when f.Attr("EventLog.EventId") == "5007" && f.Attr("Defender.Change") == "added" => $"добавлено исключение Защитника ({f.RecordedPath})",
        { Source: EvidenceSourceKind.UsnJournal, FileName: "$UsnJrnl" } => "журнал изменений создан заново",
        _ => null,
    };

    /// <summary>REMOVABLE_RUN: programs ran from a volume that is not attached now, and shortcuts show the same volume.</summary>
    private IEnumerable<Finding> RemovableRuns(IReadOnlyList<EvidenceFacts> facts)
    {
        var runs = facts.Where(f => IsExecution(f) && f.Attr("Volume.Serial") is not null).GroupBy(f => f.Attr("Volume.Serial")!, StringComparer.OrdinalIgnoreCase);
        foreach (var g in runs)
        {
            var links = facts.Where(f => string.Equals(f.Attr("Lnk.DriveSerial"), g.Key, StringComparison.OrdinalIgnoreCase)).Take(MaxContext).ToList();
            var label = links.Select(l => l.Attr("Lnk.VolumeLabel")).FirstOrDefault(l => l is not null);
            var type = links.Select(l => l.Attr("Lnk.DriveType")).FirstOrDefault(l => l is not null);
            yield return Make("REMOVABLE_RUN", Confidence.Low, null, [.. g.Take(MaxContext)], links,
                "Программы запускались с носителя, которого сейчас нет",
                $"С тома с серийным номером {g.Key}" + (label is null ? string.Empty : $" («{label}»{(type is null ? string.Empty : $", {type}")})") +
                $" запускалось: {string.Join(", ", g.Select(f => f.FileName ?? f.RecordedPath).Distinct().Take(5))}. Сейчас этот том не подключён." +
                (links.Count > 0 ? $" Ярлыков на этот том: {links.Count}." : string.Empty),
                "Запуск с флешки или другого диска, которого сейчас нет, не нарушение; но содержимое такого носителя проверить нельзя, и это стоит знать.");
        }
    }

    private Finding Make(string rule, Confidence confidence, CorrelatedObject? o, IReadOnlyList<EvidenceFacts> basis, IReadOnlyList<EvidenceFacts> context, string title, string description, string rationale, bool directIdentification = false)
    {
        var times = basis.Concat(context).Where(f => f.Time is not null).Select(f => f.Time!.Value).ToList();
        var families = basis.Select(Family).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();

        // The policy, applied once: without two independent families a rule cannot go above Low.
        if (confidence > Confidence.Low && families.Count < Finding.MinFamiliesForMedium && !directIdentification)
        {
            confidence = Confidence.Low;
        }

        if (confidence == Confidence.High && families.Count < Finding.MinFamiliesForHigh)
        {
            confidence = Confidence.Medium;
        }

        var members = basis.Select(f => new FindingMember(f.Id, "basis"))
            .Concat(context.Where(c => !basis.Any(b => b.Id == c.Id)).Select(f => new FindingMember(f.Id, "context")))
            .DistinctBy(m => m.EvidenceId)
            .ToList();
        return new Finding
        {
            FindingId = Ulid.NewUlid(time.GetUtcNow()),
            InvestigationId = investigationId,
            RuleId = rule,
            Confidence = confidence,
            Title = title,
            Description = description,
            Rationale = rationale,
            FirstUtc = times.Count == 0 ? null : times.Min(),
            LastUtc = times.Count == 0 ? null : times.Max(),
            ObjectId = o?.ObjectId,
            IndependentFamilies = families,
            Members = members,
        };
    }
}
