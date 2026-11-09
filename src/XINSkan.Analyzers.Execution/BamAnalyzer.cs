using System.Buffers.Binary;
using System.Globalization;
using XINSkan.Analyzers.History;
using XINSkan.Core.Paths;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;
using XINSkan.Ntfs;

namespace XINSkan.Analyzers.Execution;

/// <summary>
/// Background Activity Moderator (BAM) and Desktop Activity Moderator (DAM): per user, the programs that ran and
/// when each last did, kept by Windows 10 1709+ in HKLM\SYSTEM\CurrentControlSet\Services\bam.
/// </summary>
public sealed class BamAnalyzer(HistoryOptions options, IRegistryView machine, IVolumeDirectory volumes) : IAnalyzer
{
    public const string ModuleId = "bam";
    private const string ParserName = "xinskan-bam";
    private const string ParserVersion = "1";

    /// <summary>Windows 10 1809 and later; 1709–1803 kept the users directly under UserSettings.</summary>
    internal static readonly string[] Roots =
    [
        @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        @"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
        @"SYSTEM\CurrentControlSet\Services\dam\State\UserSettings",
        @"SYSTEM\CurrentControlSet\Services\dam\UserSettings",
    ];

    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    public string Id => ModuleId;

    public string DisplayName => "BAM";

    public AnalyzerRequirements Requirements { get; } = new() { OptionalCapabilities = [Capability.Administrator, Capability.OtherUserProfiles] };

    public async Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var resolver = new VolumeResolver(volumes.Volumes());
        var otherUsers = context.Permissions.Has(Capability.OtherUserProfiles);
        var scope = new HistoryScope(options.UsersRoot, options.CurrentProfile, otherUsers, options.TempFolders, options.ExtraRoots);
        var limitations = new List<Limitation>
        {
            new("BAM.WINDOW", "BAM хранит по одной записи на программу — время последнего запуска; записи старше примерно недели Windows удаляет при загрузке. Есть только в Windows 10 1709 и новее."),
            new("BAM.SCOPE", "BAM записывает в основном программы, запущенные из Проводника и консоли; консольные и фоновые программы могут отсутствовать."),
        };

        long read = 0, recorded = 0, skippedUsers = 0;
        var found = false;
        DateTimeOffset? earliest = null, latest = null;
        foreach (var root in Roots)
        {
            var sids = machine.SubKeys(root);
            if (sids is null)
            {
                continue;
            }

            found = true;
            foreach (var sid in sids)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var profile = machine.ProfileOf(sid);
                var isCurrent = profile is not null && string.Equals(profile.TrimEnd('\\'), options.CurrentProfile.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
                if (!isCurrent && !otherUsers)
                {
                    skippedUsers++;
                    continue;
                }

                foreach (var value in machine.Values(root + "\\" + sid) ?? [])
                {
                    if (value.Value is not byte[] { Length: >= 8 } data)
                    {
                        continue; // "Version", "SequenceNumber"
                    }

                    read++;
                    var time = NtfsTime.ToUtc(BinaryPrimitives.ReadInt64LittleEndian(data));
                    if (time is { } t)
                    {
                        earliest = earliest is null || t < earliest ? t : earliest;
                        latest = latest is null || t > latest ? t : latest;
                    }

                    if (Interpret(context, root, sid, profile, value.Name, time, resolver, scope) is { } evidence)
                    {
                        await context.Writer.AddEvidenceAsync(evidence, cancellationToken).ConfigureAwait(false);
                        recorded++;
                    }
                }
            }
        }

        if (!found)
        {
            limitations.Add(new Limitation("BAM.ABSENT", "Ключи BAM не найдены или не открылись: Windows старше 10 1709, служба отключена или нет прав администратора."));
        }

        if (skippedUsers > 0)
        {
            limitations.Add(new Limitation("BAM.OTHER_USERS", $"Записи других пользователей ({skippedUsers}) не прочитаны: нет разрешения на чужие профили."));
        }

        await context.Writer.AddCoverageAsync(new SourceCoverage
        {
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = EvidenceSourceKind.Bam,
            Scope = @"HKLM\SYSTEM\CurrentControlSet\Services\bam",
            Status = !found ? CollectionStatus.Skipped : skippedUsers > 0 ? CollectionStatus.Partial : CollectionStatus.Collected,
            ItemsRead = read,
            EarliestUtc = earliest,
            LatestUtc = latest,
            Limitations = limitations,
        }, cancellationToken).ConfigureAwait(false);
        context.Progress.Report(new ModuleProgress(Id, ModuleState.Running, $"Записей BAM {read.ToString("N0", Ru)}, записано {recorded.ToString("N0", Ru)}."));
    }

    private Evidence? Interpret(AnalyzerContext context, string root, string sid, string? profile, string name, DateTimeOffset? time, VolumeResolver resolver, HistoryScope scope)
    {
        // Packaged (Store) apps are recorded by package name, not path.
        if (!name.StartsWith('\\') && !(name.Length > 2 && name[1] == ':'))
        {
            return null;
        }

        var (path, resolved, _) = resolver.Resolve(name);
        var fileName = ProgramRelevance.FileName(path);
        var removable = resolved && resolver.IsRemovable(path);
        var why = ProgramRelevance.Why(fileName, path, resolved, removable, scope);
        if (why is null)
        {
            return null;
        }

        var limitations = new List<Limitation>();
        if (!resolved)
        {
            limitations.Add(new Limitation("PATH.VOLUME_UNKNOWN", "Том из записи BAM сейчас не подключён (например, флешка): путь показан так, как его записала система."));
        }

        var dam = root.Contains(@"\dam\", StringComparison.OrdinalIgnoreCase);
        return new Evidence
        {
            EvidenceId = context.NewEvidenceId(),
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = new SourceRef(EvidenceSourceKind.Bam, @"HKLM\" + root + "\\" + sid, ParserName, ParserVersion),
            Locator = @"HKLM\" + root + "\\" + sid + "\\" + name,
            EventType = EvidenceEventType.Executed,
            Timestamp = time is null ? null : new EvidenceTimestamp(time.Value, dam ? "Dam.LastExecution" : "Bam.LastExecution", TimestampPrecision.HundredNanoseconds),
            Target = new ObjectRef
            {
                RecordedPath = path,
                NormalizedPath = resolved ? PathNormalizer.Normalize(path) : null,
                FileName = fileName,
            },
            UserSid = sid,
            Confidence = Confidence.Informational,
            Rationale = "Запись BAM создаёт сама Windows, когда программа работает у пользователя: это след запуска. Время — последний раз, когда Windows обновила запись (по исследованиям — при завершении программы), а не обязательно момент запуска.",
            CollectionStatus = limitations.Count == 0 ? CollectionStatus.Collected : CollectionStatus.Partial,
            Description = $"Программа {fileName} ({path}) запускалась" + (profile is null ? $" пользователем {sid}" : $" пользователем {ProgramRelevance.FileName(profile)}") +
                          (time is null ? "." : $", последний раз — {time.Value.ToString("u", Ru)}."),
            Limitations = limitations,
            Attributes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Bam.Why"] = why,
                ["Bam.Source"] = dam ? "dam" : "bam",
                ["Bam.RecordedName"] = name,
            },
            CollectedAtUtc = context.Time.GetUtcNow(),
        };
    }
}
