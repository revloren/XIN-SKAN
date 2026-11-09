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
/// UserAssist: Explorer counts the programs and shortcuts a user starts from the Start menu, desktop or
/// Explorer, with the last time and focus time. Names are ROT13-encoded; folders are known-folder GUIDs.
/// </summary>
public sealed class UserAssistAnalyzer(HistoryOptions options, IRegistryView currentUser, UserHives hives, IVolumeDirectory volumes) : IAnalyzer
{
    public const string ModuleId = "userassist";
    internal const string Key = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
    private const string ParserName = "xinskan-userassist";
    private const string ParserVersion = "1";

    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    /// <summary>Known folders that UserAssist writes as GUIDs (KNOWNFOLDERID).</summary>
    private static readonly Dictionary<string, string> KnownFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        ["{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"] = @"C:\Windows\System32",
        ["{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}"] = @"C:\Windows\SysWOW64",
        ["{F38BF404-1D43-42F2-9305-67DE0B28FC23}"] = @"C:\Windows",
        ["{6D809377-6AF0-444B-8957-A3773F02200E}"] = @"C:\Program Files",
        ["{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}"] = @"C:\Program Files (x86)",
        ["{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}"] = @"C:\Program Files\Common Files",
        ["{0762D272-C50A-4BB0-A382-697DCD729B80}"] = @"C:\Users",
    };

    /// <summary>Folders inside a profile, resolved against the profile whose hive is read.</summary>
    private static readonly Dictionary<string, string> ProfileFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        ["{374DE290-123F-4565-9164-39C4925E467B}"] = "Downloads",
        ["{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"] = "Desktop",
        ["{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"] = "Documents",
        ["{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}"] = @"AppData\Local",
        ["{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}"] = @"AppData\Roaming",
        ["{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}"] = @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs",
        ["{9E3995AB-1F9C-4F13-B827-48B24B6C7174}"] = @"AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned",
    };

    public string Id => ModuleId;

    public string DisplayName => "UserAssist";

    public AnalyzerRequirements Requirements { get; } = new() { OptionalCapabilities = [Capability.Administrator, Capability.RawVolumeRead, Capability.OtherUserProfiles] };

    public async Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var allowed = context.Permissions.Has(Capability.OtherUserProfiles);
        var users = new List<UserRegistry>();
        if (currentUser.SubKeys(Key) is not null)
        {
            users.Add(new UserRegistry(ProgramRelevance.FileName(options.CurrentProfile), options.CurrentProfile, null, currentUser, []));
            users.AddRange(hives.Load(allowed, includeCurrent: false));
        }
        else
        {
            users.AddRange(hives.Load(allowed, includeCurrent: true));
        }

        var resolver = new VolumeResolver(volumes.Volumes());
        var scope = new HistoryScope(options.UsersRoot, options.CurrentProfile, allowed, options.TempFolders, options.ExtraRoots);
        var limitations = new List<Limitation>
        {
            new("USERASSIST.SCOPE", "UserAssist записывает запуски из Проводника, меню «Пуск» и с рабочего стола; программы, запущенные из консоли или другими программами, в нём не видны."),
        };
        if (!allowed)
        {
            limitations.Add(new Limitation("USERASSIST.OTHER_USERS", "UserAssist других пользователей не прочитан: нет разрешения на чужие профили."));
        }

        limitations.AddRange(users.SelectMany(u => u.Problems.Select(p => new Limitation("USERASSIST.USER_HIVE", $"{u.User}: {p}"))));
        long read = 0, recorded = 0;
        DateTimeOffset? earliest = null, latest = null;
        foreach (var user in users)
        {
            foreach (var guid in user.View.SubKeys(Key) ?? [])
            {
                var count = $@"{Key}\{guid}\Count";
                foreach (var value in user.View.Values(count) ?? [])
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (value.Value is not byte[] data)
                    {
                        continue;
                    }

                    read++;
                    var entry = Decode(value.Name, data, user.Profile);
                    if (entry.Time is { } t)
                    {
                        earliest = earliest is null || t < earliest ? t : earliest;
                        latest = latest is null || t > latest ? t : latest;
                    }

                    if (entry.Path is null)
                    {
                        continue;
                    }

                    var (path, resolved, _) = resolver.Resolve(entry.Path);
                    var file = ProgramRelevance.FileName(path);
                    if (ProgramRelevance.Why(file, path, resolved, resolved && resolver.IsRemovable(path), scope) is not { } why)
                    {
                        continue;
                    }

                    await context.Writer.AddEvidenceAsync(Build(context, user, count, value.Name, entry, path, resolved, why), cancellationToken).ConfigureAwait(false);
                    recorded++;
                }
            }
        }

        await context.Writer.AddCoverageAsync(new SourceCoverage
        {
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = EvidenceSourceKind.UserAssist,
            Scope = string.Join("; ", users.Select(u => u.User)) is { Length: > 0 } names ? $"UserAssist: {names}" : "UserAssist: пользователей нет",
            Status = users.Any(u => u.Problems.Count > 0) ? CollectionStatus.Partial : CollectionStatus.Collected,
            ItemsRead = read,
            EarliestUtc = earliest,
            LatestUtc = latest,
            Limitations = limitations,
        }, cancellationToken).ConfigureAwait(false);
        context.Progress.Report(new ModuleProgress(Id, ModuleState.Running, $"Записей UserAssist {read.ToString("N0", Ru)}, записано {recorded.ToString("N0", Ru)}."));
    }

    internal sealed record Entry(string? Path, string Decoded, int? RunCount, int? FocusCount, TimeSpan? FocusTime, DateTimeOffset? Time);

    /// <summary>Decodes a value: ROT13 name, known-folder GUID, counters (Windows 7+: 72 bytes; XP: 16 bytes).</summary>
    internal static Entry Decode(string name, byte[] data, string profile)
    {
        var decoded = Rot13(name);
        string? path = decoded;
        if (decoded.StartsWith('{') && decoded.IndexOf('}', StringComparison.Ordinal) is var end and > 0)
        {
            var guid = decoded[..(end + 1)];
            var rest = decoded[(end + 1)..].TrimStart('\\');
            path = KnownFolders.TryGetValue(guid, out var folder) ? folder + "\\" + rest
                : ProfileFolders.TryGetValue(guid, out var inProfile) ? ProgramRelevance.Join(profile, inProfile, rest)
                : null; // an application ID (Store apps, shell items): no path
        }
        else if (!(decoded.Length > 2 && decoded[1] == ':') && !decoded.StartsWith(@"\\", StringComparison.Ordinal) && !decoded.StartsWith('/'))
        {
            path = null; // UEME_CTLSESSION, UEME_CTLCUACount:ctor and similar counters
        }

        int? runs = null, focus = null;
        TimeSpan? focusTime = null;
        DateTimeOffset? time = null;
        if (data.Length >= 68)
        {
            runs = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(4));
            focus = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(8));
            focusTime = TimeSpan.FromMilliseconds(BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(12)));
            time = NtfsTime.ToUtc(BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(60)));
        }
        else if (data.Length >= 16)
        {
            runs = Math.Max(0, BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(4)) - 5); // XP counts from 5
            time = NtfsTime.ToUtc(BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(8)));
        }

        return new Entry(path, decoded, runs, focus, focusTime, time);
    }

    internal static string Rot13(string s) => string.Create(s.Length, s, static (span, src) =>
    {
        for (var i = 0; i < src.Length; i++)
        {
            var c = src[i];
            span[i] = c switch
            {
                >= 'a' and <= 'z' => (char)('a' + ((c - 'a' + 13) % 26)),
                >= 'A' and <= 'Z' => (char)('A' + ((c - 'A' + 13) % 26)),
                _ => c,
            };
        }
    });

    private Evidence Build(AnalyzerContext context, UserRegistry user, string key, string valueName, Entry entry, string path, bool resolved, string why)
    {
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["UserAssist.User"] = user.User,
            ["UserAssist.Name"] = entry.Decoded,
            ["UserAssist.Why"] = why,
        };
        if (entry.RunCount is { } runs)
        {
            attrs["UserAssist.RunCount"] = runs.ToString(CultureInfo.InvariantCulture);
        }

        if (entry.FocusCount is { } focus)
        {
            attrs["UserAssist.FocusCount"] = focus.ToString(CultureInfo.InvariantCulture);
        }

        if (entry.FocusTime is { } ft)
        {
            attrs["UserAssist.FocusTime"] = ft.ToString("c", CultureInfo.InvariantCulture);
        }

        var shortcut = path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase);
        var prefix = user.Sid is null && ReferenceEquals(user.View, currentUser) ? "HKCU" : $"USER({user.User})";
        return new Evidence
        {
            EvidenceId = context.NewEvidenceId(),
            InvestigationId = context.InvestigationId,
            ModuleId = Id,
            Source = new SourceRef(EvidenceSourceKind.UserAssist, $@"{prefix}\{Key}", ParserName, ParserVersion),
            Locator = $@"{prefix}\{key}\{valueName}",
            EventType = EvidenceEventType.Executed,
            Timestamp = entry.Time is { } t ? new EvidenceTimestamp(t, "UserAssist.LastRun", TimestampPrecision.HundredNanoseconds) : null,
            Target = new ObjectRef
            {
                RecordedPath = path,
                NormalizedPath = resolved && path.Length > 2 && path[1] == ':' ? PathNormalizer.Normalize(path) : null,
                FileName = ProgramRelevance.FileName(path),
            },
            UserSid = user.Sid,
            Confidence = Confidence.Informational,
            Rationale = "UserAssist ведёт Проводник, когда пользователь запускает программу или ярлык из Проводника, меню «Пуск» или с рабочего стола: это след запуска.",
            CollectionStatus = CollectionStatus.Collected,
            Description = $"{(shortcut ? "Открыт ярлык" : "Запущена программа")} {path} (пользователь {user.User})" +
                          (entry.RunCount is { } r ? $", раз: {r}" : string.Empty) +
                          (entry.Time is { } last ? $", последний — {last.ToString("u", Ru)}." : "."),
            Attributes = attrs,
            CollectedAtUtc = context.Time.GetUtcNow(),
        };
    }
}
