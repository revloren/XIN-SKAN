using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.Versioning;
using System.Text;
using XINSkan.Analyzers.FileHunter;
using XINSkan.Core.Pipeline;
using XINSkan.Investigation;
using XINSkan.Models;
using XINSkan.Platform.Windows.IO;
using XINSkan.Security;
using XINSkan.Storage;

namespace XINSkan.Cli;

/// <summary>
/// xinskan investigate --output &lt;folder&gt; [--extra &lt;folder&gt;]... [--operator &lt;name&gt;]
/// xinskan verify &lt;investigation folder&gt;
/// Exit codes: 0 done, 1 done with module errors or skipped modules, 2 failed or broken, 3 cancelled, 64 usage.
/// </summary>
internal static class Program
{
    private const int Ok = 0;
    private const int Partial = 1;
    private const int Failed = 2;
    private const int Cancelled = 3;
    private const int Usage = 64;

    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    private static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("XIN SKAN работает только в Windows 10/11.");
            return Failed;
        }

        return args switch
        {
            ["investigate", .. var rest] => await InvestigateAsync(rest).ConfigureAwait(false),
            ["verify", var folder] => Verify(folder),
            _ => PrintUsage(),
        };
    }

    private static int PrintUsage()
    {
        Console.Error.WriteLine("""
            Использование:
              xinskan investigate --output <папка> [--extra <папка>]... [--operator <имя>]
                  Новая проверка. Результаты записываются в новую подпапку <папка>; исследуемые данные не изменяются.
              xinskan verify <папка проверки>
                  Проверяет манифест, цепочку журнала аудита и базу сохранённой проверки.
            """);
        return Usage;
    }

    [SupportedOSPlatform("windows")]
    private static async Task<int> InvestigateAsync(string[] args)
    {
        string? output = null;
        string? @operator = null;
        var extra = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            var hasValue = i + 1 < args.Length;
            switch (args[i])
            {
                case "--output" when hasValue:
                    output = args[++i];
                    break;
                case "--extra" when hasValue:
                    extra.Add(args[++i]);
                    break;
                case "--operator" when hasValue:
                    @operator = args[++i];
                    break;
                default:
                    Console.Error.WriteLine($"Непонятный аргумент: {args[i]}");
                    return PrintUsage();
            }
        }

        if (string.IsNullOrWhiteSpace(output))
        {
            Console.Error.WriteLine("Укажите папку для результатов: --output <папка>.");
            return PrintUsage();
        }

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            Console.Error.WriteLine("Отмена… Уже собранные записи будут сохранены.");
            cts.Cancel();
        };

        var version = typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
        var service = new InvestigationService(
            PlatformServices.ForWindows(),
            (sink, info) => InvestigationStore.Create(sink, info, TimeProvider.System),
            TimeProvider.System,
            version);

        var request = new InvestigationRequest
        {
            OutputRoot = output,
            FileHunter = FileHunterOptions.ForCurrentSystem(extra),
            Operator = @operator,
        };

        var location = OutputLocationPolicy.Assess(output, InvestigationService.InvestigatedVolumes(request.FileHunter));
        if (location.OnInvestigatedVolume)
        {
            Console.Error.WriteLine("Внимание: результаты будут записаны на исследуемый диск. Новые файлы могут занять место остатков удалённых файлов и появятся в журнале изменений. По возможности используйте внешний диск.");
        }

        var watch = Stopwatch.StartNew();
        var progress = new ConsoleProgress();
        InvestigationOutcome outcome;
        try
        {
            outcome = await service.RunAsync(request, progress, cts.Token).ConfigureAwait(false);
        }
        catch (InvestigationSinkException ex)
        {
            Console.Error.WriteLine($"Проверка остановлена: не удалось сохранить записи ({ex.InnerException?.Message ?? ex.Message}). Папка оставлена без манифеста и отмечена как незакрытая.");
            return Failed;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Не удалось создать папку проверки: {ex.Message}");
            return Failed;
        }

        Console.WriteLine();
        Console.WriteLine($"Проверка {outcome.InvestigationId}");
        Console.WriteLine($"  Папка:        {outcome.Folder}");
        Console.WriteLine($"  Записей:      {outcome.EvidenceWritten.ToString("N0", Ru)}");
        Console.WriteLine($"  Длительность: {watch.Elapsed.TotalSeconds.ToString("F1", Ru)} с");
        Console.WriteLine($"  Манифест:     SHA-256 {outcome.ManifestSha256}");
        foreach (var m in outcome.Run.Modules)
        {
            Console.WriteLine($"  Модуль {m.ModuleId}: {m.State}; записей {m.EvidenceCount}, покрытие {m.CoverageCount}, ошибок {m.Errors.Count}{(m.Reason is null ? string.Empty : "; " + m.Reason)}");
        }

        foreach (var c in outcome.Permissions.Capabilities.Where(c => !c.Available).OrderBy(c => c.Capability))
        {
            Console.WriteLine($"  Недоступно: {c.Capability} — {c.Reason}");
        }

        if (outcome.SelfCheck.Count > 0)
        {
            Console.Error.WriteLine("Самопроверка манифеста не прошла: " + string.Join("; ", outcome.SelfCheck.Select(p => $"{p.Path}: {p.Problem}")));
            return Failed;
        }

        if (outcome.Run.Cancelled)
        {
            return Cancelled;
        }

        return outcome.Run.Modules.All(m => m.State == ModuleState.Completed) ? Ok : Partial;
    }

    [SupportedOSPlatform("windows")]
    private static int Verify(string folder)
    {
        var broken = false;

        var manifest = IntegrityManifest.Verify(folder);
        Console.WriteLine(manifest.Count == 0 ? "Манифест: все файлы совпадают." : "Манифест: расхождения:");
        foreach (var p in manifest)
        {
            Console.WriteLine($"  {p.Path}: {p.Problem}");
            broken = true;
        }

        try
        {
            using var audit = ReadOnlyFile.OpenRead(Path.Combine(folder, InvestigationService.AuditFileName));
            var v = AuditLogger.Verify(audit);
            Console.WriteLine(v.Intact
                ? $"Журнал аудита: цепочка цела, записей {v.Entries.ToString("N0", Ru)}."
                : $"Журнал аудита: цепочка нарушена на записи {v.FirstBrokenSequence}: {v.Problem}");
            broken |= !v.Intact;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.WriteLine($"Журнал аудита не прочитан: {ex.Message}");
            broken = true;
        }

        try
        {
            using var reader = InvestigationReader.Open(Path.Combine(folder, InvestigationStore.DatabaseFileName));
            var info = reader.ReadInfo();
            Console.WriteLine($"База: проверка {info.InvestigationId} от {info.StartedUtc.ToLocalTime().ToString("g", Ru)}, записей {reader.CountEvidence().ToString("N0", Ru)}.");
            foreach (var m in reader.ReadModuleResults())
            {
                var took = m.FinishedUtc - m.StartedUtc;
                Console.WriteLine($"  Модуль {m.ModuleId}: {m.State}; записей {m.EvidenceCount}{(took is { } t ? $", {t.TotalSeconds.ToString("F1", Ru)} с" : string.Empty)}");
            }

            PrintSummary(reader.ReadEvidence().ToList());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or Microsoft.Data.Sqlite.SqliteException or FormatException)
        {
            Console.WriteLine($"База не прочитана: {ex.Message}");
            broken = true;
        }

        return broken ? Failed : Ok;
    }

    /// <summary>What the stored records consist of: a quick check that the selection is sensible on a real machine.</summary>
    private static void PrintSummary(List<Evidence> evidence)
    {
        void Group(string title, Func<Evidence, string> key, int top = 8)
        {
            var groups = evidence.GroupBy(key).OrderByDescending(g => g.Count()).Take(top);
            Console.WriteLine($"  {title}: " + string.Join(", ", groups.Select(g => $"{g.Key} {g.Count().ToString("N0", Ru)}")));
        }

        static string Attr(Evidence e, string name) => e.Attributes.TryGetValue(name, out var v) ? v : "—";

        Group("По модулям и событиям", e => $"{e.ModuleId}/{e.EventType}");
        Group("По причине отбора", e => Attr(e, "Selection"));
        Group("По содержимому", e => Attr(e, "Content"));
        Group("Подпись (только PE)", e => Attr(e, "Signature"));
        Group("Уверенность", e => e.Confidence.ToString());
        Group("Расхождение времени MFT", e => Attr(e, "Mft.TimeAnomaly"));
        Group("Ограничения", e => e.Limitations.Count == 0 ? "нет" : string.Join("+", e.Limitations.Select(l => l.Code).Where(c => c != "FS.SI_TIMES").DefaultIfEmpty("только FS.SI_TIMES")));
        foreach (var g in evidence.Where(e => e.EventType == EvidenceEventType.Deleted).GroupBy(e => e.ModuleId))
        {
            // Most recent first; records without a time (MFT) after them.
            foreach (var e in g.OrderByDescending(e => e.Timestamp?.ValueUtc ?? DateTimeOffset.MinValue).Take(15))
            {
                Console.WriteLine($"    удалено ({g.Key}): {e.Target.RecordedPath}");
            }
        }

        foreach (var g in evidence.Where(e => e.EventType is EvidenceEventType.Executed or EvidenceEventType.Loaded).GroupBy(e => e.ModuleId))
        {
            foreach (var e in g.OrderByDescending(e => e.Timestamp?.ValueUtc ?? DateTimeOffset.MinValue).Take(15))
            {
                var at = e.Timestamp is { } t ? t.ValueUtc.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) : "время неизвестно";
                Console.WriteLine($"    {(e.EventType == EvidenceEventType.Loaded ? "загружен" : "запуск")} ({g.Key}, {at}): {e.Target.RecordedPath}");
            }
        }

        Console.WriteLine("  Папки с наибольшим числом записей:");
        foreach (var g in evidence.GroupBy(e => Path.GetDirectoryName(e.Target.RecordedPath ?? string.Empty) ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(g => g.Count()).Take(8))
        {
            Console.WriteLine($"    {g.Count(),6}  {g.Key}");
        }
    }

    /// <summary>
    /// Prints module state changes and at most one progress line every two seconds; the last suppressed line is
    /// printed before the next state change, so a module's final message is never lost.
    /// </summary>
    private sealed class ConsoleProgress : IProgress<ModuleProgress>
    {
        private readonly Lock _gate = new();
        private long _lastTicks;
        private string? _pending;

        public void Report(ModuleProgress value)
        {
            lock (_gate)
            {
                var now = Stopwatch.GetTimestamp();
                var isProgressLine = value.State == ModuleState.Running && value.Message is not null;
                if (isProgressLine && Stopwatch.GetElapsedTime(_lastTicks, now) < TimeSpan.FromSeconds(2))
                {
                    _pending = $"[{value.ModuleId}] {value.Message}";
                    return;
                }

                if (!isProgressLine && _pending is not null)
                {
                    Console.WriteLine(_pending);
                }

                _pending = null;
                _lastTicks = now;
                Console.WriteLine(value.Message is null ? $"[{value.ModuleId}] {value.State}" : $"[{value.ModuleId}] {value.Message}");
            }
        }
    }
}
