using XINSkan.Core.Pipeline;
using XINSkan.Models;
using XINSkan.Security;
using XINSkan.Storage;

namespace XINSkan.App.Services;

public enum IntegrityState
{
    Verified,
    Broken,
    NotClosed,
    Unreadable,
}

/// <summary>What the interface shows about one stored investigation. Every field is read from its folder.</summary>
public sealed record InvestigationSummary(
    string Folder,
    string DatabasePath,
    InvestigationInfo? Info,
    long EvidenceCount,
    IReadOnlyList<ModuleResult> Modules,
    IntegrityState Integrity,
    IReadOnlyList<string> IntegrityProblems,
    string? Error)
{
    public string Title => Info is null ? System.IO.Path.GetFileName(Folder) : Info.StartedUtc.ToLocalTime().ToString("d MMMM yyyy, HH:mm", System.Globalization.CultureInfo.GetCultureInfo("ru-RU"));

    public string IntegrityText => Integrity switch
    {
        IntegrityState.Verified => "Целостность подтверждена манифестом",
        IntegrityState.Broken => $"Целостность нарушена: {IntegrityProblems.Count} расхождений",
        IntegrityState.NotClosed => "Проверка не закрыта: манифеста нет",
        _ => "Не удалось прочитать: " + Error,
    };

    public string ModulesText => Modules.Count == 0
        ? "Модули не запускались"
        : string.Join(", ", Modules.GroupBy(m => m.State).Select(g => $"{StateName(g.Key)}: {g.Count()}"));

    private static string StateName(ModuleState s) => s switch
    {
        ModuleState.Completed => "завершено",
        ModuleState.CompletedWithErrors => "с ошибками",
        ModuleState.Skipped => "пропущено",
        ModuleState.Failed => "сбой",
        ModuleState.Cancelled => "отменено",
        _ => s.ToString(),
    };
}

/// <summary>Finds investigations under the output folder and reads them read-only.</summary>
public static class InvestigationLibrary
{
    public static IReadOnlyList<InvestigationSummary> Scan(string root)
    {
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            return [];
        }

        var list = new List<InvestigationSummary>();
        foreach (var folder in Directory.EnumerateDirectories(root))
        {
            var db = Path.Combine(folder, InvestigationStore.DatabaseFileName);
            if (!Path.Exists(db))
            {
                continue;
            }

            list.Add(Read(folder, db));
        }

        return list.OrderByDescending(s => s.Info?.StartedUtc ?? DateTimeOffset.MinValue).ToList();
    }

    private static InvestigationSummary Read(string folder, string db)
    {
        try
        {
            using var reader = InvestigationReader.Open(db);
            var info = reader.ReadInfo();
            var count = reader.CountEvidence();
            var modules = reader.ReadModuleResults();

            IntegrityState state;
            IReadOnlyList<string> problems = [];
            if (!Path.Exists(Path.Combine(folder, IntegrityManifest.DefaultName)))
            {
                state = IntegrityState.NotClosed;
            }
            else
            {
                problems = IntegrityManifest.Verify(folder).Select(p => $"{p.Path}: {p.Problem}").ToList();
                state = problems.Count == 0 ? IntegrityState.Verified : IntegrityState.Broken;
            }

            return new InvestigationSummary(folder, db, info, count, modules, state, problems, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or Microsoft.Data.Sqlite.SqliteException or FormatException)
        {
            return new InvestigationSummary(folder, db, null, 0, [], IntegrityState.Unreadable, [], ex.Message);
        }
    }
}
