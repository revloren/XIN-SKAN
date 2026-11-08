namespace XINSkan.App.Services;

public enum ModuleReadiness
{
    Ready,
    Planned,
}

/// <summary>A row in "what this build can do". Status comes from the code that exists, not from intentions.</summary>
public sealed record ModuleInfo(string Name, string Purpose, ModuleReadiness Readiness, int Stage)
{
    public string StatusText => Readiness == ModuleReadiness.Ready ? "Готов" : $"Этап {Stage}";

    public bool IsReady => Readiness == ModuleReadiness.Ready;
}

/// <summary>
/// Single source of truth for module status shown in the interface. A module moves to Ready only in the commit
/// that connects a working, tested analyzer (see docs/PROGRESS.md).
/// </summary>
public static class ModuleCatalog
{
    public static IReadOnlyList<ModuleInfo> Foundation { get; } =
    [
        new("Ядро и модели", "Конвейер проверки, схема свидетельств, разрешения и согласия", ModuleReadiness.Ready, 1),
        new("Защита только для чтения", "Запрет изменений при компиляции, проверка IL, замер на NTFS", ModuleReadiness.Ready, 2),
        new("Хранилище", "База SQLite на проверку, записи только добавляются", ModuleReadiness.Ready, 3),
    ];

    public static IReadOnlyList<ModuleInfo> Analyzers { get; } =
    [
        new("File Hunter", "Существующие файлы: имена, хеши, подписи, метаданные", ModuleReadiness.Planned, 4),
        new("History Engine", "MFT, USN Journal, Корзина, LNK, Jump Lists, ShellBags, логи Minecraft", ModuleReadiness.Planned, 5),
        new("Execution Engine", "Prefetch, Amcache, BAM, SRUM, журналы событий", ModuleReadiness.Planned, 6),
        new("Корреляция", "Связи между свидетельствами и единая хронология", ModuleReadiness.Planned, 7),
        new("Minecraft Integrity", "Экземпляры, моды, профили лаунчеров", ModuleReadiness.Planned, 8),
        new("База клиентов и признаков", "Известные клиенты, псевдонимы, функции, проверенные хеши", ModuleReadiness.Planned, 9),
        new("Network Monitor", "Соединения и трафик по процессам — только с согласия", ModuleReadiness.Planned, 10),
        new("Cloud Trace", "Загрузки браузеров и Telegram — только с согласия", ModuleReadiness.Planned, 11),
        new("Отчёты", "Для администрации и для эксперта: PDF, HTML, JSON", ModuleReadiness.Planned, 12),
    ];

    public static bool AnyAnalyzerReady => Analyzers.Any(a => a.IsReady);
}
