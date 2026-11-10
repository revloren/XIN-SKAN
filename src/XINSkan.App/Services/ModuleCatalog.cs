namespace XINSkan.App.Services;

public enum ModuleReadiness
{
    Ready,

    /// <summary>Runs in every check, but part of its stated scope is not delivered yet (named in Purpose).</summary>
    Partial,

    Planned,
}

/// <summary>A row in "what this build can do". Status comes from the code that exists, not from intentions.</summary>
public sealed record ModuleInfo(string Name, string Purpose, ModuleReadiness Readiness, int Stage)
{
    public string StatusText => Readiness switch
    {
        ModuleReadiness.Ready => "Готов",
        ModuleReadiness.Partial => "Частично",
        _ => $"Этап {Stage}",
    };

    public bool IsReady => Readiness == ModuleReadiness.Ready;

    /// <summary>Runs in a check (ready or partly delivered).</summary>
    public bool Runs => Readiness != ModuleReadiness.Planned;
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
        new("File Hunter", "Существующие файлы: имена, хеши, подписи, метаданные", ModuleReadiness.Ready, 4),
        new("History Engine", "MFT, USN Journal, Корзина, LNK, Jump Lists, ShellBags, логи Minecraft. Ещё нет: теневые копии (ждут решения владельца)", ModuleReadiness.Partial, 5),
        new("Execution Engine", "Prefetch, BAM, Amcache, UserAssist, журналы событий. Ещё нет: SRUM", ModuleReadiness.Partial, 6),
        new("Корреляция", "Связь записей одного файла по номеру MFT и пути, девять опубликованных правил, находки Low/Medium. Ещё нет: связь по содержимому (SHA-1 Amcache), отчёт-хронология", ModuleReadiness.Partial, 7),
        new("Minecraft Integrity", "Лаунчеры и экземпляры, версии и загрузчики, параметры JVM, сверка клиента и библиотек с хешами из файлов версий. Ещё нет: сверка с хешами Mojang (этап 9), Modrinth app.db, настройки Lunar/Badlion/Feather", ModuleReadiness.Partial, 8),
        new("База клиентов и признаков", "Список заказчика и кандидаты; 9 проектов проверены по исходному коду; 57 хешей выпусков; совпадения по хешу, компонентам и именам; подписанные обновления. Ещё нет: хешей для проектов без файлов на GitHub, признаков функций (этап 10)", ModuleReadiness.Partial, 9),
        new("Network Monitor", "Соединения и трафик по процессам — только с согласия", ModuleReadiness.Planned, 10),
        new("Cloud Trace", "Загрузки браузеров и Telegram — только с согласия", ModuleReadiness.Planned, 11),
        new("Отчёты", "Для администрации и для эксперта: PDF, HTML, JSON", ModuleReadiness.Planned, 12),
    ];

    public static bool AnyAnalyzerReady => Analyzers.Any(a => a.IsReady);
}
