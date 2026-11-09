using System.IO;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows.Input;
using System.Windows.Media;
using XINSkan.App.Infrastructure;
using XINSkan.Analyzers.FileHunter;
using XINSkan.App.Services;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Investigation;
using XINSkan.Models;
using XINSkan.Security;
using XINSkan.Storage;

namespace XINSkan.App.ViewModels;

/// <summary>One entry of the navigation rail.</summary>
public sealed record NavItem(string Title, Geometry Icon, ObservableObject Page);

/// <summary>
/// A capability as the operator reads it: a Russian summary of what it means for the check, with the
/// platform's technical reason kept as <see cref="Detail"/> (shown as a tooltip and written to reports).
/// </summary>
public sealed record CapabilityRow(string Name, bool Available, string Reason, string Detail)
{
    public static CapabilityRow From(CapabilityState s)
    {
        ArgumentNullException.ThrowIfNull(s);
        var (name, ok, missing) = Describe(s.Capability);
        return new(name, s.Available, s.Available ? ok : missing, s.Reason);
    }

    private static (string Name, string Ok, string Missing) Describe(Capability c) => c switch
    {
        Capability.Administrator => ("Права администратора", "Программа запущена от имени администратора.", "Программа запущена без прав администратора: источники, которым они нужны, будут пропущены."),
        Capability.RawVolumeRead => ("Чтение тома напрямую", "Системный том читается посекторно: доступны MFT и записи удалённых файлов.", "Том нельзя читать напрямую: MFT и записи удалённых файлов недоступны."),
        Capability.UsnJournalRead => ("Журнал изменений USN", "Журнал изменений системного тома активен и читается.", "Журнал изменений недоступен или отключён: история переименований и удалений будет неполной."),
        Capability.SystemRegistryHives => ("Защищённые ключи реестра", "Защищённые ключи (в том числе BAM) читаются.", "Защищённые ключи реестра недоступны: часть свидетельств запуска будет пропущена."),
        Capability.OtherUserProfiles => ("Профили других пользователей", "Профили других пользователей читаются или их нет.", "Профили других пользователей недоступны: их файлы не будут проверены."),
        Capability.SecurityEventLog => ("Журнал безопасности Windows", "Журнал безопасности читается.", "Пока не проверяется: источник журналов событий появится на этапе 6."),
        _ => (c.ToString(), "Доступно.", "Недоступно."),
    };
}

public sealed class MainViewModel : ObservableObject
{
    private NavItem _selected;

    public MainViewModel()
    {
        var env = new AppEnvironment();
        Items =
        [
            new NavItem("Обзор", Icons.Dashboard, new DashboardViewModel(env, this)),
            new NavItem("Проверка", Icons.Investigation, new InvestigationViewModel(env)),
            new NavItem("Хронология", Icons.Timeline, new TimelineViewModel(env)),
            new NavItem("Отчёты", Icons.Reports, new ReportsViewModel(env)),
            new NavItem("База клиентов", Icons.Database, new PlannedModuleViewModel(
                "База клиентов и признаков",
                "Каталог известных Minecraft-клиентов, их псевдонимов и функций с источниками и датой проверки. Совпадение по имени здесь никогда не будет доказательством само по себе.",
                9)),
            new NavItem("Сеть", Icons.Network, new PlannedModuleViewModel(
                "Network Monitor",
                "Соединения, порты и объём трафика по процессам. Запускается только после явного согласия владельца компьютера и не читает содержимое переписки, пароли и cookies.",
                10)),
            new NavItem("Настройки", Icons.Settings, new SettingsViewModel(env)),
        ];
        _selected = Items[0];
    }

    public IReadOnlyList<NavItem> Items { get; }

    public NavItem Selected
    {
        get => _selected;
        set => Set(ref _selected, value);
    }

    public void Navigate(int index) => Selected = Items[index];
}

public sealed class DashboardViewModel : ObservableObject
{
    private readonly AppEnvironment _env;
    private InvestigationSummary? _last;
    private bool _loading;
    private string? _status;

    public DashboardViewModel(AppEnvironment env, MainViewModel main)
    {
        _env = env;
        RefreshCommand = new AsyncCommand(RefreshAsync);
        StartCommand = new RelayCommand(() => main.Navigate(1));
        env.Changed += (_, _) => RefreshCommand.Execute(null);
        RefreshCommand.Execute(null);
    }

    public ObservableCollection<CapabilityRow> Readiness { get; } = [];

    public IReadOnlyList<ModuleInfo> Analyzers => ModuleCatalog.Analyzers;

    public IReadOnlyList<ModuleInfo> Foundation => ModuleCatalog.Foundation;

    public ICommand RefreshCommand { get; }

    public ICommand StartCommand { get; }

    public InvestigationSummary? LastInvestigation
    {
        get => _last;
        private set
        {
            Set(ref _last, value);
            OnPropertyChanged(nameof(HasLastInvestigation));
        }
    }

    public bool HasLastInvestigation => _last is not null;

    public string OutputFolder => _env.OutputRoot;

    public bool Loading
    {
        get => _loading;
        private set => Set(ref _loading, value);
    }

    public string? Status
    {
        get => _status;
        private set => Set(ref _status, value);
    }

    public string ReadyAnalyzersText =>
        $"{Analyzers.Count(a => a.IsReady)} из {Analyzers.Count}";

    private async Task RefreshAsync()
    {
        Loading = true;
        try
        {
            var snapshot = await AppEnvironment.ProbeAsync();
            Readiness.Clear();
            foreach (var s in snapshot.Capabilities.OrderBy(c => c.Capability))
            {
                Readiness.Add(CapabilityRow.From(s));
            }

            OnPropertyChanged(nameof(OutputFolder));
            var investigations = await Task.Run(() => InvestigationLibrary.Scan(_env.OutputRoot));
            LastInvestigation = investigations.Count > 0 ? investigations[0] : null;
            Status = null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Status = "Не удалось прочитать данные: " + ex.Message;
        }
        finally
        {
            Loading = false;
        }
    }
}

public sealed class InvestigationViewModel : ObservableObject
{
    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    private readonly AppEnvironment _env;
    private string _outputAssessment = string.Empty;
    private bool _outputOnInvestigatedVolume;
    private string _operatorName = string.Empty;
    private bool _isRunning;
    private string _progressText = string.Empty;
    private string _resultText = string.Empty;
    private bool _resultIsProblem;
    private Action? _cancel;

    public InvestigationViewModel(AppEnvironment env)
    {
        _env = env;
        RefreshCommand = new AsyncCommand(RefreshAsync);
        StartCommand = new AsyncCommand(StartAsync, () => CanStart && !IsRunning);
        CancelCommand = new RelayCommand(() => _cancel?.Invoke(), () => IsRunning);
        env.Changed += (_, _) => RefreshCommand.Execute(null);
        RefreshCommand.Execute(null);
    }

    public ObservableCollection<CapabilityRow> Capabilities { get; } = [];

    public IReadOnlyList<ModuleInfo> Analyzers => ModuleCatalog.Analyzers;

    public ICommand RefreshCommand { get; }

    public ICommand StartCommand { get; }

    public ICommand CancelCommand { get; }

    /// <summary>Starting is possible only once at least one real analyzer is connected.</summary>
    public bool CanStart => ModuleCatalog.AnyAnalyzerReady;

    public string StartHint => CanStart
        ? $"Проверка соберёт свидетельства подключёнными модулями ({string.Join(", ", ModuleCatalog.Analyzers.Where(a => a.Runs).Select(a => a.Name))}). Модули без нужных прав будут пропущены с указанием причины. Исследуемые данные только читаются."
        : "Запуск станет доступен, когда будет подключён первый анализатор.";

    public string OutputFolder => _env.OutputRoot;

    /// <summary>Who runs the check; stored in the investigation as entered.</summary>
    public string OperatorName
    {
        get => _operatorName;
        set => Set(ref _operatorName, value);
    }

    public bool IsRunning
    {
        get => _isRunning;
        private set
        {
            if (Set(ref _isRunning, value))
            {
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public string ProgressText
    {
        get => _progressText;
        private set => Set(ref _progressText, value);
    }

    public string ResultText
    {
        get => _resultText;
        private set => Set(ref _resultText, value);
    }

    public bool ResultIsProblem
    {
        get => _resultIsProblem;
        private set => Set(ref _resultIsProblem, value);
    }

    public string OutputAssessment
    {
        get => _outputAssessment;
        private set => Set(ref _outputAssessment, value);
    }

    public bool OutputOnInvestigatedVolume
    {
        get => _outputOnInvestigatedVolume;
        private set => Set(ref _outputOnInvestigatedVolume, value);
    }

    private async Task StartAsync()
    {
        IsRunning = true;
        ResultText = string.Empty;
        ProgressText = "Подготовка…";
        using var cts = new CancellationTokenSource();
        _cancel = cts.Cancel;
        try
        {
            // Progress<T> created here posts back to the interface thread.
            var progress = new Progress<ModuleProgress>(p => ProgressText = p.Message ?? $"{ModuleName(p.ModuleId)}: {StateText(p.State)}");
            var outcome = await InvestigationLauncher.RunAsync(_env.OutputRoot, OperatorName, progress, cts.Token);
            Describe(outcome);
        }
        catch (InvestigationSinkException ex)
        {
            ResultIsProblem = true;
            ResultText = $"Проверка остановлена: не удалось сохранить записи ({ex.InnerException?.Message ?? ex.Message}). Папка оставлена без манифеста и в списке проверок будет отмечена как незакрытая.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ResultIsProblem = true;
            ResultText = $"Не удалось создать папку проверки в «{_env.OutputRoot}»: {ex.Message}";
        }
        finally
        {
            _cancel = null;
            ProgressText = string.Empty;
            IsRunning = false;
            _env.NotifyInvestigationsChanged();
        }
    }

    private void Describe(InvestigationOutcome o)
    {
        var modules = string.Join("; ", o.Run.Modules.Select(m =>
            $"{ModuleName(m.ModuleId)}: {StateText(m.State)}, записей {m.EvidenceCount.ToString("N0", Ru)}" +
            (m.Errors.Count > 0 ? $", ошибок доступа {m.Errors.Count}" : string.Empty)));
        var head = o.Run.Cancelled
            ? "Проверка отменена. Собранные до отмены записи сохранены, папка закрыта манифестом."
            : "Проверка завершена.";
        var check = o.SelfCheck.Count == 0
            ? $"Манифест SHA-256 {o.ManifestSha256}."
            : $"Самопроверка манифеста не прошла: {o.SelfCheck.Count} расхождений.";
        ResultIsProblem = o.SelfCheck.Count > 0 || o.Run.Modules.Any(m => m.State is ModuleState.Failed);
        var findings = o.Correlation.Findings;
        var correlation = findings.Count == 0
            ? $"Корреляция: связано объектов {o.Correlation.Objects.Count.ToString("N0", Ru)}, находок нет."
            : $"Корреляция: связано объектов {o.Correlation.Objects.Count.ToString("N0", Ru)}, находок {findings.Count.ToString("N0", Ru)} (" +
              string.Join(", ", findings.GroupBy(f => f.Confidence).OrderByDescending(g => (int)g.Key).Select(g => $"{ConfidenceText(g.Key)} — {g.Count()}")) + ").";
        ResultText = $"{head} {modules}. {correlation} Папка: {o.Folder}. {check} Записи и находки — сведения и закономерности, а не выводы о нарушении.";
    }

    private static string ModuleName(string id) => id switch
    {
        FileHunterAnalyzer.ModuleId => "File Hunter",
        "mft" => "MFT",
        "usn" => "USN Journal",
        "recycle-bin" => "Корзина",
        "minecraft-logs" => "Логи Minecraft",
        "lnk" => "Ярлыки",
        "jumplists" => "Jump Lists",
        "shellbags" => "ShellBags",
        "prefetch" => "Prefetch",
        "bam" => "BAM",
        "amcache" => "Amcache",
        "eventlogs" => "Журналы событий",
        "userassist" => "UserAssist",
        "minecraft-integrity" => "Minecraft Integrity",
        "correlation" => "Корреляция",
        _ => id,
    };

    private static string ConfidenceText(Confidence c) => c switch
    {
        Confidence.High => "высокая",
        Confidence.Medium => "средняя",
        Confidence.Low => "низкая",
        Confidence.Inconclusive => "неопределённая",
        _ => "сведения",
    };

    private static string StateText(ModuleState s) => s switch
    {
        ModuleState.Completed => "завершено",
        ModuleState.CompletedWithErrors => "завершено с ошибками доступа",
        ModuleState.Skipped => "пропущено",
        ModuleState.Failed => "сбой",
        ModuleState.Cancelled => "отменено",
        ModuleState.Running => "выполняется",
        _ => s.ToString(),
    };

    private async Task RefreshAsync()
    {
        var snapshot = await AppEnvironment.ProbeAsync();
        Capabilities.Clear();
        foreach (var s in snapshot.Capabilities.OrderBy(c => c.Capability))
        {
            Capabilities.Add(CapabilityRow.From(s));
        }

        var (onInvestigated, text) = _env.DescribeOutput(_env.OutputRoot);
        OutputAssessment = text;
        OutputOnInvestigatedVolume = onInvestigated;
        OnPropertyChanged(nameof(OutputFolder));
    }
}

/// <summary>One line of the timeline, built from a stored evidence record.</summary>
public sealed record TimelineRow(Evidence Evidence)
{
    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    public string When => Evidence.Timestamp is { } t
        ? t.ValueUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss", Ru)
        : "время не записано";

    public string Precision => Evidence.Timestamp?.Precision switch
    {
        TimestampPrecision.TwoSeconds => "±2 с",
        TimestampPrecision.Seconds => "±1 с",
        TimestampPrecision.Day => "±1 сут.",
        null => string.Empty,
        _ => string.Empty,
    };

    public string Source => Evidence.Source.Kind.ToString();

    public string Event => Evidence.EventType.ToString();

    public string Target => Evidence.Target.RecordedPath ?? Evidence.Target.FileName ?? $"MFT {Evidence.Target.MftEntry}/{Evidence.Target.MftSequence}";

    public string Confidence => Evidence.Confidence.ToString();

    public string Description => Evidence.Description;

    public string Rationale => Evidence.Rationale;
}

public sealed class TimelineViewModel : ObservableObject
{
    private readonly AppEnvironment _env;
    private List<TimelineRow> _all = [];
    private InvestigationSummary? _selected;
    private string _filter = string.Empty;
    private string? _message;

    public TimelineViewModel(AppEnvironment env)
    {
        _env = env;
        RefreshCommand = new AsyncCommand(RefreshAsync);
        env.Changed += (_, _) => RefreshCommand.Execute(null);
        RefreshCommand.Execute(null);
    }

    public ObservableCollection<InvestigationSummary> Investigations { get; } = [];

    public ObservableCollection<TimelineRow> Rows { get; } = [];

    public ICommand RefreshCommand { get; }

    public InvestigationSummary? Selected
    {
        get => _selected;
        set
        {
            if (Set(ref _selected, value))
            {
                _ = LoadAsync(value);
            }
        }
    }

    public string Filter
    {
        get => _filter;
        set
        {
            if (Set(ref _filter, value))
            {
                ApplyFilter();
            }
        }
    }

    public string? Message
    {
        get => _message;
        private set => Set(ref _message, value);
    }

    private async Task RefreshAsync()
    {
        var found = await Task.Run(() => InvestigationLibrary.Scan(_env.OutputRoot));
        Investigations.Clear();
        foreach (var i in found)
        {
            Investigations.Add(i);
        }

        Selected = Investigations.FirstOrDefault();
        if (Selected is null)
        {
            _all = [];
            ApplyFilter();
            Message = $"В папке «{_env.OutputRoot}» пока нет проверок. Хронология появится после первой проверки.";
        }
    }

    private async Task LoadAsync(InvestigationSummary? summary)
    {
        if (summary is null)
        {
            return;
        }

        try
        {
            _all = await Task.Run(() =>
            {
                using var reader = InvestigationReader.Open(summary.DatabasePath);
                return reader.ReadEvidence()
                    .Select(e => new TimelineRow(e))
                    .OrderBy(r => r.Evidence.Timestamp?.ValueUtc ?? DateTimeOffset.MaxValue)
                    .ToList();
            });
            Message = _all.Count == 0 ? "В этой проверке нет свидетельств." : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or Microsoft.Data.Sqlite.SqliteException)
        {
            _all = [];
            Message = "Не удалось прочитать базу проверки: " + ex.Message;
        }

        ApplyFilter();
    }

    private void ApplyFilter()
    {
        Rows.Clear();
        var f = _filter.Trim();
        foreach (var r in _all)
        {
            if (f.Length == 0
                || r.Target.Contains(f, StringComparison.OrdinalIgnoreCase)
                || r.Description.Contains(f, StringComparison.OrdinalIgnoreCase)
                || r.Source.Contains(f, StringComparison.OrdinalIgnoreCase))
            {
                Rows.Add(r);
            }
        }
    }
}

public sealed class ReportsViewModel : ObservableObject
{
    private readonly AppEnvironment _env;
    private string? _message;

    public ReportsViewModel(AppEnvironment env)
    {
        _env = env;
        RefreshCommand = new AsyncCommand(RefreshAsync);
        env.Changed += (_, _) => RefreshCommand.Execute(null);
        RefreshCommand.Execute(null);
    }

    public ObservableCollection<InvestigationSummary> Investigations { get; } = [];

    public ICommand RefreshCommand { get; }

    public string? Message
    {
        get => _message;
        private set => Set(ref _message, value);
    }

    public string Note => "Отчёты для администрации и для эксперта появятся на этапе 12. Здесь уже видны сохранённые проверки и результат сверки их файлов с манифестом целостности.";

    private async Task RefreshAsync()
    {
        var found = await Task.Run(() => InvestigationLibrary.Scan(_env.OutputRoot));
        Investigations.Clear();
        foreach (var i in found)
        {
            Investigations.Add(i);
        }

        Message = found.Count == 0 ? $"В папке «{_env.OutputRoot}» пока нет проверок." : null;
    }
}

public sealed class PlannedModuleViewModel(string title, string description, int stage) : ObservableObject
{
    public string Title { get; } = title;

    public string Description { get; } = description;

    public string StageText { get; } = $"Модуль появится на этапе {stage}. До этого здесь не будет показано никаких данных, чтобы не выдавать пустой экран за результат проверки.";
}

public sealed class SettingsViewModel : ObservableObject
{
    private readonly AppEnvironment _env;
    private string _outputRoot;
    private string _assessment = string.Empty;
    private bool _onInvestigatedVolume;

    public SettingsViewModel(AppEnvironment env)
    {
        _env = env;
        _outputRoot = env.OutputRoot;
        ApplyCommand = new RelayCommand(Apply, () => !string.IsNullOrWhiteSpace(OutputRoot));
        Assess();
    }

    public string OutputRoot
    {
        get => _outputRoot;
        set
        {
            if (Set(ref _outputRoot, value))
            {
                Assess();
            }
        }
    }

    public string Assessment
    {
        get => _assessment;
        private set => Set(ref _assessment, value);
    }

    public bool OnInvestigatedVolume
    {
        get => _onInvestigatedVolume;
        private set => Set(ref _onInvestigatedVolume, value);
    }

    public ICommand ApplyCommand { get; }

    public string PersistenceNote => "Настройки действуют до закрытия программы и не сохраняются на этом компьютере: запись файла настроек изменила бы исследуемую систему.";

    public string Version => typeof(SettingsViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.1.0";

    private void Assess()
    {
        try
        {
            var (onInvestigated, text) = _env.DescribeOutput(_outputRoot);
            Assessment = text;
            OnInvestigatedVolume = onInvestigated;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            Assessment = "Путь указан неверно: " + ex.Message;
            OnInvestigatedVolume = false;
        }
    }

    private void Apply() => _env.OutputRoot = OutputRoot.Trim();
}
