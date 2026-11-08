using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows.Input;
using System.Windows.Media;
using XINSkan.App.Infrastructure;
using XINSkan.App.Services;
using XINSkan.Core.Permissions;
using XINSkan.Models;
using XINSkan.Security;
using XINSkan.Storage;

namespace XINSkan.App.ViewModels;

/// <summary>One entry of the navigation rail.</summary>
public sealed record NavItem(string Title, Geometry Icon, ObservableObject Page);

/// <summary>A capability as the operator should read it.</summary>
public sealed record CapabilityRow(string Name, bool Available, string Reason)
{
    public static CapabilityRow From(CapabilityState s) => new(Name(s.Capability), s.Available, s.Reason);

    private static string Name(Capability c) => c switch
    {
        Capability.Administrator => "Права администратора",
        Capability.RawVolumeRead => "Чтение тома напрямую (MFT)",
        Capability.UsnJournalRead => "Журнал изменений USN",
        Capability.SystemRegistryHives => "Защищённые ключи реестра",
        Capability.OtherUserProfiles => "Профили других пользователей",
        Capability.SecurityEventLog => "Журнал безопасности Windows",
        _ => c.ToString(),
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
    private readonly AppEnvironment _env;
    private string _outputAssessment = string.Empty;
    private bool _outputOnInvestigatedVolume;

    public InvestigationViewModel(AppEnvironment env)
    {
        _env = env;
        RefreshCommand = new AsyncCommand(RefreshAsync);
        StartCommand = new RelayCommand(() => { }, () => CanStart);
        env.Changed += (_, _) => RefreshCommand.Execute(null);
        RefreshCommand.Execute(null);
    }

    public ObservableCollection<CapabilityRow> Capabilities { get; } = [];

    public IReadOnlyList<ModuleInfo> Analyzers => ModuleCatalog.Analyzers;

    public ICommand RefreshCommand { get; }

    public ICommand StartCommand { get; }

    /// <summary>Starting is possible only once at least one real analyzer is connected.</summary>
    public bool CanStart => ModuleCatalog.AnyAnalyzerReady;

    public string StartHint => CanStart
        ? "Проверка соберёт свидетельства доступными модулями. Модули без нужных прав будут пропущены с указанием причины."
        : "Запуск станет доступен, когда будет подключён первый анализатор — File Hunter, этап 4. Сейчас готовы ядро, защита только для чтения и хранилище.";

    public string OutputFolder => _env.OutputRoot;

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

    private async Task RefreshAsync()
    {
        var snapshot = await AppEnvironment.ProbeAsync();
        Capabilities.Clear();
        foreach (var s in snapshot.Capabilities.OrderBy(c => c.Capability))
        {
            Capabilities.Add(CapabilityRow.From(s));
        }

        var a = _env.AssessOutput();
        OutputAssessment = a.Message;
        OutputOnInvestigatedVolume = a.OnInvestigatedVolume;
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
            var a = OutputLocationPolicy.Assess(_outputRoot, [_env.SystemDrive + "\\"]);
            Assessment = a.Message;
            OnInvestigatedVolume = a.OnInvestigatedVolume;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            Assessment = "Путь указан неверно: " + ex.Message;
            OnInvestigatedVolume = false;
        }
    }

    private void Apply() => _env.OutputRoot = OutputRoot.Trim();
}
