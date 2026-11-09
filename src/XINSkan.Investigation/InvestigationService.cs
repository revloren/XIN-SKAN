using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using XINSkan.Analyzers.FileHunter;
using XINSkan.Analyzers.Execution;
using XINSkan.Analyzers.History;
using XINSkan.Analyzers.Minecraft;
using XINSkan.Correlation;
using XINSkan.Ntfs;
using XINSkan.Core.IO;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;
using XINSkan.Platform.Windows;
using XINSkan.Platform.Windows.IO;
using XINSkan.Security;

namespace XINSkan.Investigation;

/// <summary>What the platform provides: how files are listed and opened, how signatures and capabilities are checked.</summary>
/// <param name="FileAccess">How <paramref name="Files"/> opens files, as written to the audit log.</param>
public sealed record PlatformServices(
    IDirectoryLister Lister,
    IFileSource Files,
    ISignatureVerifier Signatures,
    ICapabilityProbe Probe,
    string FileAccess)
{
    /// <summary>Raw volume access for the History Engine. Without it the MFT module reports the volume as unreadable.</summary>
    public IVolumeOpener Volumes { get; init; } = NoVolumeAccess.Instance;

    /// <summary>Change journal access for the History Engine.</summary>
    public IUsnJournalSource Journal { get; init; } = NoUsnJournal.Instance;

    /// <summary>ShellBags of the current user.</summary>
    public IShellBagSource ShellBags { get; init; } = NoShellBags.Instance;

    /// <summary>HKEY_LOCAL_MACHINE for the Execution Engine (BAM, Prefetch settings, user profiles).</summary>
    public IRegistryView Machine { get; init; } = NoRegistry.Instance;

    /// <summary>Mounted volumes, to translate device paths in Prefetch and BAM to drive letters.</summary>
    public IVolumeDirectory VolumeDirectory { get; init; } = NoVolumeDirectory.Instance;

    /// <summary>HKEY_CURRENT_USER of the account running XIN SKAN (UserAssist).</summary>
    public IRegistryView CurrentUser { get; init; } = NoRegistry.Instance;

    /// <summary>Windows event logs for the Execution Engine.</summary>
    public IEventLogSource EventLogs { get; init; } = NoEventLogs.Instance;

    /// <summary>The read-only Windows implementations, for the system XIN SKAN runs on.</summary>
    [SupportedOSPlatform("windows")]
    public static PlatformServices ForWindows() => new(
        SystemDirectoryLister.Instance,
        WindowsFileSource.Instance,
        AuthenticodeVerifier.Instance,
        new WindowsCapabilityProbe(),
        WindowsFileSource.AccessDescription)
    {
        Volumes = WindowsVolumeOpener.Instance,
        Journal = WindowsUsnJournalSource.Instance,
        ShellBags = WindowsShellBagSource.Instance,
        Machine = WindowsRegistryView.Machine,
        CurrentUser = WindowsRegistryView.CurrentUser,
        VolumeDirectory = WindowsVolumeDirectory.Instance,
        EventLogs = WindowsEventLogSource.Instance,
    };
}

/// <summary>Used where raw volume access does not exist (tests, other platforms).</summary>
public sealed class NoVolumeAccess : IVolumeOpener
{
    public static readonly NoVolumeAccess Instance = new();

    public IRawVolume Open(string drive) => throw new UnauthorizedAccessException($"Raw access to {drive} is not available here.");
}

public sealed record InvestigationRequest
{
    /// <summary>Folder under which a new investigation folder is created.</summary>
    public required string OutputRoot { get; init; }

    public required FileHunterOptions FileHunter { get; init; }

    /// <summary>Who runs the check, as entered by the operator.</summary>
    public string? Operator { get; init; }

    /// <summary>Consents given by the owner for this investigation. None are assumed.</summary>
    public IReadOnlyList<(Consent Consent, string GrantedBy, string Statement)> Consents { get; init; } = [];
}

/// <summary>Result of one investigation, as written to its folder.</summary>
public sealed record InvestigationOutcome(
    Ulid InvestigationId,
    string Folder,
    InvestigationRunResult Run,
    long EvidenceWritten,
    Sha256Hash ManifestSha256,
    IReadOnlyList<IntegrityProblem> SelfCheck,
    OutputLocationAssessment OutputLocation,
    PermissionSnapshot Permissions)
{
    /// <summary>What correlation found; empty when it did not run (cancelled or failed before it).</summary>
    public CorrelationResult Correlation { get; init; } = new([], [], []);
}

/// <summary>Creates the evidence store inside the investigation folder (normally InvestigationStore.Create).</summary>
public delegate IInvestigationSink StoreFactory(OutputSink output, InvestigationInfo info);

/// <summary>
/// Runs one investigation end to end. The order is fixed so that a folder is either complete and covered by its
/// manifest, or visibly unfinished:
/// new folder → audit log → store → permissions → analyzers → correlation → close store → close audit → manifest → seal.
/// </summary>
/// <remarks>
/// Cancellation is not a failure: records collected so far are saved and the folder is closed with a manifest.
/// A failure of the store or the output folder is: the folder is left without a manifest, so the library shows
/// it as not closed, and the exception is rethrown.
/// </remarks>
public sealed class InvestigationService(PlatformServices platform, StoreFactory createStore, TimeProvider time, string toolVersion)
{
    public const string AuditFileName = "audit.jsonl";

    public async Task<InvestigationOutcome> RunAsync(InvestigationRequest request, IProgress<ModuleProgress>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.OutputRoot);

        var started = time.GetUtcNow();
        var id = Ulid.NewUlid(started);
        var location = OutputLocationPolicy.Assess(request.OutputRoot, InvestigatedVolumes(request.FileHunter));
        var folderName = string.Create(CultureInfo.InvariantCulture, $"XINSKAN-{started.UtcDateTime:yyyyMMdd-HHmmss}-{id}");
        var output = OutputSink.CreateInvestigationFolder(request.OutputRoot, folderName);

        var info = new InvestigationInfo
        {
            InvestigationId = id,
            StartedUtc = started,
            ToolVersion = toolVersion,
            Operator = string.IsNullOrWhiteSpace(request.Operator) ? null : request.Operator.Trim(),
            MachineName = Environment.MachineName,
            OsDescription = RuntimeInformation.OSDescription,
            TimeZoneId = TimeZoneInfo.Local.Id,
        };

        InvestigationRunResult run;
        long written;
        CorrelationResult correlation;
        PermissionSnapshot permissions;
        using (var audit = new AuditLogger(output.CreateNew(AuditFileName), time))
        {
            audit.Record("investigation-start", output.Root, "create-new", "ok", $"{id}; {location.Message}");

            var store = createStore(output, info);
            var counting = new CountingSink(store);
            try
            {
                var manager = new PermissionManager(platform.Probe, time);
                foreach (var (consent, grantedBy, statement) in request.Consents)
                {
                    manager.Grant(consent, grantedBy, statement);
                    audit.Record("consent", consent.ToString(), "granted", "ok", $"{grantedBy}: {statement}");
                }

                permissions = manager.Snapshot();
                foreach (var c in permissions.Capabilities.OrderBy(c => c.Capability))
                {
                    audit.Record("probe", c.Capability.ToString(), "query", c.Available ? "available" : "unavailable", c.Reason);
                }

                var lister = new AuditingDirectoryLister(platform.Lister, audit);
                var files = new AuditingFileSource(platform.Files, audit, platform.FileAccess);
                var machine = new AuditingRegistryView(platform.Machine, audit);
                // File Hunter first (what exists now), then history; the MFT pass leaves its path index for later modules.
                var history = new VolumeHistoryCache();
                var options = HistoryOptions.From(request.FileHunter);
                var locked = new ProtectedFileSource(files, new AuditingVolumeOpener(platform.Volumes, audit), history);
                var userHives = new UserHives(options, lister, locked, machine);
                IAnalyzer[] analyzers =
                [
                    new FileHunterAnalyzer(request.FileHunter, lister, files, platform.Signatures),
                    new MftAnalyzer(HistoryOptions.From(request.FileHunter), new AuditingVolumeOpener(platform.Volumes, audit), history),
                    new UsnAnalyzer(HistoryOptions.From(request.FileHunter), new AuditingJournalSource(platform.Journal, audit), history),
                    new RecycleBinAnalyzer(HistoryOptions.From(request.FileHunter), lister, files),
                    new MinecraftLogsAnalyzer(HistoryOptions.From(request.FileHunter), lister, files, TimeZoneInfo.Local),
                    new LnkAnalyzer(HistoryOptions.From(request.FileHunter), lister, files),
                    new JumpListAnalyzer(HistoryOptions.From(request.FileHunter), lister, files),
                    new ShellBagsAnalyzer(new AuditingShellBagSource(platform.ShellBags, audit), new OtherUserShellBags(userHives)),
                    new PrefetchAnalyzer(HistoryOptions.From(request.FileHunter), lister, files, platform.VolumeDirectory, machine),
                    new BamAnalyzer(HistoryOptions.From(request.FileHunter), machine, platform.VolumeDirectory),
                    new AmcacheAnalyzer(options, locked, platform.VolumeDirectory),
                    new UserAssistAnalyzer(options, new AuditingRegistryView(platform.CurrentUser, audit, "HKCU"), userHives, platform.VolumeDirectory),
                    new MinecraftIntegrityAnalyzer(
                        new MinecraftOptions { UsersRoot = request.FileHunter.UsersRoot, CurrentProfile = request.FileHunter.CurrentProfile, ExtraRoots = request.FileHunter.ExtraRoots },
                        lister,
                        files),
                    new EventLogAnalyzer(HistoryOptions.From(request.FileHunter), new AuditingEventLogSource(platform.EventLogs, audit), platform.VolumeDirectory),
                ];

                var runner = new InvestigationRunner(counting, permissions, time, progress);
                run = await runner.RunAsync(id, analyzers, cancellationToken).ConfigureAwait(false);
                written = counting.Evidence;

                // Correlation reads only what the analyzers wrote; a cancelled run is correlated as far as it got.
                correlation = await CorrelateAsync(id, started, store, counting, audit, progress, run.Cancelled).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Best effort only: the original failure is what the caller must see.
                TryQuietly(() => audit.Record("investigation-failed", output.Root, "-", "error", $"{ex.GetType().Name}: {ex.Message}"));
                TryQuietly(() => (store as IDisposable)?.Dispose());
                throw;
            }

            // Closing the store flushes the last batch; it must happen before the manifest hashes the database.
            (store as IDisposable)?.Dispose();
            audit.Record(
                "investigation-end",
                output.Root,
                "-",
                run.Cancelled ? "cancelled" : "ok",
                $"records {written}; modules: {string.Join(", ", run.Modules.Select(m => $"{m.ModuleId}={m.State}"))}");
        }

        var manifest = IntegrityManifest.Write(output, time);
        foreach (var file in output.CreatedFiles)
        {
            output.Seal(file);
        }

        var selfCheck = IntegrityManifest.Verify(output.Root);
        return new InvestigationOutcome(id, output.Root, run, written, manifest, selfCheck, location, permissions) { Correlation = correlation };
    }

    private async Task<CorrelationResult> CorrelateAsync(Ulid id, DateTimeOffset started, IInvestigationSink store, CountingSink counting, AuditLogger audit, IProgress<ModuleProgress>? progress, bool cancelled)
    {
        var facts = counting.Facts;
        progress?.Report(new ModuleProgress("correlation", ModuleState.Running, $"Корреляция {facts.Count:N0} записей…"));
        var clock = System.Diagnostics.Stopwatch.StartNew();
        CorrelationResult result;
        try
        {
            result = new CorrelationEngine(id, started, time).Run(facts);
        }
#pragma warning disable CA1031 // A defect in a rule must not lose the collected evidence: it is recorded and correlation is skipped.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            audit.Record("correlation-failed", "evidence", "read-only", "error", $"{ex.GetType().Name}: {ex.Message}");
            result = new CorrelationResult([], [], [new Limitation("CORR.FAILED", $"Корреляция не выполнена из-за ошибки: {ex.Message}. Собранные записи сохранены.")]);
        }

        if (cancelled)
        {
            result = result with { Limitations = [.. result.Limitations, new Limitation("CORR.CANCELLED", "Проверка была отменена: корреляция выполнена по тому, что успели собрать модули.")] };
        }

        if (store is ICorrelationSink sink)
        {
            await sink.AddCorrelationAsync(result, facts.Count, CancellationToken.None).ConfigureAwait(false);
        }

        audit.Record("correlation", "evidence", "read-only", "ok",
            $"records {facts.Count}; objects {result.Objects.Count}; findings {result.Findings.Count}; {clock.Elapsed.TotalSeconds:F1} s");
        progress?.Report(new ModuleProgress("correlation", ModuleState.Completed,
            $"Объектов {result.Objects.Count:N0}, находок {result.Findings.Count:N0} ({clock.Elapsed.TotalSeconds:F1} с)."));
        return result;
    }

    /// <summary>Volumes the analyzers read from, so the output policy can warn when results land on one of them.</summary>
    public static IReadOnlyList<string> InvestigatedVolumes(FileHunterOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return new[] { options.UsersRoot, options.CurrentProfile }
            .Concat(options.TempFolders)
            .Concat(options.ExtraRoots)
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => Path.GetPathRoot(Path.GetFullPath(p)))
            .Where(r => !string.IsNullOrEmpty(r))
            .Select(r => r!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static void TryQuietly(Action action)
    {
        try
        {
            action();
        }
#pragma warning disable CA1031 // Cleanup after a failure must not replace the failure being reported.
        catch (Exception)
#pragma warning restore CA1031
        {
        }
    }

    /// <summary>Counts records the store accepted and keeps what correlation needs of each.</summary>
    private sealed class CountingSink(IInvestigationSink inner) : IInvestigationSink
    {
        private readonly List<EvidenceFacts> _facts = [];
        private long _evidence;

        public long Evidence => Interlocked.Read(ref _evidence);

        public List<EvidenceFacts> Facts
        {
            get
            {
                lock (_facts)
                {
                    return [.. _facts];
                }
            }
        }

        public async ValueTask AddEvidenceAsync(Evidence evidence, CancellationToken cancellationToken)
        {
            await inner.AddEvidenceAsync(evidence, cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref _evidence);
            var facts = EvidenceFacts.From(evidence);
            lock (_facts)
            {
                _facts.Add(facts);
            }
        }

        public ValueTask AddCoverageAsync(SourceCoverage coverage, CancellationToken cancellationToken) => inner.AddCoverageAsync(coverage, cancellationToken);

        public ValueTask AddErrorAsync(string moduleId, ModuleError moduleError, CancellationToken cancellationToken) => inner.AddErrorAsync(moduleId, moduleError, cancellationToken);

        public ValueTask CheckpointAsync(ModuleResult result, CancellationToken cancellationToken) => inner.CheckpointAsync(result, cancellationToken);
    }
}
