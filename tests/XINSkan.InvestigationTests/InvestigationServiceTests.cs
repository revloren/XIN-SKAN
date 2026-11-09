using System.Security.Cryptography;
using System.Text.Json;
using XINSkan.Analyzers.FileHunter;
using XINSkan.Core.IO;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.FileHunterTests.Support;
using XINSkan.Investigation;
using XINSkan.Models;
using XINSkan.Security;

namespace XINSkan.InvestigationTests;

/// <summary>
/// The end-to-end order of one investigation with a stand-in store: folder, audit, records, manifest, sealing,
/// and what is left behind on cancellation and on store failure.
/// </summary>
public sealed class InvestigationServiceTests : IDisposable
{
    private readonly PlayerProfile _p = new();
    private readonly string _out = Path.Combine(Path.GetTempPath(), "xinskan-out-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        _p.Dispose();
        if (Directory.Exists(_out))
        {
            foreach (var f in Directory.EnumerateFiles(_out, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(f, FileAttributes.Normal);
            }

            Directory.Delete(_out, recursive: true);
        }
    }

    private FileHunterOptions Options => new() { UsersRoot = _p.Users, CurrentProfile = _p.Player, TempFolders = [_p.WindowsTemp] };

    private static PlatformServices Platform(IFileSource? files = null) =>
        new(SystemDirectoryLister.Instance, files ?? new TestFileSource(), NoSignatureVerifier.Instance, new FixedProbe(), "read, share read/write/delete");

    private static InvestigationService Service(StoreFactory factory, IFileSource? files = null) =>
        new(Platform(files), factory, TimeProvider.System, "test-1.0");

    [Fact]
    public async Task A_run_leaves_a_closed_folder_whose_manifest_and_audit_chain_verify()
    {
        FileStore? store = null;
        var outcome = await Service((o, i) => store = new FileStore(o, i)).RunAsync(
            new InvestigationRequest { OutputRoot = _out, FileHunter = Options, Operator = "  Модератор  " }, null, CancellationToken.None);

        Assert.NotNull(store);
        Assert.True(store!.Disposed);
        Assert.Equal("Модератор", store.Info.Operator);
        Assert.Equal(outcome.InvestigationId, store.Info.InvestigationId);
        Assert.Equal(store.Evidence.Count, outcome.EvidenceWritten);
        Assert.True(outcome.EvidenceWritten >= _p.ExpectedFiles.Count + _p.ExpectedDirectories.Count);
        Assert.False(outcome.Run.Cancelled);
        Assert.Equal(ModuleState.Completed, outcome.Run.Modules.Single(m => m.ModuleId == FileHunterAnalyzer.ModuleId).State);

        // Without raw volume access the MFT module is skipped and says why.
        var mft = outcome.Run.Modules.Single(m => m.ModuleId == XINSkan.Analyzers.History.MftAnalyzer.ModuleId);
        Assert.Equal(ModuleState.Skipped, mft.State);
        Assert.Contains("RawVolumeRead", mft.Reason, StringComparison.Ordinal);
        Assert.Equal(ModuleState.Skipped, outcome.Run.Modules.Single(m => m.ModuleId == XINSkan.Analyzers.History.UsnAnalyzer.ModuleId).State);

        // The folder is new, named after the run, and holds exactly what the run created.
        Assert.StartsWith(Path.Combine(_out, "XINSKAN-"), outcome.Folder, StringComparison.Ordinal);
        Assert.EndsWith(outcome.InvestigationId.ToString(), outcome.Folder, StringComparison.Ordinal);
        var names = Directory.EnumerateFiles(outcome.Folder).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToList();
        Assert.Equal(new[] { InvestigationService.AuditFileName, IntegrityManifest.DefaultName, FileStore.Name }.Order(StringComparer.Ordinal), names);

        // The store was closed before the manifest hashed it, so the manifest matches the final content.
        Assert.Empty(outcome.SelfCheck);
        Assert.Empty(IntegrityManifest.Verify(outcome.Folder));
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Path.Combine(outcome.Folder, IntegrityManifest.DefaultName)))), outcome.ManifestSha256.ToString());
        foreach (var f in Directory.EnumerateFiles(outcome.Folder))
        {
            Assert.True(File.GetAttributes(f).HasFlag(FileAttributes.ReadOnly), f);
        }

        // Every opened file is in the audit log, and the chain is intact.
        var audit = ReadAudit(outcome.Folder);
        using (var s = File.OpenRead(Path.Combine(outcome.Folder, InvestigationService.AuditFileName)))
        {
            var v = AuditLogger.Verify(s);
            Assert.True(v.Intact, v.Problem);
            Assert.Equal(audit.Count, v.Entries);
        }

        Assert.Equal("investigation-start", audit[0].Action);
        Assert.Equal("investigation-end", audit[^1].Action);
        Assert.Equal("ok", audit[^1].Result);
        Assert.Contains(audit, a => a.Action == "probe");
        Assert.Contains(audit, a => a.Action == "correlation" && a.Result == "ok");
        var opened = audit.Where(a => a.Action == "open-file").Select(a => a.Target).ToHashSet(StringComparer.Ordinal);
        foreach (var f in _p.ExpectedFiles)
        {
            Assert.Contains(f, opened);
        }

        Assert.All(audit.Where(a => a.Action == "open-file"), a => Assert.Equal("read, share read/write/delete", a.Access));
        Assert.Contains(audit, a => a.Action == "list-directory" && a.Target == _p.Player);
    }

    [Fact]
    public async Task Every_run_gets_its_own_folder_and_earlier_results_are_not_touched()
    {
        var first = await Service((o, i) => new FileStore(o, i)).RunAsync(new InvestigationRequest { OutputRoot = _out, FileHunter = Options }, null, CancellationToken.None);
        var before = Directory.EnumerateFiles(first.Folder).ToDictionary(f => f, f => (Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f))), File.GetLastWriteTimeUtc(f)));

        var second = await Service((o, i) => new FileStore(o, i)).RunAsync(new InvestigationRequest { OutputRoot = _out, FileHunter = Options }, null, CancellationToken.None);

        Assert.NotEqual(first.Folder, second.Folder);
        Assert.NotEqual(first.InvestigationId, second.InvestigationId);
        foreach (var (f, state) in before)
        {
            Assert.Equal(state, (Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f))), File.GetLastWriteTimeUtc(f)));
        }

        Assert.Empty(IntegrityManifest.Verify(first.Folder));
    }

    [Fact]
    public async Task A_cancelled_run_keeps_its_records_and_is_still_closed_with_a_manifest()
    {
        using var cts = new CancellationTokenSource();
        var files = new TestFileSource
        {
            Fail = path =>
            {
                if (path.EndsWith("options.txt", StringComparison.Ordinal))
                {
                    cts.Cancel();
                }

                return null;
            },
        };

        FileStore? store = null;
        var outcome = await Service((o, i) => store = new FileStore(o, i), files).RunAsync(
            new InvestigationRequest { OutputRoot = _out, FileHunter = Options }, null, cts.Token);

        Assert.True(outcome.Run.Cancelled);
        Assert.All(outcome.Run.Modules, m => Assert.Equal(ModuleState.Cancelled, m.State));
        Assert.Equal(store!.Evidence.Count, outcome.EvidenceWritten);
        Assert.Empty(outcome.SelfCheck);
        Assert.True(File.Exists(Path.Combine(outcome.Folder, IntegrityManifest.DefaultName)));
        Assert.Equal("cancelled", ReadAudit(outcome.Folder)[^1].Result);
    }

    [Fact]
    public async Task A_store_failure_is_rethrown_and_the_folder_is_left_visibly_unclosed()
    {
        var ex = await Assert.ThrowsAsync<InvestigationSinkException>(() => Service((o, i) => new FileStore(o, i) { FailAfter = 3 })
            .RunAsync(new InvestigationRequest { OutputRoot = _out, FileHunter = Options }, null, CancellationToken.None));
        Assert.Equal("disk full", Assert.IsType<IOException>(ex.InnerException).Message);

        var folder = Assert.Single(Directory.EnumerateDirectories(_out));
        Assert.False(File.Exists(Path.Combine(folder, IntegrityManifest.DefaultName)));
        var audit = ReadAudit(folder);
        Assert.Equal("investigation-failed", audit[^1].Action);
        Assert.Contains("disk full", audit[^1].Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Consents_are_recorded_and_output_on_an_investigated_volume_is_flagged()
    {
        var outcome = await Service((o, i) => new FileStore(o, i)).RunAsync(
            new InvestigationRequest
            {
                OutputRoot = _out,
                FileHunter = Options,
                Consents = [(Consent.BrowserDownloadHistory, "Владелец ПК", "Разрешаю просмотр истории загрузок")],
            },
            null,
            CancellationToken.None);

        Assert.True(outcome.Permissions.Has(Consent.BrowserDownloadHistory));
        Assert.Contains(ReadAudit(outcome.Folder), a => a.Action == "consent" && a.Target == nameof(Consent.BrowserDownloadHistory) && a.Detail!.Contains("Владелец ПК", StringComparison.Ordinal));

        // The output folder and the profiles share a volume here.
        Assert.True(outcome.OutputLocation.OnInvestigatedVolume);
    }

    [Fact]
    public void Investigated_volumes_are_derived_from_every_scanned_root()
    {
        var roots = InvestigationService.InvestigatedVolumes(new FileHunterOptions
        {
            UsersRoot = Path.Combine(_p.Root, "Users"),
            CurrentProfile = _p.Player,
            TempFolders = [_p.WindowsTemp],
            ExtraRoots = ["", "   "],
        });

        Assert.Equal(Path.GetPathRoot(_p.Root), Assert.Single(roots));
    }

    private sealed record AuditLine(string Action, string Target, string Access, string Result, string? Detail);

    private static List<AuditLine> ReadAudit(string folder) =>
        File.ReadAllLines(Path.Combine(folder, InvestigationService.AuditFileName))
            .Where(l => l.Length > 0)
            .Select(l =>
            {
                using var d = JsonDocument.Parse(l);
                var r = d.RootElement;
                return new AuditLine(
                    r.GetProperty("action").GetString()!,
                    r.GetProperty("target").GetString()!,
                    r.GetProperty("access").GetString()!,
                    r.GetProperty("result").GetString()!,
                    r.TryGetProperty("detail", out var det) && det.ValueKind == JsonValueKind.String ? det.GetString() : null);
            })
            .ToList();

    /// <summary>
    /// Stand-in store: keeps records in memory and writes them to its own file only when closed, so a manifest
    /// written before closing would not match.
    /// </summary>
    private sealed class FileStore : IInvestigationSink, IDisposable
    {
        public const string Name = "store.jsonl";

        private readonly Stream _file;
        private readonly Lock _gate = new();

        public FileStore(OutputSink output, InvestigationInfo info)
        {
            Info = info;
            _file = output.CreateNew(Name);
        }

        public InvestigationInfo Info { get; }

        public List<Evidence> Evidence { get; } = [];

        public int? FailAfter { get; init; }

        public bool Disposed { get; private set; }

        public ValueTask AddEvidenceAsync(Evidence evidence, CancellationToken cancellationToken)
        {
            lock (_gate)
            {
                if (Evidence.Count >= FailAfter)
                {
                    throw new IOException("disk full");
                }

                Evidence.Add(evidence);
            }

            return ValueTask.CompletedTask;
        }

        public ValueTask AddCoverageAsync(SourceCoverage coverage, CancellationToken cancellationToken) => ValueTask.CompletedTask;

        public ValueTask AddErrorAsync(string moduleId, ModuleError moduleError, CancellationToken cancellationToken) => ValueTask.CompletedTask;

        public ValueTask CheckpointAsync(ModuleResult result, CancellationToken cancellationToken) => ValueTask.CompletedTask;

        public void Dispose()
        {
            if (Disposed)
            {
                return;
            }

            Disposed = true;
            using (var w = new StreamWriter(_file))
            {
                foreach (var e in Evidence)
                {
                    w.WriteLine(e.EvidenceId.ToString());
                }
            }
        }
    }
}
