using System.IO;
using XINSkan.App.Services;
using XINSkan.App.ViewModels;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;
using XINSkan.Security;
using XINSkan.Storage;

namespace XINSkan.AppTests;

/// <summary>The interface shows only real data: these tests pin the data paths behind the screens.</summary>
public sealed class AppDataTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 8, 12, 0, 0, TimeSpan.Zero);
    private readonly string _root = Path.Combine(Path.GetTempPath(), "xinskan-app-" + Guid.NewGuid().ToString("N"));

    public AppDataTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public void Only_delivered_analyzers_are_marked_ready()
    {
        // Updated in the stage 4 commit together with File Hunter's tests and the investigation service.
        Assert.Equal(new[] { "File Hunter" }, ModuleCatalog.Analyzers.Where(m => m.IsReady).Select(m => m.Name));
        Assert.True(ModuleCatalog.AnyAnalyzerReady);
        Assert.All(ModuleCatalog.Analyzers.Where(m => m.Stage > 4), m => Assert.Equal(ModuleReadiness.Planned, m.Readiness));
        Assert.All(ModuleCatalog.Foundation, m => Assert.Equal(ModuleReadiness.Ready, m.Readiness));
    }

    [Fact]
    public void Every_capability_has_a_readable_name()
    {
        foreach (var c in Enum.GetValues<Capability>())
        {
            var row = CapabilityRow.From(new CapabilityState(c, false, "reason"));
            Assert.NotEqual(c.ToString(), row.Name);
        }
    }

    [Fact]
    public void Empty_or_missing_output_folder_shows_no_investigations()
    {
        Assert.Empty(InvestigationLibrary.Scan(Path.Combine(_root, "missing")));
        Assert.Empty(InvestigationLibrary.Scan(_root));
    }

    [Fact]
    public async Task Library_reads_a_real_investigation_and_verifies_its_manifest()
    {
        var clock = new FixedClock(T0);
        var sink = OutputSink.CreateInvestigationFolder(_root, "case-1");
        var id = Ulid.NewUlid(T0);
        var store = InvestigationStore.Create(sink, new InvestigationInfo { InvestigationId = id, StartedUtc = T0, ToolVersion = "test", Operator = "Модератор" }, clock);
        await store.AddEvidenceAsync(new Evidence
        {
            EvidenceId = Ulid.NewUlid(T0),
            InvestigationId = id,
            ModuleId = "file-hunter",
            Source = new SourceRef(EvidenceSourceKind.FileSystem, @"C:\Users\p\.minecraft\mods", "test", "1"),
            Locator = @"C:\Users\p\.minecraft\mods\x.jar",
            EventType = EvidenceEventType.Existed,
            Target = new ObjectRef { RecordedPath = @"C:\Users\p\.minecraft\mods\x.jar", FileName = "x.jar" },
            Confidence = Confidence.Informational,
            Rationale = "Exists.",
            CollectionStatus = CollectionStatus.Collected,
            Description = "File present.",
            CollectedAtUtc = T0,
        }, CancellationToken.None);
        await store.CheckpointAsync(new ModuleResult { ModuleId = "file-hunter", State = ModuleState.Completed, EvidenceCount = 1 }, CancellationToken.None);
        store.Dispose();

        var open = Assert.Single(InvestigationLibrary.Scan(_root));
        Assert.Equal(IntegrityState.NotClosed, open.Integrity);
        Assert.Equal(1, open.EvidenceCount);
        Assert.Equal("Модератор", open.Info!.Operator);

        IntegrityManifest.Write(sink, clock);
        Assert.Equal(IntegrityState.Verified, Assert.Single(InvestigationLibrary.Scan(_root)).Integrity);

        File.AppendAllText(Path.Combine(sink.Root, InvestigationStore.DatabaseFileName), "tamper");
        var broken = Assert.Single(InvestigationLibrary.Scan(_root));
        Assert.Equal(IntegrityState.Broken, broken.Integrity);
        Assert.NotEmpty(broken.IntegrityProblems);
    }

    [Fact]
    public void Unreadable_database_is_reported_not_hidden()
    {
        var folder = Directory.CreateDirectory(Path.Combine(_root, "corrupt")).FullName;
        File.WriteAllText(Path.Combine(folder, InvestigationStore.DatabaseFileName), "not a database");
        var s = Assert.Single(InvestigationLibrary.Scan(_root));
        Assert.Equal(IntegrityState.Unreadable, s.Integrity);
        Assert.NotNull(s.Error);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
