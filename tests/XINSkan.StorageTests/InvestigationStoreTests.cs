using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;
using XINSkan.Security;
using XINSkan.Storage;

namespace XINSkan.StorageTests;

internal sealed class Clock(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = start;

    public override DateTimeOffset GetUtcNow() => Now;
}

internal sealed class NoProbe : ICapabilityProbe
{
    public CapabilityState Probe(Capability capability) => new(capability, false, "Not needed in storage tests.");
}

internal sealed class Analyzer(string id, Func<AnalyzerContext, CancellationToken, Task> run) : IAnalyzer
{
    public string Id => id;

    public string DisplayName => id;

    public AnalyzerRequirements Requirements => AnalyzerRequirements.None;

    public Task RunAsync(AnalyzerContext context, CancellationToken cancellationToken) => run(context, cancellationToken);
}

public sealed class InvestigationStoreTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 8, 12, 0, 0, TimeSpan.Zero);
    private readonly string _base = Path.Combine(Path.GetTempPath(), "xinskan-store-" + Guid.NewGuid().ToString("N"));
    private readonly Clock _clock = new(T0);
    private readonly ITestOutputHelper _output;

    public InvestigationStoreTests(ITestOutputHelper output)
    {
        _output = output;
        Directory.CreateDirectory(_base);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var f in Directory.EnumerateFiles(_base, "*", SearchOption.AllDirectories))
        {
            File.SetAttributes(f, FileAttributes.Normal);
        }

        Directory.Delete(_base, recursive: true);
    }

    private (OutputSink Sink, InvestigationStore Store, Ulid Id) NewStore(string name = "inv", int batch = 5000)
    {
        var sink = OutputSink.CreateInvestigationFolder(_base, name);
        var id = Ulid.NewUlid(T0);
        var store = InvestigationStore.Create(sink, new InvestigationInfo
        {
            InvestigationId = id,
            StartedUtc = T0,
            ToolVersion = "0.1.0-test",
            Operator = "Тестовый оператор",
            MachineName = "TEST-PC",
            OsDescription = "Windows 11 26100",
            TimeZoneId = "Asia/Qostanay",
        }, _clock, batch);
        return (sink, store, id);
    }

    private static Evidence Rich(Ulid inv, string module, int i) => new()
    {
        EvidenceId = Ulid.NewUlid(T0.AddMilliseconds(i)),
        InvestigationId = inv,
        ModuleId = module,
        Source = new SourceRef(EvidenceSourceKind.UsnJournal, @"\\.\C:\$Extend\$UsnJrnl:$J", "xinskan-usn", "1.0"),
        Locator = $"USN 0x{0x1F0000 + i:X}",
        EventType = EvidenceEventType.Renamed,
        Timestamp = new EvidenceTimestamp(T0.AddSeconds(-i), "USN.TimeStamp", TimestampPrecision.HundredNanoseconds),
        OtherTimestamps =
        [
            new EvidenceTimestamp(T0.AddDays(-1), "Zip.Entry.Modified", TimestampPrecision.TwoSeconds, "local", TimeSpan.FromHours(14)),
        ],
        Target = new ObjectRef
        {
            RecordedPath = $@"C:\Users\Игрок\.minecraft\mods\client-{i}.jar",
            NormalizedPath = $@"C:\USERS\ИГРОК\.MINECRAFT\MODS\CLIENT-{i}.JAR",
            FileName = $"client-{i}.jar",
            VolumeSerial = 0xF1E2_D3C4_B5A6_9788UL,
            MftEntry = 0xFFFF_FFFF_FFFFUL - (ulong)i,
            MftSequence = 65535,
            Size = 1_234_567,
        },
        ObjectSha256 = Sha256Hash.FromBytes(SHA256.HashData(BitConverter.GetBytes(i))),
        ArtifactSha256 = Sha256Hash.FromBytes(SHA256.HashData(BitConverter.GetBytes(-i))),
        Confidence = Confidence.Low,
        Rationale = "Rename recorded by the change journal; a name alone does not identify the content.",
        CollectionStatus = CollectionStatus.Partial,
        Description = "client.jar was renamed.",
        Limitations = [new Limitation("USN.RETENTION", "The journal holds only recent changes.")],
        UserSid = "S-1-5-21-1-2-3-1001",
        Attributes = new Dictionary<string, string> { ["OldName"] = "cheat.jar", ["Reason"] = "RENAME_NEW_NAME|CLOSE" },
        CollectedAtUtc = T0,
    };

    [Fact]
    public async Task Evidence_round_trips_with_every_field()
    {
        var (sink, store, id) = NewStore();
        var original = Rich(id, "history", 7);
        await store.AddEvidenceAsync(original, CancellationToken.None);
        await store.CheckpointAsync(new ModuleResult { ModuleId = "history", State = ModuleState.Completed, EvidenceCount = 1 }, CancellationToken.None);
        store.Dispose();

        using var reader = InvestigationReader.Open(Path.Combine(sink.Root, InvestigationStore.DatabaseFileName));
        var back = Assert.Single(reader.ReadEvidence().ToList());

        Assert.Equal(original.EvidenceId, back.EvidenceId);
        Assert.Equal(original.Source, back.Source);
        Assert.Equal(original.Locator, back.Locator);
        Assert.Equal(original.EventType, back.EventType);
        Assert.Equal(original.Timestamp, back.Timestamp);
        Assert.Equal(original.OtherTimestamps.Single(), back.OtherTimestamps.Single());
        Assert.Equal(original.Target, back.Target);
        Assert.Equal(original.ObjectSha256, back.ObjectSha256);
        Assert.Equal(original.ArtifactSha256, back.ArtifactSha256);
        Assert.Equal(original.Confidence, back.Confidence);
        Assert.Equal(original.Rationale, back.Rationale);
        Assert.Equal(original.CollectionStatus, back.CollectionStatus);
        Assert.Equal(original.Description, back.Description);
        Assert.Equal(original.Limitations.Single(), back.Limitations.Single());
        Assert.Equal(original.UserSid, back.UserSid);
        Assert.Equal(original.Attributes.OrderBy(a => a.Key, StringComparer.Ordinal), back.Attributes.OrderBy(a => a.Key, StringComparer.Ordinal));
        Assert.Equal(original.CollectedAtUtc, back.CollectedAtUtc);
        Assert.Empty(back.Validate());

        var info = reader.ReadInfo();
        Assert.Equal(id, info.InvestigationId);
        Assert.Equal("Тестовый оператор", info.Operator);
        Assert.Equal(2, reader.SchemaVersion());
        Assert.Null(reader.ReadCorrelationRun()); // correlation not written: none is reported
        Assert.Empty(reader.ReadFindings());
    }

    private static CorrelationResult Correlation(Ulid inv, Evidence a, Evidence b)
    {
        var objectId = Ulid.NewUlid(T0.AddSeconds(1));
        return new CorrelationResult(
            [
                new CorrelatedObject
                {
                    ObjectId = objectId,
                    InvestigationId = inv,
                    DisplayPath = a.Target.RecordedPath,
                    NormalizedPath = a.Target.NormalizedPath,
                    FileName = a.Target.FileName,
                    Volume = "C:",
                    MftEntry = 0xFFFF_FFFF_FFFFUL,
                    MftSequence = 65535,
                    Sha256 = a.ObjectSha256,
                    OtherPaths = [@"C:\USERS\ИГРОК\DOWNLOADS\CHEAT.JAR"],
                    FirstUtc = T0.AddHours(-2),
                    LastUtc = T0,
                    SourceFamilies = ["prefetch", "usn"],
                    Members = [new ObjectMember(a.EvidenceId, LinkKind.MftReference), new ObjectMember(b.EvidenceId, LinkKind.Path)],
                },
            ],
            [
                new Finding
                {
                    FindingId = Ulid.NewUlid(T0.AddSeconds(2)),
                    InvestigationId = inv,
                    RuleId = "HIDDEN_BY_RENAME",
                    Confidence = Confidence.Medium,
                    Title = "Заголовок",
                    Description = "Описание с кириллицей",
                    Rationale = "Обоснование",
                    Limitations = [new Limitation("CORR.X", "Ограничение")],
                    FirstUtc = T0.AddHours(-2),
                    LastUtc = T0,
                    ObjectId = objectId,
                    IndependentFamilies = ["prefetch", "usn"],
                    Members = [new FindingMember(a.EvidenceId, "basis"), new FindingMember(b.EvidenceId, "context")],
                },
            ],
            [new Limitation("CORR.NO_IDENTIFICATION", "Не определяет читы.")]);
    }

    [Fact]
    public async Task Correlation_round_trips_and_cannot_be_changed()
    {
        var (sink, store, id) = NewStore();
        var a = Rich(id, "usn", 1);
        var b = Rich(id, "prefetch", 2);
        await store.AddEvidenceAsync(a, CancellationToken.None);
        await store.AddEvidenceAsync(b, CancellationToken.None); // still pending: written before the correlation that references it
        var original = Correlation(id, a, b);
        await store.AddCorrelationAsync(original, 2, CancellationToken.None);
        store.Dispose();

        var db = Path.Combine(sink.Root, InvestigationStore.DatabaseFileName);
        using (var reader = InvestigationReader.Open(db))
        {
            var run = reader.ReadCorrelationRun()!.Value;
            Assert.Equal(2, run.EvidenceRead);
            Assert.Equal(1, run.Objects);
            Assert.Equal(1, run.Findings);
            Assert.Equal("CORR.NO_IDENTIFICATION", Assert.Single(run.Limitations).Code);

            var o = Assert.Single(reader.ReadObjects());
            var expected = original.Objects[0];
            Assert.Equal(expected.ObjectId, o.ObjectId);
            Assert.Equal(expected.DisplayPath, o.DisplayPath);
            Assert.Equal(expected.MftEntry, o.MftEntry);
            Assert.Equal(expected.MftSequence, o.MftSequence);
            Assert.Equal(expected.Sha256, o.Sha256);
            Assert.Equal(expected.OtherPaths, o.OtherPaths);
            Assert.Equal(expected.SourceFamilies, o.SourceFamilies);
            Assert.Equal(expected.FirstUtc, o.FirstUtc);
            Assert.Equal(expected.Members.OrderBy(m => m.EvidenceId.Value, StringComparer.Ordinal), o.Members.OrderBy(m => m.EvidenceId.Value, StringComparer.Ordinal));

            var f = Assert.Single(reader.ReadFindings());
            var ef = original.Findings[0];
            Assert.Equal(ef.FindingId, f.FindingId);
            Assert.Equal(Confidence.Medium, f.Confidence);
            Assert.Equal(ef.Description, f.Description);
            Assert.Equal(ef.ObjectId, f.ObjectId);
            Assert.Equal(ef.IndependentFamilies, f.IndependentFamilies);
            Assert.Equal("CORR.X", Assert.Single(f.Limitations).Code);
            Assert.Equal(2, f.Members.Count);
            Assert.Empty(f.Validate());
        }

        foreach (var sql in new[]
        {
            "UPDATE Findings SET Confidence = 'High';", "DELETE FROM Findings;", "DELETE FROM FindingMembers;",
            "UPDATE CorrelatedObjects SET DisplayPath = 'x';", "DELETE FROM ObjectMembers;", "DELETE FROM CorrelationRuns;",
        })
        {
            using var c = new SqliteConnection($"Data Source={db};Pooling=False");
            c.Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = sql;
            var ex = Assert.Throws<SqliteException>(() => cmd.ExecuteNonQuery());
            Assert.Contains("immutable", ex.Message, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("UPDATE Evidence SET Confidence = 'High';")]
    [InlineData("DELETE FROM Evidence;")]
    [InlineData("UPDATE ModuleResults SET State = 'Completed';")]
    [InlineData("DELETE FROM ModuleResults;")]
    [InlineData("DELETE FROM Investigations;")]
    public async Task Stored_records_cannot_be_changed_or_deleted(string sql)
    {
        var (sink, store, id) = NewStore();
        await store.AddEvidenceAsync(Rich(id, "history", 1), CancellationToken.None);
        await store.CheckpointAsync(new ModuleResult { ModuleId = "history", State = ModuleState.Failed }, CancellationToken.None);
        store.Dispose();

        var db = Path.Combine(sink.Root, InvestigationStore.DatabaseFileName);
        using (var c = new SqliteConnection($"Data Source={db};Pooling=False"))
        {
            c.Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = sql;
            var ex = Assert.Throws<SqliteException>(() => cmd.ExecuteNonQuery());
            Assert.Contains("immutable", ex.Message, StringComparison.Ordinal);
        }

        using var reader = InvestigationReader.Open(db);
        Assert.Equal(1, reader.CountEvidence());
        Assert.Equal(ModuleState.Failed, reader.ReadModuleResults().Single().State);
    }

    [Fact]
    public async Task Checkpointed_records_are_durable_and_visible_before_the_store_is_closed()
    {
        var (sink, store, id) = NewStore();
        for (var i = 0; i < 3; i++)
        {
            await store.AddEvidenceAsync(Rich(id, "files", i), CancellationToken.None);
        }

        await store.CheckpointAsync(new ModuleResult { ModuleId = "files", State = ModuleState.Completed, EvidenceCount = 3 }, CancellationToken.None);

        // Not yet checkpointed:
        await store.AddEvidenceAsync(Rich(id, "history", 10), CancellationToken.None);

        using (var reader = InvestigationReader.Open(store.DatabasePath))
        {
            Assert.Equal(3, reader.CountEvidence());
            Assert.Equal("files", reader.ReadModuleResults().Single().ModuleId);
        }

        store.Dispose();
        using var after = InvestigationReader.Open(Path.Combine(sink.Root, InvestigationStore.DatabaseFileName));
        Assert.Equal(4, after.CountEvidence());
    }

    [Fact]
    public async Task Batches_are_flushed_when_full()
    {
        var (_, store, id) = NewStore(batch: 10);
        for (var i = 0; i < 25; i++)
        {
            await store.AddEvidenceAsync(Rich(id, "files", i), CancellationToken.None);
        }

        using (var reader = InvestigationReader.Open(store.DatabasePath))
        {
            Assert.Equal(20, reader.CountEvidence());
        }

        store.Dispose();
    }

    [Fact]
    public async Task Duplicate_evidence_id_is_rejected_and_nothing_partial_is_committed()
    {
        var (_, store, id) = NewStore();
        var e = Rich(id, "files", 1);
        await store.AddEvidenceAsync(e, CancellationToken.None);
        await store.AddEvidenceAsync(Rich(id, "files", 2), CancellationToken.None);
        await store.AddEvidenceAsync(e, CancellationToken.None);

        await Assert.ThrowsAsync<SqliteException>(async () =>
            await store.CheckpointAsync(new ModuleResult { ModuleId = "files", State = ModuleState.Completed }, CancellationToken.None));

        using (var reader = InvestigationReader.Open(store.DatabasePath))
        {
            Assert.Equal(0, reader.CountEvidence());
            Assert.Empty(reader.ReadModuleResults());
        }

        Assert.ThrowsAny<SqliteException>(store.Dispose);
    }

    [Fact]
    public async Task Runner_cancellation_keeps_collected_records_in_the_database()
    {
        var (sink, store, id) = NewStore();
        using var cts = new CancellationTokenSource();
        var modules = new IAnalyzer[]
        {
            new Analyzer("files", async (ctx, ct) =>
            {
                for (var i = 0; i < 5; i++)
                {
                    await ctx.Writer.AddEvidenceAsync(Rich(ctx.InvestigationId, ctx.ModuleId, i), ct);
                }

                await ctx.Writer.AddCoverageAsync(new SourceCoverage
                {
                    InvestigationId = ctx.InvestigationId,
                    ModuleId = ctx.ModuleId,
                    Source = EvidenceSourceKind.FileSystem,
                    Scope = "C:",
                    Status = CollectionStatus.Partial,
                    ItemsRead = 5,
                    EarliestUtc = T0.AddDays(-3),
                    LatestUtc = T0,
                    Limitations = [new Limitation("FS.ACCESS", "Some folders were not readable.")],
                }, ct);
                await ctx.Writer.AddErrorAsync(new ModuleError("Access denied", "UnauthorizedAccessException", @"C:\Users\other"), ct);
            }),
            new Analyzer("history", async (ctx, ct) =>
            {
                await ctx.Writer.AddEvidenceAsync(Rich(ctx.InvestigationId, ctx.ModuleId, 100), ct);
                await cts.CancelAsync();
                ct.ThrowIfCancellationRequested();
            }),
            new Analyzer("execution", (_, _) => throw new InvalidOperationException("must not run")),
        };

        var permissions = new PermissionManager(new NoProbe(), _clock).Snapshot();
        var result = await new InvestigationRunner(store, permissions, _clock).RunAsync(id, modules, cts.Token);
        store.Dispose();

        Assert.True(result.Cancelled);
        using var reader = InvestigationReader.Open(Path.Combine(sink.Root, InvestigationStore.DatabaseFileName));
        Assert.Equal(6, reader.CountEvidence());
        Assert.Equal(new[] { ModuleState.CompletedWithErrors, ModuleState.Cancelled, ModuleState.Cancelled }, reader.ReadModuleResults().Select(m => m.State));
        var coverage = Assert.Single(reader.ReadCoverage());
        Assert.Equal(CollectionStatus.Partial, coverage.Status);
        Assert.Equal(T0.AddDays(-3), coverage.EarliestUtc);
        Assert.Equal("Access denied", Assert.Single(reader.ReadErrors()).Error.Message);
    }

    [Fact]
    public async Task Views_separate_file_events_from_execution_events()
    {
        var (_, store, id) = NewStore();
        await store.AddEvidenceAsync(Rich(id, "history", 1), CancellationToken.None);
        await store.AddEvidenceAsync(Rich(id, "execution", 2) with
        {
            Source = new SourceRef(EvidenceSourceKind.Prefetch, @"C:\Windows\Prefetch\JAVAW.EXE-1A2B3C4D.pf", "prefetch", "2026.10.1"),
            EventType = EvidenceEventType.ExecutedLikely,
        }, CancellationToken.None);
        store.Dispose();

        using var reader = InvestigationReader.Open(store.DatabasePath);
        Assert.Equal(1, reader.Count(StorageView.FileEvents));
        Assert.Equal(1, reader.Count(StorageView.ExecutionEvents));
    }

    [Fact]
    public void Existing_database_is_never_taken_over()
    {
        var sink = OutputSink.CreateInvestigationFolder(_base, "taken");
        sink.WriteNew(InvestigationStore.DatabaseFileName, "previous investigation"u8);
        var info = new InvestigationInfo { InvestigationId = Ulid.NewUlid(T0), StartedUtc = T0, ToolVersion = "test" };
        Assert.Throws<IOException>(() => InvestigationStore.Create(sink, info, _clock));
        Assert.Equal("previous investigation", File.ReadAllText(Path.Combine(sink.Root, InvestigationStore.DatabaseFileName)));
    }

    [Fact]
    public async Task A_second_investigation_leaves_the_first_untouched()
    {
        var (sink1, store1, id1) = NewStore("first");
        await store1.AddEvidenceAsync(Rich(id1, "files", 1), CancellationToken.None);
        store1.Dispose();
        IntegrityManifest.Write(sink1, _clock);
        var hashBefore = Hash(Path.Combine(sink1.Root, InvestigationStore.DatabaseFileName));

        var (_, store2, id2) = NewStore("second");
        await store2.AddEvidenceAsync(Rich(id2, "files", 2), CancellationToken.None);
        store2.Dispose();

        Assert.Equal(hashBefore, Hash(Path.Combine(sink1.Root, InvestigationStore.DatabaseFileName)));
        Assert.Empty(IntegrityManifest.Verify(sink1.Root));
    }

    [Fact]
    public async Task Every_file_in_the_folder_is_accounted_for_by_the_sink_and_the_manifest()
    {
        var (sink, store, id) = NewStore();
        for (var i = 0; i < 50; i++)
        {
            await store.AddEvidenceAsync(Rich(id, "files", i), CancellationToken.None);
        }

        await store.CheckpointAsync(new ModuleResult { ModuleId = "files", State = ModuleState.Completed }, CancellationToken.None);
        store.BackupTo(sink, "evidence.backup.db");
        store.Dispose();
        IntegrityManifest.Write(sink, _clock);

        var onDisk = Directory.EnumerateFiles(sink.Root, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(sink.Root, f)).Order(StringComparer.Ordinal).ToList();
        var tracked = sink.CreatedFiles.Order(StringComparer.Ordinal).ToList();
        Assert.Equal(tracked, onDisk);
        Assert.Empty(IntegrityManifest.Verify(sink.Root));

        using var backup = InvestigationReader.Open(Path.Combine(sink.Root, "evidence.backup.db"));
        Assert.Equal(50, backup.CountEvidence());
    }

    [Fact]
    public async Task Reading_a_finished_database_does_not_change_it()
    {
        var (sink, store, id) = NewStore();
        await store.AddEvidenceAsync(Rich(id, "files", 1), CancellationToken.None);
        store.Dispose();
        var db = Path.Combine(sink.Root, InvestigationStore.DatabaseFileName);
        var before = Hash(db);

        using (var reader = InvestigationReader.Open(db))
        {
            _ = reader.ReadEvidence().ToList();
            _ = reader.ReadModuleResults();
            _ = reader.ReadCoverage();
        }

        Assert.Equal(before, Hash(db));
    }

    [Fact]
    public async Task Hundred_thousand_records_are_stored_within_budget()
    {
        var (_, store, id) = NewStore();
        var sw = Stopwatch.StartNew();
        for (var i = 0; i < 100_000; i++)
        {
            await store.AddEvidenceAsync(Rich(id, "files", i), CancellationToken.None);
        }

        await store.CheckpointAsync(new ModuleResult { ModuleId = "files", State = ModuleState.Completed, EvidenceCount = 100_000 }, CancellationToken.None);
        sw.Stop();
        var size = new FileInfo(store.DatabasePath).Length;
        store.Dispose();

        _output.WriteLine($"100000 records: {sw.Elapsed.TotalSeconds:F1} s, database {size / 1048576.0:F1} MB; {store.Stats}");

        // The code's own cost (serialising and inserting) is asserted strictly. Commit time is dominated by the
        // disk's flush speed, which on shared CI runners varies 30-50 s for this load; it is bounded only loosely
        // to catch gross regressions, and measured on real hardware separately (docs/PROGRESS.md).
        Assert.True(store.Stats.InsertTime < TimeSpan.FromSeconds(30), $"Insert took {store.Stats.InsertTime}.");
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(180), $"Took {sw.Elapsed}.");
    }

    private static string Hash(string path)
    {
        using var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        return Convert.ToHexString(SHA256.HashData(s));
    }
}
