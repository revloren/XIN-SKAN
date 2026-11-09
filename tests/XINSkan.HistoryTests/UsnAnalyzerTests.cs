using System.Buffers.Binary;
using System.Text;
using XINSkan.Analyzers.History;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.FileHunterTests.Support;
using XINSkan.Models;
using XINSkan.Ntfs;
using XINSkan.NtfsTests.Support;

namespace XINSkan.HistoryTests;

/// <summary>Builds USN_RECORD_V2 bytes.</summary>
internal sealed class JournalBuilder
{
    private readonly List<byte> _bytes = [];
    private long _time = new DateTimeOffset(2026, 11, 8, 10, 0, 0, TimeSpan.Zero).UtcDateTime.ToFileTimeUtc();

    public JournalBuilder Add(FileReference file, FileReference parent, string name, UsnReason reason, bool directory = false, int secondsLater = 1)
    {
        _time += secondsLater * TimeSpan.TicksPerSecond;
        var nameBytes = Encoding.Unicode.GetBytes(name);
        var length = (60 + nameBytes.Length + 7) & ~7;
        var r = new byte[length];
        BinaryPrimitives.WriteUInt32LittleEndian(r, (uint)length);
        BinaryPrimitives.WriteUInt16LittleEndian(r.AsSpan(4), 2);
        BinaryPrimitives.WriteUInt64LittleEndian(r.AsSpan(8), file.Entry | ((ulong)file.Sequence << 48));
        BinaryPrimitives.WriteUInt64LittleEndian(r.AsSpan(16), parent.Entry | ((ulong)parent.Sequence << 48));
        BinaryPrimitives.WriteInt64LittleEndian(r.AsSpan(24), _bytes.Count);
        BinaryPrimitives.WriteInt64LittleEndian(r.AsSpan(32), _time);
        BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(40), (uint)reason);
        BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(52), directory ? UsnRecord.AttributeDirectory : 0x20u);
        BinaryPrimitives.WriteUInt16LittleEndian(r.AsSpan(56), (ushort)nameBytes.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(r.AsSpan(58), 60);
        nameBytes.CopyTo(r, 60);
        _bytes.AddRange(r);
        return this;
    }

    public DateTimeOffset Now => DateTimeOffset.FromFileTime(_time).ToUniversalTime();

    public byte[] Build() => [.. _bytes];
}

/// <summary>A journal served from bytes, the way FSCTL_READ_USN_JOURNAL would in blocks.</summary>
internal sealed class BytesJournal(byte[] records, UsnJournalInfo? info = null, int blockSize = 4096) : IUsnJournalSource
{
    public UsnJournalInfo Query(string drive) => info ?? new UsnJournalInfo(
        (ulong)new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero).UtcDateTime.ToFileTimeUtc(), 0, records.Length, 0, long.MaxValue, 32 << 20, 8 << 20);

    public IEnumerable<ReadOnlyMemory<byte>> Read(string drive, UsnJournalInfo info, CancellationToken cancellationToken)
    {
        // Split only between records, as the system does.
        var o = 0;
        while (o < records.Length)
        {
            var end = o;
            while (end < records.Length && end - o < blockSize)
            {
                var len = BinaryPrimitives.ReadInt32LittleEndian(records.AsSpan(end));
                if (len <= 0)
                {
                    end = records.Length;
                    break;
                }

                end += len;
            }

            yield return records.AsMemory(o, end - o);
            o = end;
        }
    }
}

internal sealed class FailingJournal : IUsnJournalSource
{
    public UsnJournalInfo Query(string drive) => throw new IOException("Журнал отключён.");

    public IEnumerable<ReadOnlyMemory<byte>> Read(string drive, UsnJournalInfo info, CancellationToken cancellationToken) => [];
}

/// <summary>
/// The USN module over a journal written to match the player image: the same MFT entries, so paths come from
/// the image and from the journal's own folder records.
/// </summary>
public sealed class UsnAnalyzerTests
{
    private const string Mc = @"C:\Users\player\AppData\Roaming\.minecraft";
    private static PlayerVolume V => PlayerVolume.Instance.Value;

    private static FileReference Live(string path)
    {
        var r = V.Live(path);
        return new FileReference(r.Entry, r.Sequence);
    }

    private static FileReference Folder(string path)
    {
        var r = V.Records.Single(x => x.InUse && x.IsDirectory && x.PrimaryName is not null && V.PathOf(x) == path);
        return new FileReference(r.Entry, r.Sequence);
    }

    private static FileReference DeletedRef(string name)
    {
        var r = V.Records.Single(x => !x.InUse && x.PrimaryName?.Name == name);
        return new FileReference(r.Entry, (ushort)(r.Sequence - 1));
    }

    private static VolumeHistoryCache Cache(DateTimeOffset? formatted = null)
    {
        var cache = new VolumeHistoryCache();
        cache.Set("C:", V.Index);
        cache.SetSerial("C:", 0x1234);
        if (formatted is { } f)
        {
            cache.SetFormatted("C:", f);
        }

        return cache;
    }

    private static (byte[] Journal, DateTimeOffset DeletedAt) Scenario()
    {
        var mods = Folder(Mc + @"\mods");
        var desktop = Folder(@"C:\Users\player\Desktop");
        var games = Folder(@"C:\Users\player\Games");
        var filler = Folder(@"C:\Filler");
        var system32 = Folder(@"C:\Windows\System32");
        var wurst = DeletedRef("wurst-client.jar");
        var homework = Live(@"C:\Users\player\Desktop\homework.txt");
        var impactDir = new FileReference(76, 1); // the Impact folder; its record now belongs to new.txt
        var impact = DeletedRef("impact.jar");
        var oldTimes = Live(Mc + @"\mods\old-times.jar");

        var b = new JournalBuilder()
            .Add(wurst, mods, "wurst-client.jar", UsnReason.FileCreate)
            .Add(wurst, mods, "wurst-client.jar", UsnReason.FileCreate | UsnReason.DataExtend)
            .Add(wurst, mods, "wurst-client.jar", UsnReason.FileCreate | UsnReason.DataExtend | UsnReason.Close)
            .Add(wurst, mods, "wurst-client.jar", UsnReason.StreamChange | UsnReason.NamedDataExtend | UsnReason.Close)
            .Add(homework, desktop, "client.jar", UsnReason.FileCreate | UsnReason.Close)
            .Add(homework, desktop, "client.jar", UsnReason.RenameOldName)
            .Add(homework, desktop, "homework.txt", UsnReason.RenameNewName)
            .Add(homework, desktop, "homework.txt", UsnReason.RenameNewName | UsnReason.Close)
            .Add(impactDir, games, "Impact", UsnReason.FileCreate | UsnReason.Close, directory: true)
            .Add(impact, impactDir, "impact.jar", UsnReason.FileCreate | UsnReason.Close)
            .Add(oldTimes, mods, "old-times.jar", UsnReason.BasicInfoChange)
            .Add(oldTimes, mods, "old-times.jar", UsnReason.BasicInfoChange | UsnReason.Close)
            .Add(new FileReference(900, 1), filler, "f2.txt", UsnReason.FileCreate | UsnReason.Close)
            .Add(new FileReference(901, 1), system32, "update.dll", UsnReason.FileDelete | UsnReason.Close)
            .Add(impact, impactDir, "impact.jar", UsnReason.FileDelete | UsnReason.Close)
            .Add(impactDir, games, "Impact", UsnReason.FileDelete | UsnReason.Close, directory: true)
            .Add(wurst, mods, "wurst-client.jar", UsnReason.FileDelete | UsnReason.Close, secondsLater: 30);
        return (b.Build(), b.Now);
    }

    private static async Task<(MemorySink Sink, InvestigationRunResult Run)> RunAsync(IUsnJournalSource journal, VolumeHistoryCache? cache = null)
    {
        var sink = new MemorySink();
        var permissions = new PermissionManager(new FixedProbe(Capability.UsnJournalRead), TimeProvider.System).Snapshot();
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System)
            .RunAsync(Ulid.NewUlid(DateTimeOffset.UtcNow), [new UsnAnalyzer(MftAnalyzerTests.Options, journal, cache ?? Cache())], CancellationToken.None);
        return (sink, run);
    }

    [Fact]
    public async Task The_life_of_each_relevant_file_is_rebuilt_and_nothing_else_is_recorded()
    {
        var (sink, run) = await RunAsync(new BytesJournal(Scenario().Journal));
        Assert.Equal(ModuleState.Completed, Assert.Single(run.Modules).State);

        var got = sink.Evidence.Select(e => $"{e.EventType} {e.Target.RecordedPath}").Order(StringComparer.Ordinal).ToList();
        Assert.Equal(
            new[]
            {
                $"Created {Mc}\\mods\\wurst-client.jar",
                $"Created C:\\Users\\player\\Desktop\\client.jar",
                $"Created C:\\Users\\player\\Games\\Impact\\impact.jar",
                $"Deleted {Mc}\\mods\\wurst-client.jar",
                $"Deleted C:\\Users\\player\\Games\\Impact\\impact.jar",
                $"Modified {Mc}\\mods\\old-times.jar",
                $"Modified {Mc}\\mods\\wurst-client.jar",
                $"Modified {Mc}\\mods\\wurst-client.jar",
                $"Renamed C:\\Users\\player\\Desktop\\homework.txt",
            }.Order(StringComparer.Ordinal),
            got);
    }

    [Fact]
    public async Task Deletion_has_the_exact_journal_time_and_the_live_reference()
    {
        var (journal, deletedAt) = Scenario();
        var (sink, _) = await RunAsync(new BytesJournal(journal));
        var deleted = sink.Evidence.Single(e => e.EventType == EvidenceEventType.Deleted && e.Target.FileName == "wurst-client.jar");

        Assert.Equal(deletedAt, deleted.Timestamp!.ValueUtc);
        Assert.Equal("Usn.TimeStamp", deleted.Timestamp.Field);
        Assert.Equal(TimestampPrecision.HundredNanoseconds, deleted.Timestamp.Precision);
        Assert.Equal(DeletedRef("wurst-client.jar").Sequence, deleted.Target.MftSequence);
        Assert.Equal(0x1234UL, deleted.Target.VolumeSerial);
        Assert.Equal(Confidence.Informational, deleted.Confidence);
        Assert.Equal(EvidenceSourceKind.UsnJournal, deleted.Source.Kind);
    }

    [Fact]
    public async Task A_rename_that_hides_a_jar_is_low_with_the_old_and_new_names()
    {
        var (sink, _) = await RunAsync(new BytesJournal(Scenario().Journal));
        var rename = sink.Evidence.Single(e => e.EventType == EvidenceEventType.Renamed);
        Assert.Equal("client.jar", rename.Attributes["Usn.OldName"]);
        Assert.Equal(@"C:\Users\player\Desktop\client.jar", rename.Attributes["Usn.OldPath"]);
        Assert.Equal("homework.txt", rename.Attributes["Usn.NewName"]);
        Assert.Equal(".jar → .txt", rename.Attributes["Usn.ExtensionChanged"]);
        Assert.Equal(Confidence.Low, rename.Confidence);
    }

    [Fact]
    public async Task A_folder_known_only_from_the_journal_completes_the_path()
    {
        var (sink, _) = await RunAsync(new BytesJournal(Scenario().Journal));
        var impact = sink.Evidence.First(e => e.Target.FileName == "impact.jar");

        // The MFT alone gives "C:\?\impact.jar" (the folder record was reused); the journal names the folder.
        Assert.Equal(@"C:\Users\player\Games\Impact\impact.jar", impact.Target.RecordedPath);
        Assert.Contains(impact.Limitations, l => l.Code == "PATH.DELETED_ANCESTOR");
        Assert.Equal(CollectionStatus.Collected, impact.CollectionStatus);
    }

    [Fact]
    public async Task Time_and_stream_changes_are_aggregated_per_file()
    {
        var (sink, _) = await RunAsync(new BytesJournal(Scenario().Journal));
        var times = sink.Evidence.Single(e => e.Target.FileName == "old-times.jar");
        Assert.Equal("1", times.Attributes["Usn.BasicInfoChanges"]);

        var wurst = sink.Evidence.Where(e => e.Target.FileName == "wurst-client.jar" && e.EventType == EvidenceEventType.Modified).ToList();
        Assert.Contains(wurst, e => e.Attributes.ContainsKey("Usn.DataChanges"));
        Assert.Contains(wurst, e => e.Attributes.ContainsKey("Usn.StreamChanges"));
    }

    [Fact]
    public async Task Installer_noise_is_reduced_and_finished_downloads_are_recognised()
    {
        var downloads = Folder(@"C:\Users\player\Downloads");
        var appData = Folder(@"C:\Users\player\AppData\Roaming");
        var journal = new JournalBuilder()
            // Browser download: written as .crdownload, renamed on completion.
            .Add(new FileReference(950, 1), downloads, "client.jar.crdownload", UsnReason.FileCreate | UsnReason.DataExtend | UsnReason.Close)
            .Add(new FileReference(950, 1), downloads, "client.jar.crdownload", UsnReason.RenameOldName)
            .Add(new FileReference(950, 1), downloads, "client.jar", UsnReason.RenameNewName | UsnReason.Close)
            // An updater writes a DLL as .tmp, renames it, changes it, and later removes an old one.
            .Add(new FileReference(951, 1), appData, "update.tmp", UsnReason.FileCreate | UsnReason.DataExtend | UsnReason.Close)
            .Add(new FileReference(951, 1), appData, "update.tmp", UsnReason.RenameOldName)
            .Add(new FileReference(951, 1), appData, "app.dll", UsnReason.RenameNewName | UsnReason.Close)
            .Add(new FileReference(951, 1), appData, "app.dll", UsnReason.DataOverwrite | UsnReason.Close)
            .Add(new FileReference(952, 1), appData, "old.dll", UsnReason.FileDelete | UsnReason.Close)
            .Build();

        var (sink, _) = await RunAsync(new BytesJournal(journal));
        var events = sink.Evidence.Select(e => $"{e.EventType} {e.Target.FileName} {e.Confidence}").Order(StringComparer.Ordinal).ToList();
        Assert.Equal(
            new[]
            {
                "Created client.jar.crdownload Informational",
                "Deleted old.dll Informational",
                "Downloaded client.jar Informational",
                "Modified client.jar.crdownload Informational",
            },
            events);
        Assert.Equal(".crdownload → .jar", sink.Evidence.Single(e => e.EventType == EvidenceEventType.Downloaded).Attributes["Usn.DownloadCompleted"]);
    }

    [Fact]
    public async Task Coverage_states_the_window_of_the_journal()
    {
        var (sink, _) = await RunAsync(new BytesJournal(Scenario().Journal));
        var c = Assert.Single(sink.Coverage);
        Assert.Equal(17, c.ItemsRead);
        Assert.Contains("2026-11-08", c.Limitations.Single(l => l.Code == "USN.WINDOW").Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_journal_created_long_after_the_volume_is_reported_low()
    {
        var formatted = new DateTimeOffset(2024, 3, 1, 0, 0, 0, TimeSpan.Zero);
        var (sink, _) = await RunAsync(new BytesJournal(Scenario().Journal), Cache(formatted));
        var recreated = sink.Evidence.Single(e => e.Target.FileName == "$UsnJrnl");
        Assert.Equal(Confidence.Low, recreated.Confidence);
        Assert.Equal(new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero), recreated.Timestamp!.ValueUtc);

        // Same journal, volume formatted the same day: nothing to report.
        var (quiet, _) = await RunAsync(new BytesJournal(Scenario().Journal), Cache(new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero)));
        Assert.DoesNotContain(quiet.Evidence, e => e.Target.FileName == "$UsnJrnl");
    }

    [Fact]
    public async Task Without_the_mft_index_paths_come_from_the_journal_and_this_is_stated()
    {
        var (sink, _) = await RunAsync(new BytesJournal(Scenario().Journal), new VolumeHistoryCache());
        Assert.Contains(Assert.Single(sink.Coverage).Limitations, l => l.Code == "USN.NO_MFT");
        Assert.All(sink.Evidence.Where(e => e.Target.FileName is not null && e.Target.FileName != "$UsnJrnl"), e => Assert.Equal(CollectionStatus.Partial, e.CollectionStatus));
    }

    [Fact]
    public async Task A_disabled_journal_is_an_error_and_failed_coverage()
    {
        var (sink, run) = await RunAsync(new FailingJournal());
        Assert.Equal(ModuleState.CompletedWithErrors, Assert.Single(run.Modules).State);
        Assert.Equal(CollectionStatus.Failed, Assert.Single(sink.Coverage).Status);
    }

    [Fact]
    public void Damaged_journal_data_is_stepped_over_and_counted()
    {
        var good = Scenario().Journal;
        var damaged = new byte[good.Length + 64];
        good.AsSpan(0, 200).CopyTo(damaged);
        new Random(5).NextBytes(damaged.AsSpan(200, 64));
        good.AsSpan(200).CopyTo(damaged.AsSpan(264));
        var stats = new UsnParseStatistics();
        var parsed = UsnParser.Parse(damaged, stats).ToList();
        Assert.True(parsed.Count >= 15, $"{parsed.Count} records survived");
        Assert.True(stats.Resynchronised > 0);

        var rng = new Random(77);
        for (var i = 0; i < 3000; i++)
        {
            var copy = (byte[])good.Clone();
            for (var m = 0; m < 10; m++)
            {
                copy[rng.Next(copy.Length)] = (byte)rng.Next(256);
            }

            _ = UsnParser.Parse(copy).ToList();
        }
    }
}

/// <summary>A real $J (Windows Server 2012 R2, DFIR Artifact Museum via the MFT library corpus); values from the library's tests.</summary>
public sealed class UsnReferenceSampleTests
{
    [SampleFact]
    public void Every_record_of_the_reference_journal_is_read()
    {
        var bytes = File.ReadAllBytes(SampleFactAttribute.File("DFIRArtifactMuseum", "J", "Win2012R2", "StolenSzechuan", "$J"));
        var stats = new UsnParseStatistics();
        var records = UsnParser.Parse(bytes, stats).ToList();

        Assert.Equal(82151, records.Count);
        Assert.Equal(0, stats.Resynchronised);
        Assert.Equal(("WindowsUpdate.log", 84627UL, 297UL, 132448315022266746L), (records[0].Name, records[0].File.Entry, records[0].Parent.Entry, records[0].TimeStamp));
        Assert.Equal(("SAM.LOG1", 76716UL), records.Where(r => r.Usn == 0x8C9220).Select(r => (r.Name, r.File.Entry)).Single());
        Assert.Contains(records, r => r.Usn == 0x8C9140 && r.Name == "~FontCache-S-1-5-18.dat");

        // In a raw $J the USN of a record is its offset: strictly increasing.
        Assert.True(records.Zip(records.Skip(1)).All(p => p.First.Usn < p.Second.Usn));
    }
}
