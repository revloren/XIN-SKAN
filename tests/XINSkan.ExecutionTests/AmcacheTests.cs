using XINSkan.Analyzers.Execution;
using XINSkan.Analyzers.History;
using XINSkan.Core.IO;
using XINSkan.ExecutionFormats;
using XINSkan.FileHunterTests.Support;
using XINSkan.Models;
using XINSkan.Ntfs;
using XINSkan.NtfsTests.Support;

namespace XINSkan.ExecutionTests;

internal sealed class TestProtectedFiles : IProtectedFileSource
{
    public Dictionary<string, ProtectedFile> Files { get; } = new(StringComparer.OrdinalIgnoreCase);

    public ProtectedFile? Read(string path, long maxBytes) => Files.GetValueOrDefault(path);

    public TestProtectedFiles Add(string path, byte[] data, string method = "volume")
    {
        Files[path] = new ProtectedFile(path, data, method, []);
        return this;
    }
}

public sealed class AmcacheAnalyzerTests
{
    private const string Hive = @"C:\Windows\AppCompat\Programs\Amcache.hve";
    private static readonly long Written = new DateTime(2026, 11, 7, 20, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();

    private static HistoryOptions Options => new() { Volumes = ["C:"], UsersRoot = @"C:\Users", CurrentProfile = @"C:\Users\player", WindowsFolder = @"C:\Windows" };

    private static TestKey File(string key, string path, string sha1, long size, string? program = null) => new(key, Written, [
        TestValue.Sz("LowerCaseLongPath", path),
        TestValue.Sz("FileId", "0000" + sha1),
        TestValue.Qword("Size", size),
        TestValue.Sz("Name", path[(path.LastIndexOf('\\') + 1)..]),
        TestValue.Sz("Publisher", ""),
        TestValue.Sz("ProgramId", program ?? ""),
        TestValue.Dword("IsOsComponent", 0),
    ]);

    private static byte[] NewFormat(params TestKey[] files) => HiveBuilder.Build(new("{11517B7C-E79D-4e20-961B-75A811715ADD}", SubKeys:
    [
        new("Root", SubKeys:
        [
            new("InventoryApplication", SubKeys: [new("0006abc", Written, [TestValue.Sz("Name", "Autoclicker Pro")])]),
            new("InventoryApplicationFile", SubKeys: files),
        ]),
    ]));

    [Fact]
    public async Task Programs_in_the_profile_and_temp_are_recorded_as_existed_with_sha1_system_files_are_not()
    {
        var hive = NewFormat(
            File("autoclicker.exe|1", @"c:\users\player\downloads\autoclicker.exe", "57b7fc9bf59cf09a9c19ad0ce0a159746554d682", 3060072, "0006abc"),
            File("javaw.exe|2", @"c:\program files\java\bin\javaw.exe", "1111111111111111111111111111111111111111", 1000),
            File("notepad.exe|3", @"c:\windows\system32\notepad.exe", "2222222222222222222222222222222222222222", 2000),
            File("tool.exe|4", @"c:\users\player\appdata\local\temp\tool.exe", "3333333333333333333333333333333333333333", 3000));
        var files = new TestProtectedFiles().Add(Hive, hive);

        var sink = await PrefetchAnalyzerTests.RunAsync(new AmcacheAnalyzer(Options, files, new TestVolumes()));

        Assert.Equal(new[] { "autoclicker.exe", "javaw.exe", "tool.exe" }, sink.Evidence.Select(e => e.Target.FileName).Order(StringComparer.Ordinal));
        var clicker = sink.Evidence.Single(e => e.Target.FileName == "autoclicker.exe");
        Assert.Equal(EvidenceEventType.Existed, clicker.EventType);
        Assert.Equal(EvidenceSourceKind.Amcache, clicker.Source.Kind);
        Assert.Equal("57b7fc9bf59cf09a9c19ad0ce0a159746554d682", clicker.Attributes["Amcache.Sha1"]);
        Assert.Equal("Autoclicker Pro", clicker.Attributes["Amcache.Program"]);
        Assert.Equal("volume", clicker.Attributes["Amcache.ReadMethod"]);
        Assert.Equal(3060072, clicker.Target.Size);
        Assert.Equal(DateTimeOffset.FromFileTime(Written).ToUniversalTime(), clicker.Timestamp!.ValueUtc);
        Assert.Equal(Confidence.Informational, clicker.Confidence);

        var c = Assert.Single(sink.Coverage);
        Assert.Equal(4, c.ItemsRead);
        Assert.Equal(CollectionStatus.Collected, c.Status);
        Assert.Contains(c.Limitations, l => l.Code == "AMCACHE.MEANING");
    }

    [Fact]
    public async Task Old_format_keeps_the_mft_reference_from_the_key_name()
    {
        var hive = HiveBuilder.Build(new("{11517B7C-E79D-4e20-961B-75A811715ADD}", SubKeys:
        [
            new("Root", SubKeys:
            [
                new("File", SubKeys:
                [
                    new("{c2a7e1f0-0000-0000-0000-100000000000}", SubKeys:
                    [
                        new("3000000004c4b", Written, [TestValue.Sz("15", @"C:\Users\player\Desktop\inject.exe"), TestValue.Sz("101", "0000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), TestValue.Dword("6", 4096)]),
                    ]),
                ]),
            ]),
        ]));
        var sink = await PrefetchAnalyzerTests.RunAsync(new AmcacheAnalyzer(Options, new TestProtectedFiles().Add(Hive, hive, "file"), new TestVolumes()));
        var e = Assert.Single(sink.Evidence);
        Assert.Equal(0x4c4bul, e.Target.MftEntry);
        Assert.Equal((ushort)3, e.Target.MftSequence);
        Assert.Equal(4096, e.Target.Size);
        Assert.Equal(new string('a', 40), e.Attributes["Amcache.Sha1"]);
    }

    [Fact]
    public async Task Unreadable_absent_and_dirty_hives_are_reported()
    {
        var files = new TestProtectedFiles();
        files.Files[Hive] = new ProtectedFile(Hive, [], "none", ["Файл занят системой"]);
        var failed = await PrefetchAnalyzerTests.RunAsync(new AmcacheAnalyzer(Options, files, new TestVolumes()), XINSkan.Core.Pipeline.ModuleState.CompletedWithErrors);
        Assert.Equal(CollectionStatus.Failed, Assert.Single(failed.Coverage).Status);
        Assert.Contains(failed.Coverage[0].Limitations, l => l.Code == "AMCACHE.UNREADABLE");

        var absent = await PrefetchAnalyzerTests.RunAsync(new AmcacheAnalyzer(Options, new TestProtectedFiles(), new TestVolumes()));
        Assert.Equal(CollectionStatus.Skipped, Assert.Single(absent.Coverage).Status);

        var dirty = NewFormat(File("x.exe|1", @"c:\users\player\x.exe", new string('1', 40), 1));
        dirty[4] = 9; // primary sequence differs: not fully written, and no logs
        HiveBuilder.WriteChecksum(dirty);
        var partial = await PrefetchAnalyzerTests.RunAsync(new AmcacheAnalyzer(Options, new TestProtectedFiles().Add(Hive, dirty), new TestVolumes()));
        Assert.Equal(CollectionStatus.Partial, Assert.Single(partial.Coverage).Status);
        Assert.Contains(partial.Coverage[0].Limitations, l => l.Code == "AMCACHE.DIRTY");
        Assert.Single(partial.Evidence);
    }
}

public sealed class ProtectedFileTests
{
    private sealed class LockedFiles : IFileSource
    {
        public IOpenedFile Open(string path) => throw new IOException("The process cannot access the file because it is being used by another process.");

        public IOpenedFile? TryOpenStream(string path, string streamName) => null;
    }

    private sealed class ImageOpener : IVolumeOpener
    {
        public List<string> Opened { get; } = [];

        public IRawVolume Open(string drive)
        {
            Opened.Add(drive);
            return new StreamVolume(TestImages.Player());
        }
    }

    private static (FileReference Reference, MftRecord Record) Find(string name)
    {
        var reader = MftReader.Open(new StreamVolume(TestImages.Player()));
        foreach (var raw in reader.ReadRecords())
        {
            var r = MftRecord.Parse(raw.Bytes.Span, raw.Entry);
            if (r.PrimaryName?.Name == name)
            {
                return (r.Reference, r);
            }
        }

        throw new InvalidOperationException(name + " is not in the image.");
    }

    [Fact]
    public void A_locked_file_is_read_from_the_volume_through_its_mft_record()
    {
        // injector.exe is 5000 bytes of 'M' in non-resident clusters (its record is free, the clusters intact).
        var (reference, _) = Find("injector.exe");
        var cache = new VolumeHistoryCache();
        cache.SetLocated(@"C:\Users\player\Downloads\injector.exe", reference);
        var opener = new ImageOpener();

        var file = new ProtectedFileSource(new LockedFiles(), opener, cache).Read(@"C:\Users\player\Downloads\injector.exe", 1 << 20)!;
        Assert.Equal("volume", file.Method);
        Assert.Empty(file.Problems);
        Assert.Equal(Enumerable.Repeat((byte)'M', 5000), file.Data);
        Assert.Equal(["C:"], opener.Opened);

        // Too large for the limit, and a record that now belongs to another file.
        Assert.Contains("предела", new ProtectedFileSource(new LockedFiles(), opener, cache).Read(@"C:\Users\player\Downloads\injector.exe", 100)!.Problems[0], StringComparison.Ordinal);
        cache.SetLocated(@"C:\x", new FileReference(reference.Entry, (ushort)(reference.Sequence + 7)));
        Assert.Contains("другому объекту", new ProtectedFileSource(new LockedFiles(), opener, cache).Read(@"C:\x", 1 << 20)!.Problems[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Without_a_known_record_the_locked_file_is_reported_and_missing_files_are_null()
    {
        var source = new ProtectedFileSource(new LockedFiles(), new ImageOpener(), new VolumeHistoryCache());
        var file = source.Read(@"C:\Windows\AppCompat\Programs\Amcache.hve", 1 << 20)!;
        Assert.Empty(file.Data);
        Assert.Contains("MFT", file.Problems[0], StringComparison.Ordinal);

        Assert.Null(new ProtectedFileSource(new TestFileSource(), new ImageOpener(), new VolumeHistoryCache()).Read("/no/such/file", 10));
    }

    [Fact]
    public void Boot_file_read_through_its_record_equals_the_first_sectors()
    {
        var reader = MftReader.Open(new StreamVolume(TestImages.Player()));
        var boot = MftRecord.Parse(reader.ReadRecord(7)!, 7);
        var content = NtfsFile.Read(reader, boot.Reference, 1 << 20)!;
        Assert.True(content.Complete);
        var first = new byte[512];
        reader.ReadVolume(0, first);
        Assert.Equal(first, content.Data[..512]);
    }
}
