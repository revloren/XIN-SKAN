using XINSkan.Analyzers.Execution;
using XINSkan.Analyzers.History;
using XINSkan.Core.IO;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.FileHunterTests.Support;
using XINSkan.Models;

namespace XINSkan.ExecutionTests;

/// <summary>Registry contents for tests: key → values.</summary>
internal sealed class TestRegistry : IRegistryView
{
    public Dictionary<string, List<RegistryEntry>> Keys { get; } = new(StringComparer.OrdinalIgnoreCase);

    public TestRegistry Set(string key, string name, object? value)
    {
        if (!Keys.TryGetValue(key, out var list))
        {
            Keys[key] = list = [];
            var parent = key;
            while (parent.LastIndexOf('\\') is var i and > 0)
            {
                parent = parent[..i];
                Keys.TryAdd(parent, []);
            }
        }

        if (name.Length > 0)
        {
            list.Add(new RegistryEntry(name, value));
        }

        return this;
    }

    public IReadOnlyList<RegistryEntry>? Values(string key) => Keys.TryGetValue(key, out var v) ? v : null;

    public IReadOnlyList<string>? SubKeys(string key) =>
        Keys.ContainsKey(key)
            ? Keys.Keys.Where(k => k.StartsWith(key + "\\", StringComparison.OrdinalIgnoreCase) && !k[(key.Length + 1)..].Contains('\\', StringComparison.Ordinal))
                .Select(k => k[(key.Length + 1)..]).ToList()
            : null;

    public long? LastWriteTime(string key) => null;
}

internal sealed class TestVolumes(params KnownVolume[] volumes) : IVolumeDirectory
{
    public IReadOnlyList<KnownVolume> Volumes() => volumes;
}

public sealed class PrefetchAnalyzerTests : IDisposable
{
    private const string Vol = @"\VOLUME{01d1b0e3a1b2c3d4-64BB3469}";
    private static readonly long Run1 = new DateTime(2026, 11, 7, 18, 30, 0, DateTimeKind.Utc).ToFileTimeUtc();
    private static readonly long Run2 = new DateTime(2026, 11, 6, 10, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();
    private readonly string _windows = Path.Combine(Path.GetTempPath(), "xinskan-exec-" + Guid.NewGuid().ToString("N"), "Windows");

    public PrefetchAnalyzerTests() => Directory.CreateDirectory(Path.Combine(_windows, "Prefetch"));

    public void Dispose() => Directory.Delete(Path.GetDirectoryName(_windows)!, recursive: true);

    private HistoryOptions Options => new() { Volumes = ["C:"], UsersRoot = @"C:\Users", CurrentProfile = @"C:\Users\player", WindowsFolder = _windows, TempFolders = [@"C:\Windows\Temp"] };

    private static readonly TestVolumes Volumes = new(
        new KnownVolume("C:", @"\Device\HarddiskVolume3", 0x64BB3469, false),
        new KnownVolume("E:", @"\Device\HarddiskVolume9", 0xA1B2C3D4, true));

    private void Pf(string name, byte[] data) => File.WriteAllBytes(Path.Combine(_windows, "Prefetch", name), data);

    internal static Task<MemorySink> RunAsync(IAnalyzer analyzer, params Capability[] capabilities) => RunAsync(analyzer, ModuleState.Completed, capabilities);

    internal static async Task<MemorySink> RunAsync(IAnalyzer analyzer, ModuleState expected, params Capability[] capabilities)
    {
        var sink = new MemorySink();
        var permissions = new PermissionManager(new FixedProbe(capabilities), TimeProvider.System).Snapshot();
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System).RunAsync(Ulid.NewUlid(DateTimeOffset.UtcNow), [analyzer], CancellationToken.None);
        Assert.Equal(expected, Assert.Single(run.Modules).State);
        return sink;
    }

    [Fact]
    public async Task Java_runs_their_jars_and_programs_from_downloads_or_usb_are_recorded_system_programs_are_not()
    {
        Pf("JAVAW.EXE-B3BA7868.pf", PrefetchBuilder.Mam(PrefetchBuilder.Build(30, "JAVAW.EXE", 0xB3BA7868, 42, [Run1, Run2],
        [
            new(Vol + @"\PROGRAM FILES\JAVA\JRE\BIN\JAVAW.EXE", 500, 2),
            new(Vol + @"\USERS\PLAYER\APPDATA\ROAMING\.MINECRAFT\VERSIONS\1.20.1\1.20.1.JAR", 600, 1),
            new(Vol + @"\USERS\PLAYER\APPDATA\ROAMING\.MINECRAFT\LIBRARIES\COM\GOOGLE\GSON.JAR", 601, 1),
            new(Vol + @"\USERS\PLAYER\APPDATA\ROAMING\.MINECRAFT\MODS\WURST.JAR", 602, 4),
        ])));
        Pf("INJECTOR.EXE-11111111.pf", PrefetchBuilder.Build(30, "INJECTOR.EXE", 0x11111111, 1, [Run1],
            [new(@"\Device\HarddiskVolume3\USERS\PLAYER\DOWNLOADS\INJECTOR.EXE", 700, 1)], device: @"\Device\HarddiskVolume3"));
        Pf("TOOL.EXE-22222222.pf", PrefetchBuilder.Build(30, "TOOL.EXE", 0x22222222, 3, [Run2],
            [new(@"\VOLUME{01d1b0e3a1b2c3d4-DEADBEEF}\TOOLS\TOOL.EXE", 5, 1)], device: @"\VOLUME{01d1b0e3a1b2c3d4-DEADBEEF}", serial: 0xDEADBEEF));
        Pf("NOTEPAD.EXE-D8414F97.pf", PrefetchBuilder.Build(30, "NOTEPAD.EXE", 0xD8414F97, 9, [Run1],
            [new(Vol + @"\WINDOWS\SYSTEM32\NOTEPAD.EXE", 800, 1)]));
        Pf("BROKEN.EXE-33333333.pf", [1, 2, 3, 4]);

        var sink = await RunAsync(new PrefetchAnalyzer(Options, SystemDirectoryLister.Instance, new TestFileSource(), Volumes, NoRegistry.Instance));

        var java = sink.Evidence.Single(e => e.Target.FileName == "JAVAW.EXE");
        Assert.Equal(EvidenceEventType.Executed, java.EventType);
        Assert.Equal(EvidenceSourceKind.Prefetch, java.Source.Kind);
        Assert.Equal(@"C:\PROGRAM FILES\JAVA\JRE\BIN\JAVAW.EXE", java.Target.RecordedPath);
        Assert.Equal(500ul, java.Target.MftEntry);
        Assert.Equal(DateTimeOffset.FromFileTime(Run1).ToUniversalTime(), java.Timestamp!.ValueUtc);
        Assert.Contains(java.OtherTimestamps, t => t.Field == "Prefetch.LastRun[1]" && t.ValueUtc == DateTimeOffset.FromFileTime(Run2).ToUniversalTime());
        Assert.Equal("42", java.Attributes["Prefetch.RunCount"]);
        Assert.Equal(Confidence.Informational, java.Confidence);

        // JARs Java loaded: the game and the mod, not the game's own libraries.
        var jars = sink.Evidence.Where(e => e.EventType == EvidenceEventType.Loaded).ToList();
        Assert.Equal(new[] { "1.20.1.JAR", "WURST.JAR" }, jars.Select(e => e.Target.FileName).Order(StringComparer.Ordinal));
        var wurst = jars.Single(e => e.Target.FileName == "WURST.JAR");
        Assert.Equal(@"C:\USERS\PLAYER\APPDATA\ROAMING\.MINECRAFT\MODS\WURST.JAR", wurst.Target.RecordedPath);
        Assert.Equal((ushort)4, wurst.Target.MftSequence);
        Assert.Equal(Confidence.Informational, wurst.Confidence);
        Assert.True(wurst.Attributes.ContainsKey("MinecraftRoot"));

        var injector = sink.Evidence.Single(e => e.Target.FileName == "INJECTOR.EXE");
        Assert.Equal(@"C:\USERS\PLAYER\DOWNLOADS\INJECTOR.EXE", injector.Target.RecordedPath);
        Assert.Contains("загрузках", injector.Attributes["Prefetch.Why"], StringComparison.Ordinal);

        // The volume is not mounted now: the path stays as recorded, and the record says so.
        var tool = sink.Evidence.Single(e => e.Target.FileName == "TOOL.EXE");
        Assert.Equal(@"\VOLUME{01d1b0e3a1b2c3d4-DEADBEEF}\TOOLS\TOOL.EXE", tool.Target.RecordedPath);
        Assert.Null(tool.Target.NormalizedPath);
        Assert.Equal(CollectionStatus.Partial, tool.CollectionStatus);
        Assert.Contains(tool.Limitations, l => l.Code == "PATH.VOLUME_UNKNOWN");
        Assert.Equal("DEADBEEF", tool.Attributes["Volume.Serial"]);

        Assert.DoesNotContain(sink.Evidence, e => e.Target.FileName == "NOTEPAD.EXE");
        var c = Assert.Single(sink.Coverage);
        Assert.Equal(5, c.ItemsRead);
        Assert.Equal(CollectionStatus.Partial, c.Status);
        Assert.Contains(c.Limitations, l => l.Code == "PREFETCH.DAMAGED");
        Assert.Equal(DateTimeOffset.FromFileTime(Run2).ToUniversalTime(), c.EarliestUtc);
        Assert.Equal(DateTimeOffset.FromFileTime(Run1).ToUniversalTime(), c.LatestUtc);
    }

    [Fact]
    public async Task Disabled_prefetch_is_a_low_sign_with_its_innocent_explanations()
    {
        var registry = new TestRegistry()
            .Set(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters", "EnablePrefetcher", 0)
            .Set(@"SYSTEM\CurrentControlSet\Services\SysMain", "Start", 4);
        var sink = await RunAsync(new PrefetchAnalyzer(Options, SystemDirectoryLister.Instance, new TestFileSource(), Volumes, registry));

        var off = sink.Evidence.Single(e => e.Target.FileName == "EnablePrefetcher");
        Assert.Equal(Confidence.Low, off.Confidence);
        Assert.Equal(EvidenceEventType.Observed, off.EventType);
        Assert.Contains("оптимизатор", off.Rationale, StringComparison.Ordinal);
        Assert.Equal(Confidence.Low, sink.Evidence.Single(e => e.Target.FileName == "Start").Confidence);
        var c = Assert.Single(sink.Coverage);
        Assert.Contains(c.Limitations, l => l.Code == "PREFETCH.DISABLED");
        Assert.Contains(c.Limitations, l => l.Code == "PREFETCH.EMPTY");
    }

    [Fact]
    public async Task Unreadable_prefetch_folder_is_reported_not_hidden()
    {
        var lister = new FaultyLister(p => p.EndsWith("Prefetch", StringComparison.Ordinal) ? new UnauthorizedAccessException("denied") : null);
        var sink = await RunAsync(new PrefetchAnalyzer(Options, lister, new TestFileSource(), Volumes, NoRegistry.Instance), ModuleState.CompletedWithErrors);
        var c = Assert.Single(sink.Coverage);
        Assert.Equal(CollectionStatus.Failed, c.Status);
        Assert.Contains(c.Limitations, l => l.Code == "PREFETCH.UNREADABLE");
        Assert.Single(sink.Errors);
    }

    [Theory]
    [InlineData(@"\VOLUME{01d1b0e3a1b2c3d4-64BB3469}\USERS\A.EXE", @"C:\USERS\A.EXE", true)]
    [InlineData(@"\Device\HarddiskVolume9\cheat.exe", @"E:\cheat.exe", true)]
    [InlineData(@"\device\harddiskvolume3", "C:", true)]
    [InlineData(@"\Device\HarddiskVolume5\x.exe", @"\Device\HarddiskVolume5\x.exe", false)]
    [InlineData(@"D:\Games\x.exe", @"D:\Games\x.exe", true)]
    [InlineData(@"Microsoft.WindowsCalculator_8wekyb3d8bbwe", @"Microsoft.WindowsCalculator_8wekyb3d8bbwe", false)]
    public void Volume_paths_resolve_to_drive_letters(string recorded, string expected, bool resolved)
    {
        var r = new VolumeResolver(Volumes.Volumes()).Resolve(recorded);
        Assert.Equal(expected, r.Path);
        Assert.Equal(resolved, r.Resolved);
    }
}

public sealed class BamAnalyzerTests
{
    private const string Sid = "S-1-5-21-1000-2000-3000-1001";
    private const string Other = "S-1-5-21-1000-2000-3000-1002";
    private const string Root = @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings";
    private static readonly DateTime When = new(2026, 11, 7, 21, 15, 0, DateTimeKind.Utc);

    private static HistoryOptions Options => new() { Volumes = ["C:"], UsersRoot = @"C:\Users", CurrentProfile = @"C:\Users\player" };

    private static readonly TestVolumes Volumes = new(
        new KnownVolume("C:", @"\Device\HarddiskVolume3", 1, false),
        new KnownVolume("E:", @"\Device\HarddiskVolume9", 2, true));

    private static byte[] Entry(DateTime time)
    {
        var b = new byte[24];
        BitConverter.GetBytes(time.ToFileTimeUtc()).CopyTo(b, 0);
        return b;
    }

    private static TestRegistry Registry() => new TestRegistry()
        .Set(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + Sid, "ProfileImagePath", @"C:\Users\player")
        .Set(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + Other, "ProfileImagePath", @"C:\Users\sister")
        .Set(Root + "\\" + Sid, "Version", 1)
        .Set(Root + "\\" + Sid, "SequenceNumber", 9)
        .Set(Root + "\\" + Sid, @"\Device\HarddiskVolume3\Program Files\Java\bin\javaw.exe", Entry(When))
        .Set(Root + "\\" + Sid, @"\Device\HarddiskVolume3\Users\player\Downloads\loader.exe", Entry(When.AddHours(-1)))
        .Set(Root + "\\" + Sid, @"\Device\HarddiskVolume9\autoclicker.exe", Entry(When.AddHours(-2)))
        .Set(Root + "\\" + Sid, @"\Device\HarddiskVolume3\Windows\System32\cmd.exe", Entry(When))
        .Set(Root + "\\" + Sid, "Microsoft.WindowsCalculator_8wekyb3d8bbwe", Entry(When))
        .Set(Root + "\\" + Other, @"\Device\HarddiskVolume3\Users\sister\Downloads\game.exe", Entry(When));

    [Fact]
    public async Task Programs_of_interest_are_recorded_with_user_and_time_system_programs_are_not()
    {
        var sink = await PrefetchAnalyzerTests.RunAsync(new BamAnalyzer(Options, Registry(), Volumes));

        Assert.Equal(new[] { "autoclicker.exe", "javaw.exe", "loader.exe" }, sink.Evidence.Select(e => e.Target.FileName).Order(StringComparer.Ordinal));
        var java = sink.Evidence.Single(e => e.Target.FileName == "javaw.exe");
        Assert.Equal(EvidenceEventType.Executed, java.EventType);
        Assert.Equal(EvidenceSourceKind.Bam, java.Source.Kind);
        Assert.Equal(@"C:\Program Files\Java\bin\javaw.exe", java.Target.RecordedPath);
        Assert.Equal(Sid, java.UserSid);
        Assert.Equal(new DateTimeOffset(When), java.Timestamp!.ValueUtc);
        Assert.Equal(Confidence.Informational, java.Confidence);
        Assert.Contains("player", java.Description, StringComparison.Ordinal);

        Assert.Contains("съёмном", sink.Evidence.Single(e => e.Target.FileName == "autoclicker.exe").Attributes["Bam.Why"], StringComparison.Ordinal);

        // The other user's entries need the permission to read other profiles.
        var c = Assert.Single(sink.Coverage);
        Assert.Equal(CollectionStatus.Partial, c.Status);
        Assert.Contains(c.Limitations, l => l.Code == "BAM.OTHER_USERS");
        Assert.Equal(5, c.ItemsRead);
        Assert.Equal(new DateTimeOffset(When.AddHours(-2)), c.EarliestUtc);
    }

    [Fact]
    public async Task Other_users_are_read_with_the_permission()
    {
        var sink = await PrefetchAnalyzerTests.RunAsync(new BamAnalyzer(Options, Registry(), Volumes), Capability.OtherUserProfiles);
        var game = sink.Evidence.Single(e => e.Target.FileName == "game.exe");
        Assert.Equal(Other, game.UserSid);
        Assert.Contains("sister", game.Description, StringComparison.Ordinal);
        Assert.Equal(CollectionStatus.Collected, Assert.Single(sink.Coverage).Status);
    }

    [Fact]
    public async Task Missing_bam_is_reported_as_skipped()
    {
        var sink = await PrefetchAnalyzerTests.RunAsync(new BamAnalyzer(Options, NoRegistry.Instance, Volumes));
        Assert.Empty(sink.Evidence);
        var c = Assert.Single(sink.Coverage);
        Assert.Equal(CollectionStatus.Skipped, c.Status);
        Assert.Contains(c.Limitations, l => l.Code == "BAM.ABSENT");
    }
}
