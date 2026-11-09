using System.Security.Cryptography;
using System.Text;
using XINSkan.Analyzers.History;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.FileHunterTests.Support;
using XINSkan.Models;
using XINSkan.Ntfs;
using XINSkan.NtfsTests.Support;

namespace XINSkan.HistoryTests;

/// <summary>The MFT module on the player image (see XINSkan.NtfsTests/TestData/README.md for its history).</summary>
public sealed class MftAnalyzerTests
{
    private const string Mc = @"C:\Users\player\AppData\Roaming\.minecraft";

    internal sealed class ImageOpener(Func<Stream> image) : IVolumeOpener
    {
        public IRawVolume Open(string drive) => new StreamVolume(image());
    }

    internal static HistoryOptions Options => new()
    {
        Volumes = ["C:"],
        UsersRoot = @"C:\Users",
        CurrentProfile = @"C:\Users\player",
        TempFolders = [@"C:\Windows\Temp"],
    };

    internal static async Task<(MemorySink Sink, InvestigationRunResult Run, VolumeHistoryCache Cache)> RunAsync(IVolumeOpener opener, HistoryOptions? options = null, params Capability[] capabilities)
    {
        var sink = new MemorySink();
        var cache = new VolumeHistoryCache();
        var permissions = new PermissionManager(new FixedProbe([Capability.RawVolumeRead, .. capabilities]), TimeProvider.System).Snapshot();
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System)
            .RunAsync(Ulid.NewUlid(DateTimeOffset.UtcNow), [new MftAnalyzer(options ?? Options, opener, cache)], CancellationToken.None);
        return (sink, run, cache);
    }

    private static async Task<MemorySink> PlayerAsync()
    {
        var (sink, run, _) = await RunAsync(new ImageOpener(TestImages.Player));
        Assert.Equal(ModuleState.Completed, Assert.Single(run.Modules).State);
        return sink;
    }

    private static Evidence Single(MemorySink s, string path) => s.Evidence.Single(e => e.Target.RecordedPath == path);

    [Fact]
    public async Task Records_exactly_the_deleted_and_live_objects_that_matter()
    {
        var s = await PlayerAsync();
        var got = s.Evidence.Select(e => (e.EventType, e.Target.RecordedPath)).OrderBy(x => x.RecordedPath, StringComparer.Ordinal).ToList();
        var longJar = @"C:\Users\player\Downloads\" + new string('a', 200) + ".jar";

        Assert.Equal(
            new (EvidenceEventType, string?)[]
            {
                (EvidenceEventType.Deleted, @"C:\?\impact.jar"),
                (EvidenceEventType.Deleted, Mc + @"\config\wurst"),
                (EvidenceEventType.Deleted, Mc + @"\config\wurst\settings.json"),
                (EvidenceEventType.Existed, Mc + @"\mods\kept-mod.jar"),
                (EvidenceEventType.Existed, Mc + @"\mods\old-times.jar"),
                (EvidenceEventType.Existed, Mc + @"\mods\sodium-fabric-0.5.3.jar"),
                (EvidenceEventType.Deleted, Mc + @"\mods\wurst-client.jar"),
                (EvidenceEventType.Existed, longJar),
                (EvidenceEventType.Deleted, @"C:\Users\player\Downloads\injector.exe"),
                (EvidenceEventType.Existed, @"C:\Users\player\Downloads\shared.jar"),
                (EvidenceEventType.Existed, @"C:\Users\player\Downloads\чит-клиент.jar"),
                (EvidenceEventType.Deleted, @"C:\Users\player\Temp\Reused\old.jar"),
            }.OrderBy(x => x.Item2, StringComparer.Ordinal),
            got);
    }

    [Fact]
    public async Task A_deleted_mod_keeps_its_origin_content_hash_and_previous_reference()
    {
        var wurst = Single(await PlayerAsync(), Mc + @"\mods\wurst-client.jar");

        Assert.Equal(EvidenceSourceKind.Mft, wurst.Source.Kind);
        Assert.Equal(Confidence.Informational, wurst.Confidence);
        Assert.Null(wurst.Timestamp); // the MFT does not say when
        Assert.Contains(wurst.Limitations, l => l.Code == "MFT.DELETE_TIME_UNKNOWN");
        Assert.Equal("https://example.org/wurst-client.jar", wurst.Attributes["Zone.HostUrl"]);
        Assert.Equal("resident", wurst.Attributes["Mft.Content"]);
        Assert.Equal(Sha256Hash.FromBytes(SHA256.HashData(Encoding.ASCII.GetBytes("wurst\n"))), wurst.ObjectSha256);
        Assert.NotNull(wurst.ArtifactSha256);

        // The record is free with sequence 2; the file itself was known as entry/1.
        Assert.Equal("2", wurst.Attributes["Mft.RecordSequence"]);
        Assert.Equal((ushort)1, wurst.Target.MftSequence);
        Assert.Equal(Mc, wurst.Attributes["MinecraftRoot"]);
        Assert.Equal(CollectionStatus.Collected, wurst.CollectionStatus);
        Assert.Contains("$SI.Created", wurst.OtherTimestamps.Select(t => t.Field));
        Assert.Contains("$FN.Created", wurst.OtherTimestamps.Select(t => t.Field));
    }

    [Fact]
    public async Task Anything_deleted_inside_minecraft_is_recorded_and_nothing_outside_the_area()
    {
        var s = await PlayerAsync();
        var settings = Single(s, Mc + @"\config\wurst\settings.json");
        Assert.Contains(settings.Limitations, l => l.Code == "PATH.DELETED_ANCESTOR");
        Assert.Equal("true", Single(s, Mc + @"\config\wurst").Attributes["Mft.IsDirectory"]);

        Assert.DoesNotContain(s.Evidence, e => e.Target.FileName is "update.dll" or "f1.txt");
    }

    [Fact]
    public async Task Uncertain_paths_are_marked_and_not_normalised()
    {
        var s = await PlayerAsync();

        var impact = Single(s, @"C:\?\impact.jar");
        Assert.Null(impact.Target.NormalizedPath);
        Assert.Equal(CollectionStatus.Partial, impact.CollectionStatus);
        Assert.Contains(impact.Limitations, l => l.Code == "PATH.REUSED_ANCESTOR");

        var old = Single(s, @"C:\Users\player\Temp\Reused\old.jar");
        Assert.NotNull(old.Target.NormalizedPath);
        Assert.Contains(old.Limitations, l => l.Code == "PATH.DELETED_ANCESTOR");
    }

    [Fact]
    public async Task Live_records_carry_file_name_time_and_hard_link_names()
    {
        var s = await PlayerAsync();
        var shared = Single(s, @"C:\Users\player\Downloads\shared.jar");
        Assert.Equal(EvidenceEventType.Existed, shared.EventType);
        Assert.Equal("$FN.Created", shared.Timestamp!.Field);
        Assert.Contains("shared-link.jar", shared.Attributes["Mft.Names"], StringComparison.Ordinal);
        Assert.All(s.Evidence.Where(e => e.EventType == EvidenceEventType.Existed), e => Assert.Equal(Confidence.Informational, e.Confidence));
    }

    [Fact]
    public async Task Coverage_states_what_was_read_and_what_absence_does_not_prove()
    {
        var s = await PlayerAsync();
        var c = Assert.Single(s.Coverage);
        Assert.Equal(EvidenceSourceKind.Mft, c.Source);
        Assert.Equal(CollectionStatus.Collected, c.Status);
        Assert.Equal(PlayerVolume.Instance.Value.Reader.RecordCount, c.ItemsRead);
        Assert.Contains(c.Limitations, l => l.Code == "MFT.REUSE");
    }

    [Fact]
    public async Task The_path_index_is_left_for_the_modules_that_follow()
    {
        var (_, _, cache) = await RunAsync(new ImageOpener(TestImages.Player));
        var index = cache.Get("C:");
        Assert.NotNull(index);
        Assert.Equal(PlayerVolume.Instance.Value.Reader.RecordCount, index!.Capacity);
    }

    [Fact]
    public async Task Without_raw_volume_access_the_module_is_skipped_with_the_reason()
    {
        var sink = new MemorySink();
        var permissions = new PermissionManager(new FixedProbe(), TimeProvider.System).Snapshot();
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System)
            .RunAsync(Ulid.NewUlid(DateTimeOffset.UtcNow), [new MftAnalyzer(Options, new ImageOpener(TestImages.Player), new VolumeHistoryCache())], CancellationToken.None);
        var m = Assert.Single(run.Modules);
        Assert.Equal(ModuleState.Skipped, m.State);
        Assert.Contains(nameof(Capability.RawVolumeRead), m.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unreadable_volume_is_an_error_and_failed_coverage_not_a_crash()
    {
        var (sink, run, _) = await RunAsync(new ImageOpener(() => new MemoryStream(new byte[4096])));
        Assert.Equal(ModuleState.CompletedWithErrors, Assert.Single(run.Modules).State);
        Assert.Equal(CollectionStatus.Failed, Assert.Single(sink.Coverage).Status);
        Assert.Empty(sink.Evidence);
    }

    [Fact]
    public async Task Other_profiles_are_left_out_without_access_and_counted()
    {
        var options = Options with { CurrentProfile = @"C:\Users\someone-else" };
        var (sink, _, _) = await RunAsync(new ImageOpener(TestImages.Player), options);

        // Only Minecraft folders stay in scope (they are checked wherever they are), and the jar of unknown place.
        Assert.All(sink.Evidence, e => Assert.True(e.Target.RecordedPath!.Contains(@"\.minecraft\", StringComparison.Ordinal) || e.Target.RecordedPath.StartsWith(@"C:\?", StringComparison.Ordinal), e.Target.RecordedPath));
        Assert.Contains(Assert.Single(sink.Coverage).Limitations, l => l.Code == "SCOPE.OTHER_PROFILES");
    }
}

public sealed class TimeAnomalyTests
{
    private const long T = 133_485_408_123_456_789; // 2024-01-01 with a fraction

    private static MftRecord Record(long siCreated, long fnCreated) => MftRecord.Parse(new RecordBuilder()
        .Resident(MftRecord.TypeStandardInformation, RecordBuilder.StandardInformation(siCreated, T, T, T))
        .Resident(MftRecord.TypeFileName, RecordBuilder.FileName(64, 1, "x.jar", fnCreated)).Build(100), 100);

    [Fact]
    public void Matching_times_raise_nothing() => Assert.Empty(MftAnalyzer.TimeAnomalies(Record(T, T)));

    [Fact]
    public void Creation_set_back_before_the_name_existed_is_flagged()
    {
        var setBack = T - (TimeSpan.TicksPerDay * 400) - (T % TimeSpan.TicksPerSecond); // whole second, 400 days earlier
        Assert.Equal(new[] { "SI_CREATED_BEFORE_FN", "SI_CREATED_WHOLE_SECOND" }, MftAnalyzer.TimeAnomalies(Record(setBack, T)));
    }

    [Fact]
    public void A_difference_within_a_second_is_not_flagged() =>
        Assert.Empty(MftAnalyzer.TimeAnomalies(Record(T - (TimeSpan.TicksPerSecond / 2), T)));

    [Fact]
    public void Later_standard_information_is_normal_after_copy_or_edit() =>
        Assert.Empty(MftAnalyzer.TimeAnomalies(Record(T + TimeSpan.TicksPerDay, T)));
}

public sealed class HistoryScopeTests
{
    private static HistoryScope Scope(bool others = false) =>
        new(@"C:\Users", @"C:\Users\player", others, [@"C:\Windows\Temp"], [@"D:\Games"]);

    [Theory]
    [InlineData(@"C:\Users\player\Downloads\a.jar", true, false, true)]
    [InlineData(@"C:\Users\player\a.jar", true, false, true)]
    [InlineData(@"C:\Users\player\AppData\Local\Temp\x\a.exe", true, false, true)]
    [InlineData(@"C:\Users\player\AppData\Roaming\.minecraft\mods\a.jar", true, true, false)]
    [InlineData(@"C:\Users\player\Games\a.jar", true, false, false)]
    [InlineData(@"C:\Users\Public\Downloads\a.jar", false, false, false)]
    [InlineData(@"C:\Users\Default\a.jar", false, false, false)]
    [InlineData(@"C:\Users\other\Downloads\a.jar", false, false, false)]
    [InlineData(@"C:\Windows\Temp\a.exe", true, false, true)]
    [InlineData(@"C:\Windows\System32\a.dll", false, false, false)]
    [InlineData(@"C:\Games\.minecraft\versions\x.jar", true, true, false)]
    [InlineData(@"C:\Games\.minecraftbackup\x.jar", false, false, false)]
    [InlineData(@"D:\Games\x.jar", true, false, false)]
    public void Paths_are_placed_by_rule(string path, bool inScope, bool minecraft, bool drop)
    {
        var m = Scope().Match(path);
        Assert.Equal((inScope, minecraft, drop), (m.InScope, m.InMinecraftTree, m.InDropLocation));
    }

    [Fact]
    public void Other_profiles_count_when_left_out_and_are_in_scope_with_access()
    {
        var without = Scope();
        Assert.False(without.Match(@"C:\Users\other\Downloads\a.jar").InScope);
        Assert.Equal(1, without.ExcludedOtherProfiles);
        Assert.True(Scope(others: true).Match(@"C:\Users\other\Downloads\a.jar").InScope);
    }
}
