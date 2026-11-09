using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using XINSkan.Analyzers.History;
using XINSkan.Core.IO;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.FileHunterTests.Support;
using XINSkan.Models;

namespace XINSkan.HistoryTests;

public sealed class RecycleInfoParserTests
{
    internal static byte[] V2(string path, long size, DateTimeOffset deleted)
    {
        var name = Encoding.Unicode.GetBytes(path + "\0");
        var b = new byte[28 + name.Length];
        BinaryPrimitives.WriteInt64LittleEndian(b, 2);
        BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(8), size);
        BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(16), deleted.UtcDateTime.ToFileTimeUtc());
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(24), (uint)(path.Length + 1));
        name.CopyTo(b, 28);
        return b;
    }

    private static byte[] V1(string path, long size, DateTimeOffset deleted)
    {
        var b = new byte[544];
        BinaryPrimitives.WriteInt64LittleEndian(b, 1);
        BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(8), size);
        BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(16), deleted.UtcDateTime.ToFileTimeUtc());
        Encoding.Unicode.GetBytes(path).CopyTo(b, 24);
        return b;
    }

    private static readonly DateTimeOffset T = new(2026, 11, 8, 9, 30, 15, TimeSpan.Zero);

    [Fact]
    public void Both_versions_give_path_size_and_time()
    {
        var v2 = RecycleInfoParser.Parse(V2(@"C:\Users\player\Downloads\чит.jar", 12345, T), out var p2)!;
        Assert.Null(p2);
        Assert.Equal((2, 12345L, @"C:\Users\player\Downloads\чит.jar", T), (v2.Version, v2.Size, v2.OriginalPath, v2.DeletedUtc!.Value));

        var v1 = RecycleInfoParser.Parse(V1(@"C:\Users\player\Desktop\a.exe", 7, T), out _)!;
        Assert.Equal((1, @"C:\Users\player\Desktop\a.exe"), (v1.Version, v1.OriginalPath));
    }

    [Theory]
    [InlineData(new byte[] { 1, 2, 3 })]
    [InlineData(new byte[] { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 })]
    public void Damaged_files_are_rejected_with_a_reason(byte[] b)
    {
        Assert.Null(RecycleInfoParser.Parse(b, out var problem));
        Assert.NotNull(problem);
    }

    [Fact]
    public void A_path_length_beyond_the_file_is_rejected()
    {
        var b = V2(@"C:\a.jar", 1, T);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(24), 5000);
        Assert.Null(RecycleInfoParser.Parse(b, out var problem));
        Assert.Contains("выходит", problem, StringComparison.Ordinal);
    }
}

public sealed class RecycleBinAnalyzerTests : IDisposable
{
    private static readonly DateTimeOffset T = new(2026, 11, 8, 9, 30, 15, TimeSpan.Zero);
    private readonly string _volume = Path.Combine(Path.GetTempPath(), "xinskan-rb-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_volume))
        {
            Directory.Delete(_volume, recursive: true);
        }
    }

    private string Sid(string sid)
    {
        var d = Path.Combine(_volume, "$Recycle.Bin", sid);
        Directory.CreateDirectory(d);
        return d;
    }

    private static void Item(string sidDir, string id, string originalPath, byte[]? content, DateTimeOffset when)
    {
        File.WriteAllBytes(Path.Combine(sidDir, "$I" + id), RecycleInfoParserTests.V2(originalPath, content?.Length ?? 0, when));
        if (content is not null)
        {
            File.WriteAllBytes(Path.Combine(sidDir, "$R" + id), content);
        }
    }

    private async Task<(MemorySink Sink, InvestigationRunResult Run)> RunAsync(params Capability[] caps)
    {
        var sink = new MemorySink();
        var options = MftAnalyzerTests.Options with { Volumes = [_volume] };
        var permissions = new PermissionManager(new FixedProbe(caps), TimeProvider.System).Snapshot();
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System).RunAsync(
            Ulid.NewUlid(DateTimeOffset.UtcNow), [new RecycleBinAnalyzer(options, SystemDirectoryLister.Instance, new TestFileSource())], CancellationToken.None);
        return (sink, run);
    }

    [Fact]
    public async Task Relevant_items_are_recorded_with_origin_time_and_content_and_the_rest_is_not()
    {
        var me = Sid("S-1-5-21-1-2-3-1001");
        Item(me, "ABC123.jar", @"C:\Users\player\AppData\Roaming\.minecraft\mods\wurst-client.jar", Jar.FabricMod("wurst", "Wurst Client", "7.40"), T);
        Item(me, "DEF456.txt", @"C:\Users\player\Downloads\homework.txt", Jar.FabricMod("hidden", "Hidden", "1"), T.AddMinutes(1)); // a jar under another name
        Item(me, "GHI789.jar", @"C:\Users\player\Downloads\gone.jar", null, T.AddMinutes(2));                                   // $R emptied
        Item(me, "JKL000.docx", @"C:\Users\player\Documents\essay.docx", "plain text"u8.ToArray(), T);                          // not relevant
        Item(me, "MNO111.jar", @"C:\Program Files\Tool\x.jar", Jar.FabricMod("x", "X", "1"), T);                                 // outside the area

        // A deleted .minecraft folder.
        var folder = Path.Combine(me, "$RPQR222");
        Directory.CreateDirectory(Path.Combine(folder, "mods"));
        File.WriteAllBytes(Path.Combine(folder, "mods", "impact.jar"), Jar.FabricMod("impact", "Impact", "4.9"));
        File.WriteAllText(Path.Combine(folder, "options.txt"), "x");
        File.WriteAllBytes(Path.Combine(me, "$IPQR222"), RecycleInfoParserTests.V2(@"C:\Users\player\AppData\Roaming\.minecraft", 0, T.AddHours(1)));

        var (sink, run) = await RunAsync();
        Assert.Equal(ModuleState.Completed, Assert.Single(run.Modules).State);
        var paths = sink.Evidence.Select(e => e.Target.RecordedPath).Order(StringComparer.Ordinal).ToList();
        Assert.Equal(
            new[]
            {
                @"C:\Users\player\AppData\Roaming\.minecraft",
                @"C:\Users\player\AppData\Roaming\.minecraft\mods\impact.jar",
                @"C:\Users\player\AppData\Roaming\.minecraft\mods\wurst-client.jar",
                @"C:\Users\player\Downloads\gone.jar",
                @"C:\Users\player\Downloads\homework.txt",
            },
            paths);

        var wurst = sink.Evidence.Single(e => e.Target.FileName == "wurst-client.jar");
        Assert.Equal(EvidenceEventType.Deleted, wurst.EventType);
        Assert.Equal(T, wurst.Timestamp!.ValueUtc);
        Assert.Equal("wurst", wurst.Attributes["Mod.Id"]);
        Assert.Equal("S-1-5-21-1-2-3-1001", wurst.UserSid);
        Assert.NotNull(wurst.ObjectSha256);

        Assert.Equal("Zip", sink.Evidence.Single(e => e.Target.FileName == "homework.txt").Attributes["Content"]);
        var gone = sink.Evidence.Single(e => e.Target.FileName == "gone.jar");
        Assert.Contains(gone.Limitations, l => l.Code == "RECYCLE.ITEM_GONE");
        Assert.Equal(CollectionStatus.Partial, gone.CollectionStatus);

        Assert.Equal("impact", sink.Evidence.Single(e => e.Target.FileName == "impact.jar").Attributes["Mod.Id"]);
        Assert.Equal(6, Assert.Single(sink.Coverage).ItemsRead);
    }

    [Fact]
    public async Task A_damaged_info_file_is_an_error_not_a_crash()
    {
        var me = Sid("S-1-5-21-1");
        File.WriteAllBytes(Path.Combine(me, "$IBAD.jar"), [1, 2, 3]);
        var (sink, run) = await RunAsync();
        Assert.Equal(ModuleState.CompletedWithErrors, Assert.Single(run.Modules).State);
        Assert.Equal(CollectionStatus.Partial, Assert.Single(sink.Coverage).Status);
    }

    [Fact]
    public async Task No_recycle_bin_is_stated()
    {
        Directory.CreateDirectory(_volume);
        var (sink, _) = await RunAsync();
        Assert.Contains(Assert.Single(sink.Coverage).Limitations, l => l.Code == "RECYCLE.NONE");
    }
}

public sealed class MinecraftLogParserTests
{
    internal const string FabricLog = """
        [10:15:32] [main/INFO]: Loading Minecraft 1.20.1 with Fabric Loader 0.14.22
        [10:15:32] [main/INFO]: Loading 6 mods:
        	- fabric-api 0.86.1+1.20.1
        	   |-- fabric-api-base 0.4.29+b04edc7a77
        	   \-- fabric-networking-api-v1 1.3.9+b04edc7a77
        	- fabricloader 0.14.22
        	- java 17
        	- minecraft 1.20.1
        	- sodium 0.5.3+mc1.20.1
        	- meteor-client 0.5.4-SNAPSHOT
        [10:15:33] [main/INFO]: SpongePowered MIXIN Subsystem Version=0.8.5
        [10:15:40] [Render thread/INFO]: Setting user: Steve
        [10:16:10] [Render thread/INFO]: Connecting to play.example.net, 25565
        [10:16:10] [Render thread/INFO]: Connecting to play.example.net, 25565
        [10:47:02] [Render thread/INFO]: Stopping!
        """;

    internal const string ForgeLog = """
        [08Nov2026 18:01:02.123] [main/INFO] [cpw.mods.modlauncher.Launcher/MODLAUNCHER]: ModLauncher running: args [--username, Alex, --version, 1.20.1-forge-47.2.0, --fml.forgeVersion, 47.2.0, --fml.mcVersion, 1.20.1, --fml.forgeGroup, net.minecraftforge]
        [08Nov2026 18:01:05.000] [main/DEBUG] [net.minecraftforge.fml.loading.moddiscovery.ModDiscoverer/SCAN]: Found mod file jei-1.20.1-forge-15.2.0.27.jar of type MOD with provider {mods folder locator at C:\Users\x\AppData\Roaming\.minecraft\mods}
        [08Nov2026 18:01:05.010] [main/DEBUG] [net.minecraftforge.fml.loading.moddiscovery.ModDiscoverer/SCAN]: Found mod file "xray-1.20.1.jar" of type MOD with provider {mods folder locator}
        [08Nov2026 18:05:00.000] [Render thread/INFO] [net.minecraft.client.Minecraft/]: Setting user: Alex
        """;

    [Fact]
    public void Fabric_log_gives_version_loader_mods_user_servers_and_times()
    {
        var f = MinecraftLogParser.Parse(new StringReader(FabricLog));
        Assert.Equal(("1.20.1", "fabric", "0.14.22"), (f.GameVersion, f.Loader, f.LoaderVersion));
        Assert.Equal(new[] { "fabric-api@0.86.1+1.20.1", "fabricloader@0.14.22", "java@17", "minecraft@1.20.1", "sodium@0.5.3+mc1.20.1", "meteor-client@0.5.4-SNAPSHOT" },
            f.Mods.Where(m => !m.Nested).Select(m => $"{m.Id}@{m.Version}"));
        Assert.Equal(new[] { "fabric-api-base", "fabric-networking-api-v1" }, f.Mods.Where(m => m.Nested).Select(m => m.Id));
        Assert.Equal("Steve", f.User);
        Assert.Equal(new[] { "play.example.net:25565" }, f.Servers);
        Assert.Equal((new TimeSpan(10, 15, 32), new TimeSpan(10, 47, 2)), (f.FirstTime!.Value, f.LastTime!.Value));
        Assert.Null(f.PrintedDate);
    }

    [Fact]
    public void Forge_log_gives_the_date_and_the_mod_files()
    {
        var f = MinecraftLogParser.Parse(new StringReader(ForgeLog));
        Assert.Equal(("1.20.1", "forge", "47.2.0"), (f.GameVersion, f.Loader, f.LoaderVersion));
        Assert.Equal(new DateOnly(2026, 11, 8), f.PrintedDate);
        Assert.Equal(new[] { "jei-1.20.1-forge-15.2.0.27.jar", "xray-1.20.1.jar" }, f.ModFiles);
        Assert.Equal("Alex", f.User);
    }

    [Fact]
    public void A_rotated_log_name_gives_its_day() =>
        Assert.Equal(new DateOnly(2026, 11, 7), MinecraftLogParser.DateFromName("2026-11-07-3.log.gz"));

    [Fact]
    public void Garbage_and_very_long_logs_do_not_break_the_parser()
    {
        var rng = new Random(3);
        var junk = new StringBuilder();
        for (var i = 0; i < 20_000; i++)
        {
            junk.Append((char)rng.Next(1, 0x2FFF));
            if (i % 120 == 0)
            {
                junk.Append('\n');
            }
        }

        _ = MinecraftLogParser.Parse(new StringReader(junk.ToString()));
        var huge = MinecraftLogParser.Parse(new StringReader(string.Concat(Enumerable.Repeat("[10:00:00] [main/INFO]: x\n", MinecraftLogParser.MaxLines + 10))));
        Assert.True(huge.Truncated);
    }
}

public sealed class MinecraftLogsAnalyzerTests : IDisposable
{
    private readonly PlayerProfile _p = new();

    public void Dispose() => _p.Dispose();

    [Fact]
    public async Task Each_log_of_each_game_folder_becomes_one_launch_with_its_mods()
    {
        var logs = Path.Combine(_p.MinecraftDir, "logs");
        File.WriteAllText(Path.Combine(logs, "latest.log"), MinecraftLogParserTests.FabricLog);
        File.SetLastWriteTimeUtc(Path.Combine(logs, "latest.log"), new DateTime(2026, 11, 8, 10, 47, 2, DateTimeKind.Utc));
        using (var gz = new GZipStream(File.Create(Path.Combine(logs, "2026-11-07-1.log.gz")), CompressionLevel.Fastest))
        {
            gz.Write(Encoding.UTF8.GetBytes(MinecraftLogParserTests.FabricLog.Replace("meteor-client 0.5.4-SNAPSHOT", "iris 1.6.4", StringComparison.Ordinal)));
        }

        // A Prism-style instance: game folder named "minecraft", recognised by its contents.
        var instance = _p.P("AppData", "Roaming", "PrismLauncher", "instances", "Pack", "minecraft");
        Directory.CreateDirectory(Path.Combine(instance, "mods"));
        Directory.CreateDirectory(Path.Combine(instance, "logs"));
        File.WriteAllText(Path.Combine(instance, "options.txt"), "x");
        File.WriteAllText(Path.Combine(instance, "logs", "latest.log"), MinecraftLogParserTests.ForgeLog);

        var sink = new MemorySink();
        var options = new HistoryOptions { Volumes = [], UsersRoot = _p.Users, CurrentProfile = _p.Player };
        var permissions = new PermissionManager(new FixedProbe(), TimeProvider.System).Snapshot();
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System).RunAsync(
            Ulid.NewUlid(DateTimeOffset.UtcNow), [new MinecraftLogsAnalyzer(options, SystemDirectoryLister.Instance, new TestFileSource(), TimeZoneInfo.Utc)], CancellationToken.None);

        Assert.Equal(ModuleState.Completed, Assert.Single(run.Modules).State);

        // The player profile fixture already has a one-line latest.log; it is replaced above. 3 logs in total.
        Assert.Equal(3, sink.Evidence.Count);
        var latest = sink.Evidence.Single(e => e.Locator.EndsWith(Path.Combine(".minecraft", "logs", "latest.log"), StringComparison.Ordinal));
        Assert.Equal(EvidenceEventType.Loaded, latest.EventType);
        Assert.Contains("meteor-client@0.5.4-SNAPSHOT", latest.Attributes["Game.Mods"], StringComparison.Ordinal);
        Assert.Equal(new DateTimeOffset(2026, 11, 8, 10, 15, 32, TimeSpan.Zero), latest.Timestamp!.ValueUtc);
        Assert.Equal(TimeSpan.FromDays(1), latest.Timestamp.Uncertainty);
        Assert.Contains(latest.Limitations, l => l.Code == "LOG.DATE_FROM_FILE");

        var rotated = sink.Evidence.Single(e => e.Locator.EndsWith("2026-11-07-1.log.gz", StringComparison.Ordinal));
        Assert.Equal(new DateTimeOffset(2026, 11, 7, 10, 15, 32, TimeSpan.Zero), rotated.Timestamp!.ValueUtc);
        Assert.Equal(TimeSpan.Zero, rotated.Timestamp.Uncertainty);
        Assert.Contains("iris@1.6.4", rotated.Attributes["Game.Mods"], StringComparison.Ordinal);

        var forge = sink.Evidence.Single(e => e.Attributes.GetValueOrDefault("Game.Loader") == "forge");
        Assert.Equal(instance, forge.Target.RecordedPath);
        Assert.Contains("xray-1.20.1.jar", forge.Attributes["Game.ModFiles"], StringComparison.Ordinal);
        Assert.Equal(new DateTimeOffset(2026, 11, 8, 18, 1, 2, TimeSpan.Zero), forge.Timestamp!.ValueUtc);

        Assert.Equal(3, Assert.Single(sink.Coverage).ItemsRead);
    }
}
