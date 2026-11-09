using XINSkan.Analyzers.History;
using XINSkan.Core.IO;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.FileHunterTests.Support;
using XINSkan.Models;
using XINSkan.ShellFormatsTests;

namespace XINSkan.HistoryTests;

public sealed class LnkAndJumpListAnalyzerTests : IDisposable
{
    private readonly PlayerProfile _p = new();

    public void Dispose() => _p.Dispose();

    private string Recent => _p.P("AppData", "Roaming", "Microsoft", "Windows", "Recent");

    private static async Task<MemorySink> RunAsync(IAnalyzer analyzer)
    {
        var sink = new MemorySink();
        var permissions = new PermissionManager(new FixedProbe(), TimeProvider.System).Snapshot();
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System).RunAsync(Ulid.NewUlid(DateTimeOffset.UtcNow), [analyzer], CancellationToken.None);
        Assert.Equal(ModuleState.Completed, Assert.Single(run.Modules).State);
        return sink;
    }

    private HistoryOptions Options => new() { Volumes = [], UsersRoot = _p.Users, CurrentProfile = _p.Player };

    [Fact]
    public async Task Recent_links_to_relevant_targets_are_recorded_with_drive_and_times()
    {
        Directory.CreateDirectory(Recent);
        var modified = new DateTimeOffset(2026, 11, 7, 12, 0, 0, TimeSpan.Zero).UtcDateTime.ToFileTimeUtc();
        File.WriteAllBytes(Path.Combine(Recent, "wurst-client.jar.lnk"), ShellBuilders.Link(@"E:\cheats\wurst-client.jar", 2, 0xA1B2C3D4, "KINGSTON", targetModified: modified));
        File.WriteAllBytes(Path.Combine(Recent, ".minecraft.lnk"), ShellBuilders.Link(@"C:\Users\player\AppData\Roaming\.minecraft", 3, 0x1234, "SYSTEM"));
        File.WriteAllBytes(Path.Combine(Recent, "essay.docx.lnk"), ShellBuilders.Link(@"C:\Users\player\Documents\essay.docx", 3, 0x1234, "SYSTEM"));
        File.WriteAllBytes(Path.Combine(Recent, "broken.lnk"), [1, 2, 3]);
        var lnkTime = new DateTime(2026, 11, 8, 9, 0, 0, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(Path.Combine(Recent, "wurst-client.jar.lnk"), lnkTime);

        var sink = await RunAsync(new LnkAnalyzer(Options, SystemDirectoryLister.Instance, new TestFileSource()));
        Assert.Equal(new[] { @"C:\Users\player\AppData\Roaming\.minecraft", @"E:\cheats\wurst-client.jar" },
            sink.Evidence.Select(e => e.Target.RecordedPath).Order(StringComparer.Ordinal));

        var usb = sink.Evidence.Single(e => e.Target.FileName == "wurst-client.jar");
        Assert.Equal(EvidenceEventType.Accessed, usb.EventType);
        Assert.Equal(EvidenceSourceKind.Lnk, usb.Source.Kind);
        Assert.Equal("съёмный", usb.Attributes["Lnk.DriveType"]);
        Assert.Equal("A1B2C3D4", usb.Attributes["Lnk.DriveSerial"]);
        Assert.Equal("KINGSTON", usb.Attributes["Lnk.VolumeLabel"]);
        Assert.Equal(new DateTimeOffset(lnkTime), usb.Timestamp!.ValueUtc);
        Assert.Contains(usb.OtherTimestamps, t => t.Field == "Lnk.TargetModified" && t.ValueUtc == DateTimeOffset.FromFileTime(modified).ToUniversalTime());
        Assert.Equal(Confidence.Informational, usb.Confidence);

        var c = Assert.Single(sink.Coverage);
        Assert.Equal(4, c.ItemsRead);
        Assert.Contains(c.Limitations, l => l.Code == "LNK.DAMAGED");
    }

    [ShellSampleFact]
    public async Task Jump_lists_are_read_and_only_relevant_entries_recorded()
    {
        var auto = Path.Combine(Recent, "AutomaticDestinations");
        var custom = Path.Combine(Recent, "CustomDestinations");
        Directory.CreateDirectory(auto);
        Directory.CreateDirectory(custom);
        var root = ShellSampleFactAttribute.File("JumpList", "JumpList.Test", "TestFiles");
        File.Copy(Path.Combine(root, "Win10", "f01b4d95cf55d32a.automaticDestinations-ms"), Path.Combine(auto, "f01b4d95cf55d32a.automaticDestinations-ms"));
        File.Copy(Path.Combine(root, "dtformats", "5afe4de1b92fc382.customDestinations-ms"), Path.Combine(custom, "5afe4de1b92fc382.customDestinations-ms"));

        var sink = await RunAsync(new JumpListAnalyzer(Options, SystemDirectoryLister.Instance, new TestFileSource()));

        // Explorer's list holds folders like C:\Temp (not relevant); the custom list pins GettingStarted.exe (a program).
        Assert.Equal(9, sink.Evidence.Count);
        Assert.All(sink.Evidence, e => Assert.Equal(@"C:\Windows\System32\GettingStarted.exe", e.Target.RecordedPath));
        Assert.All(sink.Evidence, e => Assert.Equal(EvidenceSourceKind.JumpList, e.Source.Kind));
        Assert.Equal(2, Assert.Single(sink.Coverage).ItemsRead);
    }
}

public sealed class ShellBagsAnalyzerTests
{
    private sealed class MemoryRegistry : IShellBagSource
    {
        public Dictionary<string, List<(string, byte[])>> Keys { get; } = new(StringComparer.OrdinalIgnoreCase);

        public void Add(string key, string name, byte[] item)
        {
            Keys.TryAdd(key, []);
            Keys[key].Add((name, item));
            Keys.TryAdd(key + "\\" + name, []);
        }

        public IReadOnlyList<(string Name, byte[] Data)>? Values(string key) => Keys.TryGetValue(key, out var v) ? v : null;

        public IReadOnlyList<string>? SubKeys(string key) => Keys.ContainsKey(key) ? Keys.Keys.Where(k => k.StartsWith(key + "\\", StringComparison.OrdinalIgnoreCase)).ToList() : null;

        public long? LastWriteTime(string key) => new DateTimeOffset(2026, 11, 8, 20, 0, 0, TimeSpan.Zero).UtcDateTime.ToFileTimeUtc();
    }

    [Fact]
    public async Task Folders_of_minecraft_launchers_and_archives_opened_in_explorer_are_recorded()
    {
        var t = new DateTime(2026, 11, 1, 10, 0, 0, DateTimeKind.Utc);
        var r = new MemoryRegistry();
        var root = ShellBagsAnalyzer.Roots[0];
        r.Add(root, "0", ShellBuilders.Root(new Guid("20D04FE0-3AEA-1069-A2D8-08002B30309D")));
        r.Add(root + "\\0", "0", ShellBuilders.Volume('C'));
        r.Add(root + "\\0\\0", "0", ShellBuilders.Entry("Users", "Users", true, t));
        r.Add(root + "\\0\\0\\0", "0", ShellBuilders.Entry("player", "player", true, t));
        r.Add(root + "\\0\\0\\0\\0", "0", ShellBuilders.Entry("AppData", "AppData", true, t));
        r.Add(root + "\\0\\0\\0\\0\\0", "0", ShellBuilders.Entry("Roaming", "Roaming", true, t));
        r.Add(root + "\\0\\0\\0\\0\\0\\0", "0", ShellBuilders.Entry("MINECR~1", ".minecraft", true, t, 9, 777, 3));
        r.Add(root + "\\0\\0\\0\\0\\0\\0\\0", "0", ShellBuilders.Entry("mods", "mods", true, t));
        r.Add(root + "\\0\\0\\0\\0", "1", ShellBuilders.Entry("DOWNLO~1", "Downloads", true, t));
        r.Add(root + "\\0\\0\\0\\0\\1", "0", ShellBuilders.Entry("CHEATS~1.ZIP", "cheats.zip", true, t));
        r.Add(root + "\\0\\0\\0\\0\\1\\0", "0", ShellBuilders.Entry("WURST", "wurst", true, t));
        r.Add(root + "\\0\\0\\0\\0", "2", ShellBuilders.Entry("DOCUME~1", "Documents", true, t));

        var sink = new MemorySink();
        var permissions = new PermissionManager(new FixedProbe(), TimeProvider.System).Snapshot();
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System).RunAsync(Ulid.NewUlid(DateTimeOffset.UtcNow), [new ShellBagsAnalyzer(r)], CancellationToken.None);
        Assert.Equal(ModuleState.Completed, Assert.Single(run.Modules).State);

        Assert.Equal(
            new[]
            {
                @"C:\Users\player\AppData\Roaming\.minecraft",
                @"C:\Users\player\AppData\Roaming\.minecraft\mods",
                @"C:\Users\player\Downloads\cheats.zip",
                @"C:\Users\player\Downloads\cheats.zip\wurst",
            },
            sink.Evidence.Select(e => e.Target.RecordedPath).Order(StringComparer.Ordinal));

        var mc = sink.Evidence.Single(e => e.Target.RecordedPath!.EndsWith(".minecraft", StringComparison.Ordinal));
        Assert.Equal((777UL, (ushort)3), (mc.Target.MftEntry!.Value, mc.Target.MftSequence!.Value));
        Assert.Equal("Registry.KeyLastWrite", mc.Timestamp!.Field);
        Assert.Contains(mc.OtherTimestamps, x => x.Field == "ShellItem.Modified" && x.Precision == TimestampPrecision.TwoSeconds);
        Assert.Equal(EvidenceEventType.Accessed, mc.EventType);

        var c = Assert.Single(sink.Coverage);
        Assert.Equal(12, c.ItemsRead);
        Assert.Contains(c.Limitations, l => l.Code == "SHELLBAGS.CURRENT_USER");
    }

    [Fact]
    public async Task No_shellbags_is_stated_not_an_error()
    {
        var sink = new MemorySink();
        var permissions = new PermissionManager(new FixedProbe(), TimeProvider.System).Snapshot();
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System).RunAsync(Ulid.NewUlid(DateTimeOffset.UtcNow), [new ShellBagsAnalyzer(new MemoryRegistry())], CancellationToken.None);
        Assert.Equal(ModuleState.Completed, Assert.Single(run.Modules).State);
        Assert.Equal("Ключи ShellBags не найдены", Assert.Single(sink.Coverage).Scope);
    }
}
