using System.Text;
using XINSkan.Analyzers.Execution;
using XINSkan.Analyzers.History;
using XINSkan.Core.IO;
using XINSkan.Core.Permissions;
using XINSkan.ExecutionFormats;
using XINSkan.FileHunterTests.Support;
using XINSkan.Models;
using XINSkan.ShellFormatsTests;

namespace XINSkan.ExecutionTests;

public sealed class UserHivesTests : IDisposable
{
    private static readonly DateTime T = new(2026, 11, 2, 15, 0, 0, DateTimeKind.Utc);
    private readonly PlayerProfile _p = new();

    public void Dispose() => _p.Dispose();

    private string Anna => Path.Combine(_p.Users, "anna");

    private HistoryOptions Options => new() { Volumes = ["C:"], UsersRoot = _p.Users, CurrentProfile = _p.Player };

    /// <summary>A chain of keys "A\B\C" ending in <paramref name="leaf"/>.</summary>
    private static TestKey Chain(string path, TestKey leaf)
    {
        var parts = path.Split('\\');
        var key = leaf with { Name = parts[^1] };
        for (var i = parts.Length - 2; i >= 0; i--)
        {
            key = new TestKey(parts[i], SubKeys: [key]);
        }

        return key;
    }

    private static TestValue Bin(string name, byte[] data) => new(name, HiveValue.RegBinary, data);

    /// <summary>UsrClass.dat whose BagMRU holds C:\Users\anna\Downloads\cheats.zip\wurst.</summary>
    private static byte[] UsrClass()
    {
        var wurst = new TestKey("0", T.ToFileTimeUtc());
        var zip = new TestKey("0", T.ToFileTimeUtc(), [Bin("0", ShellBuilders.Entry("WURST", "wurst", true, T))], [wurst]);
        var downloads = new TestKey("0", T.ToFileTimeUtc(), [Bin("0", ShellBuilders.Entry("CHEATS~1.ZIP", "cheats.zip", true, T))], [zip]);
        var anna = new TestKey("0", T.ToFileTimeUtc(), [Bin("0", ShellBuilders.Entry("DOWNLO~1", "Downloads", true, T))], [downloads]);
        var users = new TestKey("0", T.ToFileTimeUtc(), [Bin("0", ShellBuilders.Entry("anna", "anna", true, T))], [anna]);
        var c = new TestKey("0", T.ToFileTimeUtc(), [Bin("0", ShellBuilders.Entry("Users", "Users", true, T))], [users]);
        var computer = new TestKey("0", T.ToFileTimeUtc(), [Bin("0", ShellBuilders.Volume('C'))], [c]);
        var bagMru = new TestKey("BagMRU", T.ToFileTimeUtc(), [Bin("0", ShellBuilders.Root(new Guid("20D04FE0-3AEA-1069-A2D8-08002B30309D")))], [computer]);
        return HiveBuilder.Build(new TestKey("S-1-5-21-1-1002_Classes", SubKeys: [Chain(@"Local Settings\Software\Microsoft\Windows\Shell\BagMRU", bagMru)]));
    }

    private static byte[] UserAssistData(int runs, DateTime last)
    {
        var d = new byte[72];
        BitConverter.GetBytes(runs).CopyTo(d, 4);
        BitConverter.GetBytes(runs).CopyTo(d, 8);
        BitConverter.GetBytes(90_000u).CopyTo(d, 12);
        BitConverter.GetBytes(last.ToFileTimeUtc()).CopyTo(d, 60);
        return d;
    }

    private static byte[] NtUser(params (string Name, byte[] Data)[] entries) => HiveBuilder.Build(new TestKey("ROOT", SubKeys:
    [
        Chain(UserAssistAnalyzer.Key + @"\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
            new TestKey("Count", T.ToFileTimeUtc(), [.. entries.Select(e => Bin(UserAssistAnalyzer.Rot13(e.Name), e.Data))])),
    ]));

    private TestProtectedFiles AnnaFiles()
    {
        Directory.CreateDirectory(Anna);
        return new TestProtectedFiles()
            .Add(ProgramRelevance.Join(Anna, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"), UsrClass())
            .Add(ProgramRelevance.Join(Anna, "NTUSER.DAT"), NtUser((ProgramRelevance.Join(Anna, "Downloads", "autoclicker.exe"), UserAssistData(12, T))));
    }

    [Fact]
    public void Hive_view_sends_classes_to_usrclass_and_converts_values()
    {
        var ntuser = RegistryHive.Open(HiveBuilder.Build(new TestKey("ROOT", SubKeys: [Chain(@"Software\Lunar", new TestKey("Lunar", 5, [TestValue.Dword("Runs", 3), TestValue.Sz("Path", "x"), TestValue.Qword("Q", 9)]))])))!;
        var classes = RegistryHive.Open(HiveBuilder.Build(new TestKey("X_Classes", SubKeys: [new TestKey(".jar", 7, [TestValue.Sz("", "jarfile")])])))!;
        var view = new HiveRegistryView(ntuser.Root, classes.Root);
        Assert.Equal(3, view.Values(@"Software\Lunar")!.Single(v => v.Name == "Runs").Value);
        Assert.Equal("x", view.Values(@"Software\Lunar")!.Single(v => v.Name == "Path").Value);
        Assert.Equal(9L, view.Values(@"Software\Lunar")!.Single(v => v.Name == "Q").Value);
        Assert.Equal(new[] { ".jar" }, view.SubKeys(@"Software\Classes"));
        Assert.Equal(7, view.LastWriteTime(@"Software\Classes\.jar"));
        Assert.Null(view.Values(@"Software\ClassesX"));
    }

    [Fact]
    public async Task Other_users_shellbags_are_read_from_their_hive_with_permission_only()
    {
        var hives = new UserHives(Options, SystemDirectoryLister.Instance, AnnaFiles(), NoRegistry.Instance);
        var analyzer = new ShellBagsAnalyzer(new EmptyShellBags(), new OtherUserShellBags(hives));

        var denied = await PrefetchAnalyzerTests.RunAsync(analyzer);
        Assert.Empty(denied.Evidence);
        Assert.Contains(denied.Coverage[0].Limitations, l => l.Code == "SHELLBAGS.OTHER_USERS");

        var sink = await PrefetchAnalyzerTests.RunAsync(new ShellBagsAnalyzer(new EmptyShellBags(), new OtherUserShellBags(hives)), Capability.OtherUserProfiles);
        var paths = sink.Evidence.Select(e => e.Target.RecordedPath).ToList();
        Assert.Contains(@"C:\Users\anna\Downloads\cheats.zip", paths);
        Assert.Contains(@"C:\Users\anna\Downloads\cheats.zip\wurst", paths);
        var e = sink.Evidence.First();
        Assert.Equal("anna", e.Attributes["ShellBags.User"]);
        Assert.StartsWith(@"USER(anna)\Software\Classes\Local Settings", e.Locator, StringComparison.Ordinal);
        Assert.Contains("anna", e.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UserAssist_of_the_current_user_from_the_registry_and_of_others_from_their_hives()
    {
        var current = new TestRegistry();
        var count = UserAssistAnalyzer.Key + @"\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count";
        current.Set(count, UserAssistAnalyzer.Rot13(_p.P("Downloads", "injector.exe")), UserAssistData(3, T.AddDays(1)));
        current.Set(count, UserAssistAnalyzer.Rot13(@"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\notepad.exe"), UserAssistData(40, T));
        current.Set(count, UserAssistAnalyzer.Rot13(@"{6D809377-6AF0-444B-8957-A3773F02200E}\Java\bin\javaw.exe"), UserAssistData(7, T));
        current.Set(count, UserAssistAnalyzer.Rot13("UEME_CTLSESSION"), new byte[1612]);
        current.Set(count, UserAssistAnalyzer.Rot13("Microsoft.Windows.Explorer"), UserAssistData(1, T));

        var hives = new UserHives(Options, SystemDirectoryLister.Instance, AnnaFiles(), NoRegistry.Instance);
        var sink = await PrefetchAnalyzerTests.RunAsync(new UserAssistAnalyzer(Options, current, hives, new TestVolumes()), Capability.OtherUserProfiles);

        Assert.Equal(new[] { "autoclicker.exe", "injector.exe", "javaw.exe" }, sink.Evidence.Select(e => e.Target.FileName).Order(StringComparer.Ordinal));
        var injector = sink.Evidence.Single(e => e.Target.FileName == "injector.exe");
        Assert.Equal(EvidenceEventType.Executed, injector.EventType);
        Assert.Equal(EvidenceSourceKind.UserAssist, injector.Source.Kind);
        Assert.Equal("3", injector.Attributes["UserAssist.RunCount"]);
        Assert.Equal("00:01:30", injector.Attributes["UserAssist.FocusTime"]);
        Assert.Equal(new DateTimeOffset(T.AddDays(1)), injector.Timestamp!.ValueUtc);
        Assert.StartsWith("HKCU", injector.Locator, StringComparison.Ordinal);
        Assert.Equal(@"C:\Program Files\Java\bin\javaw.exe", sink.Evidence.Single(e => e.Target.FileName == "javaw.exe").Target.RecordedPath);

        var clicker = sink.Evidence.Single(e => e.Target.FileName == "autoclicker.exe");
        Assert.Equal("anna", clicker.Attributes["UserAssist.User"]);
        Assert.Equal("12", clicker.Attributes["UserAssist.RunCount"]);
        Assert.StartsWith("USER(anna)", clicker.Locator, StringComparison.Ordinal);
        Assert.Equal(5 + 1, Assert.Single(sink.Coverage).ItemsRead);
    }

    [Theory]
    [InlineData("HRZR_PGYFRFFVBA", "UEME_CTLSESSION")]
    [InlineData(@"P:\Hfref\cynlre\Qbjaybnqf\k.rkr", @"C:\Users\player\Downloads\x.exe")]
    [InlineData("{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}", "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}")]
    public void Rot13_decodes_letters_only(string encoded, string decoded) => Assert.Equal(decoded, UserAssistAnalyzer.Rot13(encoded));

    private sealed class EmptyShellBags : IShellBagSource
    {
        public IReadOnlyList<(string Name, byte[] Data)>? Values(string key) => null;

        public IReadOnlyList<string>? SubKeys(string key) => null;

        public long? LastWriteTime(string key) => null;
    }
}
