using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using XINSkan.Analyzers.Minecraft;
using XINSkan.Core.IO;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.FileHunterTests.Support;
using XINSkan.Models;

namespace XINSkan.MinecraftTests;

/// <summary>Writes launcher folders the way the launchers write them.</summary>
internal sealed class GameFolders(string profile)
{
    public string Roaming => Path.Combine(profile, "AppData", "Roaming");

    public string Official => Path.Combine(Roaming, ".minecraft");

#pragma warning disable CA5350 // the version files publish SHA-1; tests write what they would contain
    public static string Sha1(byte[] b) => Convert.ToHexStringLower(SHA1.HashData(b));
#pragma warning restore CA5350

    public static void Write(string path, byte[] data)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, data);
    }

    public static void Json(string path, object value) => Write(path, JsonSerializer.SerializeToUtf8Bytes(value));

    public static string Lib(string root, string relative) => Path.Combine([root, "libraries", .. relative.Split('/')]);

    /// <summary>A vanilla version with a client JAR and libraries; clientBytes may differ from what the file promises.</summary>
    public static void Vanilla(string root, string id, byte[] promised, byte[] actual, params (string Path, byte[] Promised, byte[]? Actual)[] libraries)
    {
        Write(Path.Combine(root, "versions", id, id + ".jar"), actual);
        foreach (var (p, _, a) in libraries.Where(l => l.Actual is not null))
        {
            Write(Lib(root, p), a!);
        }

        Json(Path.Combine(root, "versions", id, id + ".json"), new
        {
            id,
            mainClass = "net.minecraft.client.main.Main",
            downloads = new { client = new { sha1 = Sha1(promised), size = promised.Length, url = $"https://piston-data.mojang.com/v1/objects/{Sha1(promised)}/client.jar" } },
            libraries = libraries.Select(l => new { name = "x:y:1", downloads = new { artifact = new { path = l.Path, sha1 = Sha1(l.Promised), size = l.Promised.Length, url = "https://libraries.minecraft.net/" + l.Path } } }).ToArray(),
            arguments = new { jvm = new object[] { "-Djava.library.path=${natives_directory}", new { rules = Array.Empty<object>(), value = "-XstartOnFirstThread" } } },
        });
    }
}

public sealed class MinecraftIntegrityTests : IDisposable
{
    private readonly PlayerProfile _p = new();
    private static readonly byte[] Client = Encoding.ASCII.GetBytes("PK vanilla client 1.20.1");
    private static readonly byte[] Authlib = Encoding.ASCII.GetBytes("PK authlib");
    private static readonly byte[] Lwjgl = Encoding.ASCII.GetBytes("PK lwjgl");

    public void Dispose() => _p.Dispose();

    private MinecraftOptions Options => new() { UsersRoot = _p.Users, CurrentProfile = _p.Player };

    private static async Task<MemorySink> RunAsync(IAnalyzer analyzer, params Capability[] capabilities)
    {
        var sink = new MemorySink();
        var permissions = new PermissionManager(new FixedProbe(capabilities), TimeProvider.System).Snapshot();
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System).RunAsync(Ulid.NewUlid(DateTimeOffset.UtcNow), [analyzer], CancellationToken.None);
        Assert.Equal(ModuleState.Completed, Assert.Single(run.Modules).State);
        foreach (var e in sink.Evidence)
        {
            Assert.Empty(e.Validate());
        }

        return sink;
    }

    [Fact]
    public async Task Official_launcher_profiles_versions_and_libraries_are_checked()
    {
        var g = new GameFolders(_p.Player);
        GameFolders.Json(Path.Combine(g.Official, "launcher_profiles.json"), new
        {
            profiles = new Dictionary<string, object>
            {
                ["a1"] = new { name = "PvP", type = "custom", lastVersionId = "1.20.1", lastUsed = "2026-11-07T19:30:00.000Z", javaArgs = "-Xmx4G \"-javaagent:C:\\Users\\player\\Downloads\\my agent.jar=cfg\" -XX:+UseG1GC" },
                ["b2"] = new { type = "latest-release", lastVersionId = "latest-release", lastUsed = "2026-10-01T10:00:00.000Z" },
            },
            version = 3,
        });
        GameFolders.Vanilla(g.Official, "1.20.1", Client, Client,
            ("com/mojang/authlib/4.0.43/authlib-4.0.43.jar", Authlib, Authlib),
            ("org/lwjgl/lwjgl/3.3.1/lwjgl-3.3.1.jar", Lwjgl, Encoding.ASCII.GetBytes("PK lwjgl patched")),
            ("org/lwjgl/lwjgl/3.3.1/lwjgl-3.3.1-natives-macos.jar", Lwjgl, null));
        GameFolders.Vanilla(g.Official, "1.8.9-hacked", Client, Encoding.ASCII.GetBytes("PK modified client"));

        // A Fabric profile: inherits the vanilla version, Fabric-style libraries with top-level hashes.
        var loader = Encoding.ASCII.GetBytes("PK fabric loader");
        GameFolders.Write(GameFolders.Lib(g.Official, "net/fabricmc/fabric-loader/0.15.0/fabric-loader-0.15.0.jar"), loader);
        GameFolders.Json(Path.Combine(g.Official, "versions", "fabric-loader-0.15.0-1.20.1", "fabric-loader-0.15.0-1.20.1.json"), new
        {
            id = "fabric-loader-0.15.0-1.20.1",
            inheritsFrom = "1.20.1",
            mainClass = "net.fabricmc.loader.impl.launch.knot.KnotClient",
            libraries = new object[] { new { name = "net.fabricmc:fabric-loader:0.15.0", url = "https://maven.fabricmc.net/", sha1 = GameFolders.Sha1(loader) } },
        });

        // A "client" with its own entry point and JVM options in the version file.
        GameFolders.Json(Path.Combine(g.Official, "versions", "Wurst", "Wurst.json"), new
        {
            id = "Wurst",
            inheritsFrom = "1.20.1",
            mainClass = "net.wurstclient.Launch",
            arguments = new { jvm = new[] { "-noverify" } },
        });

        var sink = await RunAsync(new MinecraftIntegrityAnalyzer(Options, SystemDirectoryLister.Instance, new TestFileSource()));
        var ev = sink.Evidence;

        var pvp = ev.Single(e => e.Attributes.GetValueOrDefault("Instance.Name") == "PvP");
        Assert.Equal(EvidenceSourceKind.Launcher, pvp.Source.Kind);
        Assert.Equal("1.20.1", pvp.Attributes["Instance.Version"]);
        Assert.Equal(new DateTimeOffset(2026, 11, 7, 19, 30, 0, TimeSpan.Zero), pvp.Timestamp!.ValueUtc);
        Assert.Contains(ev, e => e.Attributes.GetValueOrDefault("Instance.Name") == "Последний выпуск");

        var agent = ev.Single(e => e.Attributes.GetValueOrDefault("Jvm.Flag") == "javaagent");
        Assert.Equal(@"C:\Users\player\Downloads\my agent.jar", agent.Target.RecordedPath);
        Assert.NotNull(agent.Target.NormalizedPath); // links to the agent JAR found by File Hunter
        Assert.Equal(Confidence.Low, agent.Confidence);
        Assert.Contains("профилировщик", agent.Rationale, StringComparison.Ordinal);

        var vanilla = ev.Single(e => e.Attributes.GetValueOrDefault("Version.Id") == "1.20.1" && e.Attributes.ContainsKey("Version.Libraries"));
        Assert.Equal("Match", vanilla.Attributes["Version.Client"]);
        Assert.Equal("3", vanilla.Attributes["Version.Libraries"]);
        Assert.Equal("1", vanilla.Attributes["Version.LibrariesMatched"]);
        Assert.Equal("1", vanilla.Attributes["Version.LibrariesMismatched"]);
        Assert.Equal("1", vanilla.Attributes["Version.LibrariesMissing"]);

        var lib = ev.Single(e => e.Target.FileName == "lwjgl-3.3.1.jar");
        Assert.Equal(Confidence.Low, lib.Confidence);
        Assert.Equal(GameFolders.Sha1(Lwjgl), lib.Attributes["Sha1.Expected"]);

        // The modified client: Mojang's URL and hash in the version file, a different JAR on disk.
        var hacked = ev.Single(e => e.Target.FileName == "1.8.9-hacked.jar");
        Assert.Equal(Confidence.Medium, hacked.Confidence);
        Assert.Equal(GameFolders.Sha1(Client), hacked.Attributes["Sha1.Expected"]);

        var fabric = ev.Single(e => e.Attributes.GetValueOrDefault("Version.Id") == "fabric-loader-0.15.0-1.20.1" && e.Attributes.ContainsKey("Version.Libraries"));
        Assert.Equal("1", fabric.Attributes["Version.LibrariesMatched"]);
        Assert.Equal("1.20.1", fabric.Attributes["Version.InheritsFrom"]);
        Assert.False(fabric.Attributes.ContainsKey("Version.Client")); // checked in the vanilla pass

        Assert.Contains(ev, e => e.Attributes.GetValueOrDefault("Version.MainClass") == "net.wurstclient.Launch" && e.Confidence == Confidence.Low && !e.Attributes.ContainsKey("Version.Libraries"));
        Assert.Contains(ev, e => e.Attributes.GetValueOrDefault("Jvm.Flag") == "noverify" && e.Attributes["Jvm.Where"].Contains("Wurst", StringComparison.Ordinal));
        Assert.DoesNotContain(ev, e => e.Attributes.GetValueOrDefault("Version.MainClass") == "net.fabricmc.loader.impl.launch.knot.KnotClient" && e.Confidence == Confidence.Low);
        Assert.DoesNotContain(ev, e => e.Confidence > Confidence.Medium);

        var c = Assert.Single(sink.Coverage);
        Assert.Contains("Официальный лаунчер", c.Scope, StringComparison.Ordinal);
        Assert.DoesNotContain(c.Limitations, l => l.Code == "MC.BUDGET");
        Assert.Contains(c.Limitations, l => l.Code == "MC.OTHER_USERS"); // the fixture has a second profile
    }

    [Fact]
    public async Task Clients_of_official_versions_are_compared_with_what_Mojang_publishes()
    {
        var g = new GameFolders(_p.Player);
        var official = Encoding.ASCII.GetBytes("PK the real 1.20.1 client");
        var patched = Encoding.ASCII.GetBytes("PK 1.20.1 client with injected code");

        // 1. Version file and JAR changed together: the local check passes, Mojang's list does not.
        GameFolders.Vanilla(g.Official, "1.20.1", patched, patched);

        // 2. A third-party version file with no client download, and a patched JAR.
        GameFolders.Write(Path.Combine(g.Official, "versions", "1.19.4", "1.19.4.jar"), patched);
        GameFolders.Json(Path.Combine(g.Official, "versions", "1.19.4", "1.19.4.json"), new { id = "1.19.4", mainClass = "net.minecraft.client.main.Main" });

        // 3. The same, with the official JAR.
        GameFolders.Write(Path.Combine(g.Official, "versions", "1.18.2", "1.18.2.jar"), official);
        GameFolders.Json(Path.Combine(g.Official, "versions", "1.18.2", "1.18.2.json"), new { id = "1.18.2", mainClass = "net.minecraft.client.main.Main" });

        // 4. A version file whose client hash was edited, next to the official JAR.
        GameFolders.Vanilla(g.Official, "1.17.1", patched, official);

        // 5. Not an official id: nothing to compare with.
        GameFolders.Vanilla(g.Official, "1.20.1-pvp", patched, patched);

        var mojang = new Dictionary<string, OfficialClient>(StringComparer.Ordinal)
        {
            ["1.20.1"] = new(GameFolders.Sha1(official), official.Length, "test"),
            ["1.19.4"] = new(GameFolders.Sha1(official), official.Length, "test"),
            ["1.18.2"] = new(GameFolders.Sha1(official), official.Length, "test"),
            ["1.17.1"] = new(GameFolders.Sha1(official), official.Length, "test"),
        };
        var ev = (await RunAsync(new MinecraftIntegrityAnalyzer(Options with { OfficialClients = mojang }, SystemDirectoryLister.Instance, new TestFileSource()))).Evidence;
        Evidence Summary(string id) => ev.Single(e => e.Attributes.GetValueOrDefault("Version.Id") == id && e.Attributes.ContainsKey("Version.Libraries"));

        var edited = ev.Single(e => e.Target.FileName == "1.20.1.jar");
        Assert.Equal(Confidence.Medium, edited.Confidence);
        Assert.Equal(GameFolders.Sha1(official), edited.Attributes["Sha1.Official"]);
        Assert.Contains("файл версии изменён вместе с JAR", edited.Description, StringComparison.Ordinal);
        Assert.Equal("Match", Summary("1.20.1").Attributes["Version.Client"]); // the local check alone would pass
        Assert.Equal("differs", Summary("1.20.1").Attributes["Version.ClientOfficial"]);

        var noHash = ev.Single(e => e.Target.FileName == "1.19.4.jar");
        Assert.Equal(Confidence.Medium, noHash.Confidence);
        Assert.Contains("хеша клиента не указывает", noHash.Description, StringComparison.Ordinal);

        Assert.Equal("Mojang", Summary("1.18.2").Attributes["Version.ClientOfficial"]);
        Assert.DoesNotContain(ev, e => e.Target.FileName == "1.18.2.jar");

        var json = ev.Single(e => e.Attributes.GetValueOrDefault("Version.Id") == "1.17.1" && e.Confidence == Confidence.Low);
        Assert.Contains("файл версии правили", json.Rationale, StringComparison.Ordinal);
        Assert.Equal("Mojang", Summary("1.17.1").Attributes["Version.ClientOfficial"]);

        Assert.False(Summary("1.20.1-pvp").Attributes.ContainsKey("Version.ClientOfficial"));
        Assert.DoesNotContain(ev, e => e.Target.FileName == "1.20.1-pvp.jar");
    }

    [Fact]
    public async Task Prism_curseforge_atlauncher_modrinth_and_unparsed_launchers_are_found()
    {
        var g = new GameFolders(_p.Player);
        var prism = Path.Combine(g.Roaming, "PrismLauncher");
        GameFolders.Write(Path.Combine(prism, "prismlauncher.cfg"), Encoding.UTF8.GetBytes("[General]\nJvmArgs=-Xmx2G\nJavaPath=C:/Java/bin/javaw.exe\n"));
        GameFolders.Write(Path.Combine(prism, "instances", "PvP Pack", "instance.cfg"), Encoding.UTF8.GetBytes(
            "[General]\nname=PvP Pack\nOverrideJavaArgs=true\nJvmArgs=-javaagent:C:\\tools\\boost.jar\nlastLaunchTime=1762543800000\n"));
        GameFolders.Json(Path.Combine(prism, "instances", "PvP Pack", "mmc-pack.json"), new
        {
            components = new object[] { new { uid = "net.minecraft", version = "1.20.1" }, new { uid = "net.fabricmc.fabric-loader", version = "0.15.0" } },
            formatVersion = 1,
        });
        Directory.CreateDirectory(Path.Combine(prism, "instances", "PvP Pack", "minecraft"));
        var client = Encoding.ASCII.GetBytes("PK prism client");
        GameFolders.Write(GameFolders.Lib(prism, "com/mojang/minecraft/1.20.1/minecraft-1.20.1-client.jar"), client);
        GameFolders.Json(Path.Combine(prism, "meta", "net.minecraft", "1.20.1.json"), new
        {
            mainClass = "net.minecraft.client.main.Main",
            mainJar = new { name = "com.mojang:minecraft:1.20.1:client", downloads = new { artifact = new { sha1 = GameFolders.Sha1(client), size = client.Length, url = "https://piston-data.mojang.com/x/client.jar" } } },
            libraries = Array.Empty<object>(),
        });
        GameFolders.Json(Path.Combine(prism, "meta", "net.minecraft", "index.json"), new { versions = Array.Empty<object>() });

        GameFolders.Json(Path.Combine(_p.Player, "curseforge", "minecraft", "Instances", "All the Mods", "minecraftinstance.json"), new
        {
            name = "All the Mods 9",
            gameVersion = "1.20.1",
            baseModLoader = new { name = "forge-47.2.0" },
            lastPlayed = "2026-11-06T12:00:00Z",
            installPath = @"C:\Users\player\curseforge\minecraft\Instances\All the Mods",
        });
        GameFolders.Json(Path.Combine(g.Roaming, "ATLauncher", "instances", "Vanilla", "instance.json"), new
        {
            id = "1.21",
            launcher = new { name = "Vanilla 1.21", lastPlayed = 1762000000000L, loaderVersion = new { type = "Fabric", version = "0.16.0" } },
        });
        Directory.CreateDirectory(Path.Combine(g.Roaming, "ModrinthApp", "profiles", "Fabulously Optimized"));
        Directory.CreateDirectory(Path.Combine(_p.Player, ".lunarclient"));

        var sink = await RunAsync(new MinecraftIntegrityAnalyzer(Options, SystemDirectoryLister.Instance, new TestFileSource()));
        var ev = sink.Evidence;

        var pack = ev.Single(e => e.Attributes.GetValueOrDefault("Instance.Name") == "PvP Pack");
        Assert.Equal("Prism Launcher", pack.Attributes["Launcher"]);
        Assert.Equal("Fabric 0.15.0", pack.Attributes["Instance.Loader"]);
        Assert.Equal(@"-Xmx2G -javaagent:C:\tools\boost.jar", pack.Attributes["Instance.JavaArgs"]);
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1762543800000), pack.Timestamp!.ValueUtc);
        Assert.EndsWith("minecraft", pack.Target.RecordedPath!, StringComparison.Ordinal);
        Assert.Contains(ev, e => e.Attributes.GetValueOrDefault("Jvm.Flag") == "javaagent" && e.Target.RecordedPath == @"C:\tools\boost.jar");
        Assert.Contains(ev, e => e.Attributes.GetValueOrDefault("Version.Id") == "net.minecraft 1.20.1" && e.Attributes.GetValueOrDefault("Version.Client") == "Match");

        var atm = ev.Single(e => e.Attributes.GetValueOrDefault("Instance.Name") == "All the Mods 9");
        Assert.Equal("Forge 47.2.0", atm.Attributes["Instance.Loader"]);
        Assert.Equal("Fabric 0.16.0", ev.Single(e => e.Attributes.GetValueOrDefault("Instance.Name") == "Vanilla 1.21").Attributes["Instance.Loader"]);

        var modrinth = ev.Single(e => e.Attributes.GetValueOrDefault("Launcher") == "Modrinth App");
        Assert.Equal(CollectionStatus.Partial, modrinth.CollectionStatus); // app.db is not read, and it says so
        var lunar = ev.Single(e => e.Attributes.GetValueOrDefault("Launcher") == "Lunar Client");
        Assert.Contains(lunar.Limitations, l => l.Text.Contains("не разбираются", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Other_profiles_need_permission_and_portable_launchers_are_found_in_operator_folders()
    {
        var anna = Path.Combine(_p.Users, "anna");
        GameFolders.Json(Path.Combine(anna, "AppData", "Roaming", ".minecraft", "launcher_profiles.json"), new { profiles = new { x = new { name = "Anna", lastVersionId = "1.20.1" } } });
        var portable = Path.Combine(_p.Root, "Games", "MultiMC");
        GameFolders.Write(Path.Combine(portable, "multimc.cfg"), Encoding.UTF8.GetBytes("JvmArgs=-Xbootclasspath/a:C:\\x\\boot.jar\n"));
        GameFolders.Write(Path.Combine(portable, "instances", "One", "instance.cfg"), Encoding.UTF8.GetBytes("name=One\n"));

        var options = Options with { ExtraRoots = [Path.Combine(_p.Root, "Games")] };
        var denied = await RunAsync(new MinecraftIntegrityAnalyzer(options, SystemDirectoryLister.Instance, new TestFileSource()));
        Assert.DoesNotContain(denied.Evidence, e => e.Attributes.GetValueOrDefault("Instance.Name") == "Anna");
        Assert.Contains(denied.Coverage[0].Limitations, l => l.Code == "MC.OTHER_USERS");
        Assert.Equal(CollectionStatus.Partial, denied.Coverage[0].Status);
        Assert.Contains(denied.Evidence, e => e.Attributes.GetValueOrDefault("Instance.Name") == "One" && e.Attributes["Launcher"] == "MultiMC");
        Assert.Contains(denied.Evidence, e => e.Attributes.GetValueOrDefault("Jvm.Flag") == "bootclasspath" && e.Target.RecordedPath == @"C:\x\boot.jar");

        var allowed = await RunAsync(new MinecraftIntegrityAnalyzer(options, SystemDirectoryLister.Instance, new TestFileSource()), Capability.OtherUserProfiles);
        Assert.Equal("anna", allowed.Evidence.Single(e => e.Attributes.GetValueOrDefault("Instance.Name") == "Anna").Attributes["Instance.User"]);
    }

    [Fact]
    public async Task Hash_budget_is_stated_and_damaged_files_never_throw()
    {
        var g = new GameFolders(_p.Player);
        GameFolders.Vanilla(g.Official, "1.20.1", Client, Client, ("a/b/1/b-1.jar", Authlib, Authlib));
        GameFolders.Write(Path.Combine(g.Official, "launcher_profiles.json"), Encoding.UTF8.GetBytes("{ \"profiles\": { \"x\": [1, 2"));
        GameFolders.Write(Path.Combine(g.Official, "versions", "broken", "broken.json"), Encoding.UTF8.GetBytes("not json"));
        GameFolders.Json(Path.Combine(g.Official, "versions", "evil", "evil.json"), new { libraries = new object[] { new { name = "..:..:..", sha1 = "00" }, new { downloads = new { artifact = new { path = "../../../../Windows/x.dll", sha1 = "00" } } } } });

        var sink = await RunAsync(new MinecraftIntegrityAnalyzer(Options with { HashBudgetBytes = Client.Length }, SystemDirectoryLister.Instance, new TestFileSource()));
        var c = Assert.Single(sink.Coverage);
        Assert.Equal(CollectionStatus.Partial, c.Status);
        Assert.Contains(c.Limitations, l => l.Code == "MC.BUDGET");
        Assert.Contains(sink.Evidence, e => e.Attributes.GetValueOrDefault("Instance.Name") == ".minecraft"); // profiles unreadable, folder known
        var evil = sink.Evidence.Single(e => e.Attributes.GetValueOrDefault("Version.Id") == "evil");
        Assert.Equal("0", evil.Attributes["Version.LibrariesMatched"]);
        Assert.DoesNotContain(sink.Evidence, e => e.Target.RecordedPath?.Contains("Windows", StringComparison.Ordinal) == true);
    }

    [Theory]
    [InlineData("-Xmx2G -javaagent:C:\\a.jar", new[] { "-Xmx2G", "-javaagent:C:\\a.jar" })]
    [InlineData("\"-javaagent:C:\\my dir\\a.jar\"  -noverify", new[] { "-javaagent:C:\\my dir\\a.jar", "-noverify" })]
    [InlineData("", new string[0])]
    public void Jvm_arguments_are_split_like_the_launchers_do(string line, string[] expected) =>
        Assert.Equal(expected, JvmArguments.Split(line));

    [Fact]
    public void Jvm_flags_that_load_code_are_recognised()
    {
        var flags = JvmArguments.Find(["-Xmx4G", "-javaagent:C:\\a.jar=opt", "-agentpath:C:\\b.dll", "-agentlib:jdwp=transport=dt_socket", "-Xbootclasspath/a:C:\\c.jar;C:\\d.jar",
            "-Xverify:none", "-Djava.system.class.loader=x.Y", "-Dfabric.addMods=C:\\e.jar", "-XX:+UseG1GC", "-Dlog4j2.formatMsgNoLookups=true"]);
        Assert.Equal(new[] { "javaagent", "agentpath", "agentlib", "bootclasspath", "noverify", "classloader", "extramods" }, flags.Select(f => f.Kind));
        Assert.Equal(new[] { "C:\\a.jar", "C:\\b.dll", null, "C:\\c.jar", null, null, "C:\\e.jar" }, flags.Select(f => f.Path));
        Assert.Contains("отладчик", flags[2].Meaning, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("net.fabricmc:fabric-loader:0.15.0", "net/fabricmc/fabric-loader/0.15.0/fabric-loader-0.15.0.jar")]
    [InlineData("org.lwjgl:lwjgl:3.3.1:natives-windows", "org/lwjgl/lwjgl/3.3.1/lwjgl-3.3.1-natives-windows.jar")]
    [InlineData("a:b", null)]
    [InlineData("..:b:1", null)]
    [InlineData("a:b/c:1", null)]
    public void Maven_names_become_library_paths(string name, string? expected) => Assert.Equal(expected, VersionIntegrity.MavenPath(name));
}
