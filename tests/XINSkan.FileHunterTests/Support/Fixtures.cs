using System.IO.Compression;
using System.Text;
using XINSkan.Core.IO;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.Models;

namespace XINSkan.FileHunterTests.Support;

/// <summary>Builds harmless JAR files with chosen descriptors and class names. Classes are 4-byte stubs.</summary>
internal static class Jar
{
    public static byte[] Build(Action<ZipArchive> fill)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            fill(zip);
        }

        return ms.ToArray();
    }

    public static void Text(this ZipArchive zip, string name, string content)
    {
        using var w = new StreamWriter(zip.CreateEntry(name).Open(), new UTF8Encoding(false));
        w.Write(content);
    }

    public static void Bytes(this ZipArchive zip, string name, byte[] content)
    {
        using var s = zip.CreateEntry(name).Open();
        s.Write(content);
    }

    public static void Class(this ZipArchive zip, string path) => zip.Bytes(path, [0xCA, 0xFE, 0xBA, 0xBE]);

    public static byte[] FabricMod(string id, string name, string version, params string[] classes) => Build(z =>
    {
        z.Text("fabric.mod.json", $$"""
            {
              // comments and trailing commas occur in real descriptors
              "schemaVersion": 1,
              "id": "{{id}}",
              "name": "{{name}}",
              "version": "{{version}}",
            }
            """);
        foreach (var c in classes)
        {
            z.Class(c);
        }
    });

    public static byte[] ForgeMod(string modId, string name, string version) => Build(z =>
    {
        z.Text("META-INF/mods.toml", $"""
            modLoader="javafml"
            loaderVersion="[47,)"
            license="MIT"

            [[mods]]
            modId="{modId}" # trailing comment
            version="{version}"
            displayName="{name}"

            [[dependencies.{modId}]]
            modId="forge"
            """);
        z.Class("com/example/forgemod/Main.class");
    });

    public static byte[] Agent() => Build(z =>
    {
        z.Text("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nPremain-Class: org.example.agent.Ag\r\n ent\r\nAgent-Class: org.example.agent.Agent\r\nCan-Retransform-Classes: true\r\n\r\nName: org/example/\r\nSealed: true\r\n");
        z.Class("org/example/agent/Agent.class");
    });
}

/// <summary>
/// A player profile with Minecraft data, downloads and noise, built in a temporary folder.
/// Paths that should and should not become evidence are listed explicitly.
/// </summary>
internal sealed class PlayerProfile : IDisposable
{
    public PlayerProfile(bool withOtherProfile = true, string? baseDirectory = null)
    {
        Root = Path.Combine(baseDirectory ?? Path.GetTempPath(), "xinskan-fh-" + Guid.NewGuid().ToString("N"));
        Users = Path.Combine(Root, "Users");
        Player = Path.Combine(Users, "player");
        WindowsTemp = Path.Combine(Root, "Windows", "Temp");

        var mc = Path.Combine(Player, "AppData", "Roaming", ".minecraft");
        Write(mc, "options.txt", "lang:ru_ru");
        Write(mc, "mods/test-client.jar", Jar.FabricMod("testclient", "Test Client", "1.0.0", "net/example/testclient/modules/Fly.class", "net/example/testclient/modules/Speed.class", "net/example/testclient/Main.class"));
        Write(mc, "mods/forge-mod.jar", Jar.ForgeMod("examplemod", "Example Mod", "2.3"));
        Write(mc, "mods/agent.jar", Jar.Agent());
        Write(mc, "mods/broken.jar", Jar.FabricMod("broken", "Broken", "0")[..60]);
        Write(mc, "config/testclient/settings.json", """{ "module": "value" }""");
        Write(mc, "versions/1.20.1/1.20.1.json", "{}");
        Write(mc, "logs/latest.log", "[main/INFO]: Loading 3 mods");

        Write(Player, "Downloads/renamed.txt", Jar.FabricMod("hidden", "Hidden", "1"));
        Write(Player, "Downloads/photo.png", RandomBytes(4096));
        Write(Player, "Downloads/tool.exe", File.ReadAllBytes(typeof(object).Assembly.Location));
        Write(Player, "Documents/notes.txt", "just notes");
        Write(Player, "Pictures/big.png", RandomBytes(2048));
        Write(Player, "Games/CustomClient/client.jar", Jar.FabricMod("custom", "Custom", "9"));
        Write(Player, "Games/CustomClient/readme.txt", "readme");
        Write(Player, "AppData/Local/Packages/app/cache.dat", RandomBytes(512));
        Write(Player, "AppData/Local/Temp/payload.tmp", File.ReadAllBytes(typeof(object).Assembly.Location));

        Write(Users, "Public/Desktop/shared.jar", Jar.FabricMod("public", "Public", "1"));
        if (withOtherProfile)
        {
            Write(Users, "other/Downloads/other.jar", Jar.FabricMod("other", "Other", "1"));
        }

        Write(WindowsTemp, "dropped.bin", File.ReadAllBytes(typeof(object).Assembly.Location));
        Write(WindowsTemp, "install.log", "log");

        // A link back to the profile: must not be followed (it would loop).
        Directory.CreateSymbolicLink(Path.Combine(Player, "Games", "loop"), Player);
    }

    public string Root { get; }

    public string Users { get; }

    public string Player { get; }

    public string WindowsTemp { get; }

    public string MinecraftDir => Path.Combine(Player, "AppData", "Roaming", ".minecraft");

    public string P(params string[] parts) => Path.Combine([Player, .. parts]);

    /// <summary>Files that must become evidence (other profile excluded).</summary>
    public IReadOnlyList<string> ExpectedFiles =>
    [
        Path.Combine(MinecraftDir, "options.txt"),
        Path.Combine(MinecraftDir, "mods", "test-client.jar"),
        Path.Combine(MinecraftDir, "mods", "forge-mod.jar"),
        Path.Combine(MinecraftDir, "mods", "agent.jar"),
        Path.Combine(MinecraftDir, "mods", "broken.jar"),
        Path.Combine(MinecraftDir, "config", "testclient", "settings.json"),
        Path.Combine(MinecraftDir, "versions", "1.20.1", "1.20.1.json"),
        Path.Combine(MinecraftDir, "logs", "latest.log"),
        P("Downloads", "renamed.txt"),
        P("Downloads", "tool.exe"),
        P("Games", "CustomClient", "client.jar"),
        P("AppData", "Local", "Temp", "payload.tmp"),
        Path.Combine(WindowsTemp, "dropped.bin"),
    ];

    public IReadOnlyList<string> ExpectedDirectories =>
    [
        MinecraftDir,
        Path.Combine(MinecraftDir, "mods"),
        Path.Combine(MinecraftDir, "config"),
        Path.Combine(MinecraftDir, "config", "testclient"),
        Path.Combine(MinecraftDir, "versions"),
        Path.Combine(MinecraftDir, "versions", "1.20.1"),
        Path.Combine(MinecraftDir, "logs"),
    ];

    public void Dispose()
    {
        if (Directory.Exists(Root))
        {
            // Remove the link itself first; a recursive delete must never walk through it into the profile.
            var loop = Path.Combine(Player, "Games", "loop");
            if (new DirectoryInfo(loop).LinkTarget is not null)
            {
                Directory.Delete(loop);
            }

            Directory.Delete(Root, recursive: true);
        }
    }

    public static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        new Random(n).NextBytes(b);
        b[0] = 0x89; // never starts like an archive or executable
        return b;
    }

    private static void Write(string baseDir, string relative, string text) => Write(baseDir, relative, Encoding.UTF8.GetBytes(text));

    private static void Write(string baseDir, string relative, byte[] bytes)
    {
        var path = Path.Combine([baseDir, .. relative.Split('/')]);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
    }
}

/// <summary>Reads files with read sharing and in-memory alternate streams (portable stand-in for WindowsFileSource).</summary>
internal sealed class TestFileSource : IFileSource
{
    public Dictionary<(string Path, string Stream), byte[]> Streams { get; } = [];

    public Func<string, Exception?>? Fail { get; set; }

    public int OpenCount;

    public IOpenedFile Open(string path)
    {
        if (Fail?.Invoke(path) is { } ex)
        {
            throw ex;
        }

        Interlocked.Increment(ref OpenCount);
        return new OpenedFile(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete));
    }

    public IOpenedFile? TryOpenStream(string path, string streamName) =>
        Streams.TryGetValue((path, streamName), out var b) ? new OpenedFile(new MemoryStream(b, writable: false)) : null;

    private sealed class OpenedFile(Stream s) : IOpenedFile
    {
        public Stream Content => s;

        public FileIdentity? Identity => null;

        public void Dispose() => s.Dispose();
    }
}

/// <summary>Directory lister that can be told to fail for chosen folders.</summary>
internal sealed class FaultyLister(Func<string, Exception?> fail) : IDirectoryLister
{
    public IReadOnlyList<FsEntry> List(string directory) =>
        fail(directory) is { } ex ? throw ex : SystemDirectoryLister.Instance.List(directory);

    public bool DirectoryExists(string path) => SystemDirectoryLister.Instance.DirectoryExists(path);
}

internal sealed class FixedProbe(params Capability[] available) : ICapabilityProbe
{
    public CapabilityState Probe(Capability capability) =>
        new(capability, available.Contains(capability), available.Contains(capability) ? "yes" : "no");
}

internal sealed class MemorySink : IInvestigationSink
{
    private readonly Lock _gate = new();

    public List<Evidence> Evidence { get; } = [];

    public List<SourceCoverage> Coverage { get; } = [];

    public List<ModuleError> Errors { get; } = [];

    public List<ModuleResult> Results { get; } = [];

    public ValueTask AddEvidenceAsync(Evidence evidence, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            Evidence.Add(evidence);
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask AddCoverageAsync(SourceCoverage coverage, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            Coverage.Add(coverage);
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask AddErrorAsync(string moduleId, ModuleError moduleError, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            Errors.Add(moduleError);
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask CheckpointAsync(ModuleResult result, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            Results.Add(result);
        }

        return ValueTask.CompletedTask;
    }
}
