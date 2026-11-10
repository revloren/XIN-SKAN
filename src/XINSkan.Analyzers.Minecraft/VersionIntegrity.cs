using System.Security.Cryptography;
using System.Text.Json;

namespace XINSkan.Analyzers.Minecraft;

public enum HashStatus
{
    /// <summary>The file's SHA-1 equals the one in the version file.</summary>
    Match,

    /// <summary>The file differs from what the version file promises.</summary>
    Mismatch,

    /// <summary>The file is not there (natives of another OS, not downloaded yet, removed).</summary>
    Missing,

    /// <summary>The version file gives no hash for it.</summary>
    NoHash,

    /// <summary>Too large, or the read budget of the module is spent.</summary>
    NotRead,
}

/// <summary>The client JAR Mojang publishes for a version id (database/mojang.json, from Mojang's own version files).</summary>
public sealed record OfficialClient(string Sha1, long Size, string Source);

/// <summary>A file the version file names, and what reading it showed.</summary>
/// <param name="OfficialSha1">For a client JAR of an official version id: the SHA-1 Mojang publishes for it.</param>
public sealed record CheckedFile(string Path, string? ExpectedSha1, long? ExpectedSize, string? ActualSha1, long? ActualSize, HashStatus Status, string? Url, string? OfficialSha1 = null)
{
    /// <summary>Whether the file on disk is Mojang's official client; null when there is nothing to compare.</summary>
    public bool? IsOfficial => ActualSha1 is null || OfficialSha1 is null ? null : string.Equals(ActualSha1, OfficialSha1, StringComparison.OrdinalIgnoreCase);

    /// <summary>Whether the version file's own client hash is Mojang's; null when either is missing.</summary>
    public bool? DeclaresOfficial => ExpectedSha1 is null || OfficialSha1 is null ? null : string.Equals(ExpectedSha1, OfficialSha1, StringComparison.OrdinalIgnoreCase);
}

/// <summary>What one installed version is made of and whether its files are what its version file says.</summary>
public sealed record VersionReport
{
    public required string Id { get; init; }

    public required string JsonPath { get; init; }

    public string? InheritsFrom { get; init; }

    public string? MainClass { get; init; }

    public bool MainClassKnown { get; init; }

    public CheckedFile? Client { get; init; }

    /// <summary>The client download URL is Mojang's (the version file has the official shape).</summary>
    public bool ClientFromMojang { get; init; }

    public IReadOnlyList<CheckedFile> Libraries { get; init; } = [];

    public IReadOnlyList<JvmFlag> JvmFlags { get; init; } = [];

    public IReadOnlyList<string> Problems { get; init; } = [];
}

/// <summary>
/// Checks installed versions against their own version files: the client JAR against downloads.client.sha1,
/// libraries against downloads.artifact.sha1 (or the Fabric-style sha1 field), and reads the main class and the
/// JVM arguments the version file adds. Hashes are SHA-1 because that is what Mojang and the loaders publish.
/// </summary>
internal sealed class VersionIntegrity(Reader reader, long budgetBytes, IReadOnlyDictionary<string, OfficialClient>? official = null)
{
    public const long MaxFileBytes = 512L * 1024 * 1024;

    private static readonly HashSet<string> KnownMainClasses = new(StringComparer.Ordinal)
    {
        "net.minecraft.client.main.Main",
        "net.minecraft.launchwrapper.Launch",
        "net.minecraft.client.Minecraft",
        "net.fabricmc.loader.impl.launch.knot.KnotClient",
        "net.fabricmc.loader.launch.knot.KnotClient",
        "org.quiltmc.loader.impl.launch.knot.KnotClient",
        "cpw.mods.bootstraplauncher.BootstrapLauncher",
        "cpw.mods.modlauncher.Launcher",
        "net.minecraftforge.bootstrap.ForgeBootstrap",
        "net.neoforged.fml.startup.Client",
        "io.github.zekerzhayard.forgewrapper.installer.Main",
    };

    private long _spent;

    public long BytesRead => _spent;

    public bool BudgetExhausted { get; private set; }

    public IReadOnlyList<VersionReport> CheckAll(string gameRoot)
    {
        var versions = InstanceFinder.Combine(gameRoot, "versions");
        var libraries = InstanceFinder.Combine(gameRoot, "libraries");
        var reports = new List<VersionReport>();
        foreach (var dir in reader.List(versions).Where(e => e.IsDirectory && !e.IsReparsePoint).OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
        {
            var json = InstanceFinder.Combine(dir.FullPath, dir.Name + ".json");
            if (Check(versions, libraries, dir.Name, json) is { } r)
            {
                reports.Add(r);
            }
        }

        return reports;
    }

    internal VersionReport? Check(string versions, string libraries, string id, string jsonPath)
    {
        using var doc = Json.Parse(reader.Bytes(jsonPath));
        if (doc is null)
        {
            return null;
        }

        var e = doc.RootElement;
        var problems = new List<string>();
        var inherits = e.Str("inheritsFrom");

        // The client JAR is checked where the version file that defines downloads.client lives (the vanilla
        // version a loader inherits from checks its own JAR in its own pass).
        CheckedFile? client = null;
        var fromMojang = false;
        if (e.Get("downloads", "client") is { ValueKind: JsonValueKind.Object } c)
        {
            var url = c.Str("url");
            fromMojang = url is not null && (url.StartsWith("https://piston-data.mojang.com/", StringComparison.OrdinalIgnoreCase)
                                             || url.StartsWith("https://launcher.mojang.com/", StringComparison.OrdinalIgnoreCase));
            var jarName = e.Str("jar") ?? id;
            client = Hash(InstanceFinder.Combine(versions, jarName, jarName + ".jar"), c.Str("sha1"), c.Num("size"), url, Official(id));
        }

        else if (e.Get("mainJar") is { ValueKind: JsonValueKind.Object } main && main.Str("name") is { } mainName && MavenPath(mainName) is { } mainPath)
        {
            // Prism/MultiMC meta: the client is a library ("com.mojang:minecraft:1.20.1:client").
            var url = main.Str("downloads", "artifact", "url");
            fromMojang = url is not null && (url.StartsWith("https://piston-data.mojang.com/", StringComparison.OrdinalIgnoreCase)
                                             || url.StartsWith("https://launcher.mojang.com/", StringComparison.OrdinalIgnoreCase));
            client = Hash(Library(libraries, mainPath), main.Str("downloads", "artifact", "sha1"), main.Num("downloads", "artifact", "size"), url, Official(mainName.Split(':')[2]));
        }

        else if (Official(id) is { } own && e.Str("inheritsFrom") is null)
        {
            // An official version id whose version file gives no client download (some third-party launchers):
            // the JAR next to it is still compared with what Mojang publishes for that id.
            var jarName = e.Str("jar") ?? id;
            var candidate = Hash(InstanceFinder.Combine(versions, jarName, jarName + ".jar"), null, null, null, own);
            client = candidate.Status == HashStatus.Missing ? null : candidate;
        }

        var libs = new List<CheckedFile>();
        foreach (var lib in e.Items("libraries"))
        {
            if (lib.Get("downloads", "artifact") is { ValueKind: JsonValueKind.Object } a && a.Str("path") is { Length: > 0 } path)
            {
                libs.Add(Hash(Library(libraries, path), a.Str("sha1"), a.Num("size"), a.Str("url")));
            }
            else if (lib.Str("name") is { } name && MavenPath(name) is { } maven)
            {
                // Fabric/Quilt style: name + url, hashes as top-level fields when present.
                libs.Add(Hash(Library(libraries, maven), lib.Str("sha1"), lib.Num("size"), lib.Str("url")));
            }
        }

        var jvm = e.Items("arguments", "jvm").Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList();
        var mainClass = e.Str("mainClass");
        if (BudgetExhausted)
        {
            problems.Add("Бюджет чтения исчерпан: часть файлов не прочитана.");
        }

        return new VersionReport
        {
            Id = id,
            JsonPath = jsonPath,
            InheritsFrom = inherits,
            MainClass = mainClass,
            MainClassKnown = mainClass is null || KnownMainClasses.Contains(mainClass),
            Client = client,
            ClientFromMojang = fromMojang,
            Libraries = libs,
            JvmFlags = JvmArguments.Find(jvm),
            Problems = problems,
        };
    }

    /// <summary>"group:artifact:version[:classifier]" → group/as/path/artifact/version/artifact-version[-classifier].jar.</summary>
    internal static string? MavenPath(string name)
    {
        var p = name.Split(':');
        if (p.Length is < 3 or > 4 || p.Any(x => x.Length == 0 || x.Contains("..", StringComparison.Ordinal) || x.Contains('/') || x.Contains('\\')))
        {
            return null;
        }

        var file = $"{p[1]}-{p[2]}{(p.Length == 4 ? "-" + p[3] : string.Empty)}.jar";
        return $"{p[0].Replace('.', '/')}/{p[1]}/{p[2]}/{file}";
    }

    private static string Library(string root, string relative) =>
        InstanceFinder.Combine(root, [.. relative.Split('/', '\\').Where(s => s.Length > 0 && s != "..")]);

    private string? Official(string id) => official?.GetValueOrDefault(id)?.Sha1.ToLowerInvariant();

#pragma warning disable CA5350 // SHA-1 is what the version files publish; it identifies files, it does not protect anything.
    private CheckedFile Hash(string path, string? sha1, long? size, string? url, string? officialSha1 = null)
    {
        if (BudgetExhausted)
        {
            return new CheckedFile(path, sha1, size, null, null, HashStatus.NotRead, url, officialSha1);
        }

        using var f = reader.Open(path);
        if (f is null)
        {
            return new CheckedFile(path, sha1, size, null, null, HashStatus.Missing, url, officialSha1);
        }

        var length = f.Content.Length;
        if (sha1 is null && officialSha1 is null)
        {
            return new CheckedFile(path, null, size, null, length, HashStatus.NoHash, url);
        }

        if (length > MaxFileBytes || _spent + length > budgetBytes)
        {
            BudgetExhausted |= _spent + length > budgetBytes;
            return new CheckedFile(path, sha1, size, null, length, HashStatus.NotRead, url, officialSha1);
        }

        _spent += length;
        var actual = Convert.ToHexStringLower(SHA1.HashData(f.Content));
        var status = sha1 is null ? HashStatus.NoHash : string.Equals(actual, sha1, StringComparison.OrdinalIgnoreCase) ? HashStatus.Match : HashStatus.Mismatch;
        return new CheckedFile(path, sha1?.ToLowerInvariant(), size, actual, length, status, url, officialSha1);
    }
#pragma warning restore CA5350
}
