using System.Globalization;
using System.Text;
using System.Text.Json;
using XINSkan.Core.IO;

namespace XINSkan.Analyzers.Minecraft;

/// <summary>One game installation or launcher instance, as its launcher describes it.</summary>
public sealed record MinecraftInstance
{
    public required string Launcher { get; init; }

    public required string Name { get; init; }

    /// <summary>The file the description was read from.</summary>
    public required string Source { get; init; }

    /// <summary>The game folder (saves, mods, logs).</summary>
    public string? GameDir { get; init; }

    public string? Version { get; init; }

    public string? Loader { get; init; }

    public string? LoaderVersion { get; init; }

    public string? JavaArgs { get; init; }

    public string? JavaPath { get; init; }

    public DateTimeOffset? LastUsed { get; init; }

    public IReadOnlyList<string> Problems { get; init; } = [];
}

/// <summary>A launcher found in a profile, and where its data lives.</summary>
public sealed record LauncherHome(string Launcher, string Folder);

/// <summary>Bounded reading through the investigation's file source (audited, read-only, full sharing).</summary>
internal sealed class Reader(IDirectoryLister lister, IFileSource files)
{
    public bool Exists(string dir)
    {
        try
        {
            return lister.DirectoryExists(dir);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public IReadOnlyList<FsEntry> List(string dir)
    {
        try
        {
            return lister.DirectoryExists(dir) ? lister.List(dir) : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    public byte[]? Bytes(string path, int max = Json.MaxBytes)
    {
        try
        {
            using var f = files.Open(path);
            if (f.Content.Length > max)
            {
                return null;
            }

            var b = new byte[f.Content.Length];
            var n = f.Content.ReadAtLeast(b, b.Length, throwOnEndOfStream: false);
            return n == b.Length ? b : b[..n];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public IOpenedFile? Open(string path)
    {
        try
        {
            return files.Open(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}

/// <summary>
/// Finds launchers in a user profile and reads their instance descriptions. Formats: the official launcher
/// (launcher_profiles.json), Prism/PolyMC/MultiMC (instance.cfg, mmc-pack.json), CurseForge
/// (minecraftinstance.json), ATLauncher (instance.json), Modrinth App (profile.json of older versions).
/// Launchers whose settings are not read (Lunar, Badlion, Feather, TLauncher's own file) are recorded as present.
/// </summary>
internal static class InstanceFinder
{
    private static readonly string[] GameFolders = [".minecraft", "minecraft"];

    public static IReadOnlyList<LauncherHome> Homes(Reader r, string profile)
    {
        var roaming = Combine(profile, "AppData", "Roaming");
        var candidates = new (string Launcher, string Folder)[]
        {
            ("Официальный лаунчер", Combine(roaming, ".minecraft")),
            ("Prism Launcher", Combine(roaming, "PrismLauncher")),
            ("PolyMC", Combine(roaming, "PolyMC")),
            ("MultiMC", Combine(roaming, "MultiMC")),
            ("CurseForge", Combine(profile, "curseforge", "minecraft")),
            ("ATLauncher", Combine(roaming, "ATLauncher")),
            ("Modrinth App", Combine(roaming, "ModrinthApp")),
            ("Modrinth App", Combine(roaming, "com.modrinth.theseus")),
            ("TLauncher", Combine(roaming, ".tlauncher")),
            ("Lunar Client", Combine(profile, ".lunarclient")),
            ("Badlion Client", Combine(roaming, "Badlion Client")),
            ("Feather Client", Combine(roaming, ".feather")),
        };
        return candidates.Where(c => r.Exists(c.Folder)).Select(c => new LauncherHome(c.Launcher, c.Folder)).ToList();
    }

    public static IReadOnlyList<MinecraftInstance> Read(Reader r, LauncherHome home) => home.Launcher switch
    {
        "Официальный лаунчер" => Official(r, home.Folder),
        "Prism Launcher" or "PolyMC" or "MultiMC" => Prism(r, home),
        "CurseForge" => CurseForge(r, home.Folder),
        "ATLauncher" => AtLauncher(r, home.Folder),
        "Modrinth App" => Modrinth(r, home.Folder),
        _ => [new MinecraftInstance { Launcher = home.Launcher, Name = home.Launcher, Source = home.Folder, GameDir = home.Folder, Problems = ["Настройки этого лаунчера не разбираются: записано только то, что он установлен."] }],
    };

    /// <summary>launcher_profiles.json: every profile with its version, game folder, Java arguments and last use.</summary>
    internal static List<MinecraftInstance> Official(Reader r, string root)
    {
        var list = new List<MinecraftInstance>();
        foreach (var name in new[] { "launcher_profiles.json", "launcher_profiles_microsoft_store.json" })
        {
            var path = Combine(root, name);
            using var doc = Json.Parse(r.Bytes(path));
            if (doc is null)
            {
                continue;
            }

            foreach (var p in doc.RootElement.Props("profiles"))
            {
                var v = p.Value;
                var type = v.Str("type");
                list.Add(new MinecraftInstance
                {
                    Launcher = "Официальный лаунчер",
                    Name = v.Str("name") is { Length: > 0 } n ? n : type switch { "latest-release" => "Последний выпуск", "latest-snapshot" => "Последний снапшот", _ => p.Name },
                    Source = path,
                    GameDir = v.Str("gameDir") ?? root,
                    Version = v.Str("lastVersionId") ?? type,
                    JavaArgs = v.Str("javaArgs"),
                    JavaPath = v.Str("javaDir"),
                    LastUsed = Time(v.Str("lastUsed")),
                });
            }
        }

        if (list.Count == 0 && r.Exists(Combine(root, "versions")))
        {
            list.Add(new MinecraftInstance { Launcher = "Официальный лаунчер", Name = ".minecraft", Source = root, GameDir = root, Problems = ["launcher_profiles.json нет или он не разобран: папка игры есть, профили неизвестны."] });
        }

        return list;
    }

    /// <summary>Prism/PolyMC/MultiMC: instances\*\instance.cfg (INI) and mmc-pack.json; global JVM arguments apply to all.</summary>
    internal static List<MinecraftInstance> Prism(Reader r, LauncherHome home)
    {
        var global = Ini(r.Bytes(Combine(home.Folder, home.Launcher switch { "PolyMC" => "polymc.cfg", "MultiMC" => "multimc.cfg", _ => "prismlauncher.cfg" })));
        var list = new List<MinecraftInstance>();
        foreach (var dir in r.List(Combine(home.Folder, "instances")).Where(e => e.IsDirectory && !e.IsReparsePoint && !e.Name.StartsWith('.') && !e.Name.StartsWith('_')))
        {
            var cfgPath = Combine(dir.FullPath, "instance.cfg");
            var cfg = Ini(r.Bytes(cfgPath));
            if (cfg.Count == 0)
            {
                continue;
            }

            using var pack = Json.Parse(r.Bytes(Combine(dir.FullPath, "mmc-pack.json")));
            string? version = null, loader = null, loaderVersion = null;
            foreach (var c in pack?.RootElement.Items("components") ?? [])
            {
                var uid = c.Str("uid");
                var ver = c.Str("version") ?? c.Str("cachedVersion");
                switch (uid)
                {
                    case "net.minecraft":
                        version = ver;
                        break;
                    case "net.fabricmc.fabric-loader":
                        (loader, loaderVersion) = ("Fabric", ver);
                        break;
                    case "org.quiltmc.quilt-loader":
                        (loader, loaderVersion) = ("Quilt", ver);
                        break;
                    case "net.minecraftforge":
                        (loader, loaderVersion) = ("Forge", ver);
                        break;
                    case "net.neoforged":
                        (loader, loaderVersion) = ("NeoForge", ver);
                        break;
                }
            }

            var overrideArgs = cfg.GetValueOrDefault("OverrideJavaArgs") == "true";
            var args = string.Join(' ', new[] { global.GetValueOrDefault("JvmArgs"), overrideArgs ? cfg.GetValueOrDefault("JvmArgs") : null }.Where(a => !string.IsNullOrWhiteSpace(a)));
            var gameDir = GameFolders.Select(d => Combine(dir.FullPath, d)).FirstOrDefault(r.Exists) ?? Combine(dir.FullPath, ".minecraft");
            list.Add(new MinecraftInstance
            {
                Launcher = home.Launcher,
                Name = cfg.GetValueOrDefault("name") ?? dir.Name,
                Source = cfgPath,
                GameDir = gameDir,
                Version = version,
                Loader = loader,
                LoaderVersion = loaderVersion,
                JavaArgs = args.Length == 0 ? null : args,
                JavaPath = cfg.GetValueOrDefault("OverrideJavaLocation") == "true" ? cfg.GetValueOrDefault("JavaPath") : global.GetValueOrDefault("JavaPath"),
                LastUsed = long.TryParse(cfg.GetValueOrDefault("lastLaunchTime"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var ms) && ms > 0
                    ? DateTimeOffset.FromUnixTimeMilliseconds(ms)
                    : null,
            });
        }

        return list;
    }

    /// <summary>CurseForge: Instances\*\minecraftinstance.json.</summary>
    internal static List<MinecraftInstance> CurseForge(Reader r, string root)
    {
        var list = new List<MinecraftInstance>();
        foreach (var dir in r.List(Combine(root, "Instances")).Where(e => e.IsDirectory && !e.IsReparsePoint))
        {
            var path = Combine(dir.FullPath, "minecraftinstance.json");
            using var doc = Json.Parse(r.Bytes(path));
            if (doc is null)
            {
                continue;
            }

            var e = doc.RootElement;
            var loader = e.Str("baseModLoader", "name"); // "forge-47.2.0", "fabric-0.15.0-1.20.1"
            var dash = loader?.IndexOf('-', StringComparison.Ordinal) ?? -1;
            list.Add(new MinecraftInstance
            {
                Launcher = "CurseForge",
                Name = e.Str("name") ?? dir.Name,
                Source = path,
                GameDir = e.Str("installPath") ?? dir.FullPath,
                Version = e.Str("gameVersion"),
                Loader = dash > 0 ? Capitalize(loader![..dash]) : loader,
                LoaderVersion = dash > 0 ? loader![(dash + 1)..] : null,
                JavaArgs = e.Str("javaArgsOverride"),
                LastUsed = Time(e.Str("lastPlayed")),
            });
        }

        return list;
    }

    /// <summary>ATLauncher: instances\*\instance.json.</summary>
    internal static List<MinecraftInstance> AtLauncher(Reader r, string root)
    {
        var list = new List<MinecraftInstance>();
        foreach (var dir in r.List(Combine(root, "instances")).Where(e => e.IsDirectory && !e.IsReparsePoint))
        {
            var path = Combine(dir.FullPath, "instance.json");
            using var doc = Json.Parse(r.Bytes(path));
            if (doc is null)
            {
                continue;
            }

            var e = doc.RootElement;
            list.Add(new MinecraftInstance
            {
                Launcher = "ATLauncher",
                Name = e.Str("launcher", "name") ?? dir.Name,
                Source = path,
                GameDir = dir.FullPath,
                Version = e.Str("id"),
                Loader = e.Str("launcher", "loaderVersion", "type"),
                LoaderVersion = e.Str("launcher", "loaderVersion", "version"),
                JavaArgs = e.Str("launcher", "javaArguments"),
                LastUsed = e.Num("launcher", "lastPlayed") is { } ms && ms > 0 ? DateTimeOffset.FromUnixTimeMilliseconds(ms) : null,
            });
        }

        return list;
    }

    /// <summary>Modrinth App: profiles\*\profile.json (versions before the move to app.db).</summary>
    internal static List<MinecraftInstance> Modrinth(Reader r, string root)
    {
        var list = new List<MinecraftInstance>();
        foreach (var dir in r.List(Combine(root, "profiles")).Where(e => e.IsDirectory && !e.IsReparsePoint))
        {
            var path = Combine(dir.FullPath, "profile.json");
            using var doc = Json.Parse(r.Bytes(path));
            var e = doc?.RootElement;
            list.Add(new MinecraftInstance
            {
                Launcher = "Modrinth App",
                Name = e?.Str("metadata", "name") ?? dir.Name,
                Source = doc is null ? dir.FullPath : path,
                GameDir = dir.FullPath,
                Version = e?.Str("metadata", "game_version"),
                Loader = e?.Str("metadata", "loader"),
                LoaderVersion = e?.Str("metadata", "loader_version", "id"),
                JavaArgs = e is { } x ? string.Join(' ', x.Items("java", "extra_arguments").Where(a => a.ValueKind == JsonValueKind.String).Select(a => a.GetString())) is { Length: > 0 } s ? s : null : null,
                Problems = doc is null ? ["profile.json нет: новые версии Modrinth App хранят настройки в базе app.db, она не разбирается."] : [],
            });
        }

        return list;
    }

    internal static Dictionary<string, string> Ini(byte[]? bytes)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (bytes is null)
        {
            return map;
        }

        foreach (var raw in Encoding.UTF8.GetString(bytes).Split('\n'))
        {
            var line = raw.Trim();
            var eq = line.IndexOf('=', StringComparison.Ordinal);
            if (eq > 0 && !line.StartsWith('[') && !line.StartsWith('#'))
            {
                map.TryAdd(line[..eq].Trim(), line[(eq + 1)..].Trim());
            }
        }

        return map;
    }

    private static DateTimeOffset? Time(string? s) =>
        DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t) && t.Year > 2000 ? t : null;

    private static string Capitalize(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];

    /// <summary>Windows paths with backslashes on any platform (tests run on Linux).</summary>
    internal static string Combine(string root, params string[] parts) =>
        root.Contains('\\', StringComparison.Ordinal) || (root.Length >= 2 && root[1] == ':')
            ? string.Join('\\', [root.TrimEnd('\\'), .. parts])
            : Path.Combine([root, .. parts]);
}
