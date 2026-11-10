using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using XINSkan.Core.Paths;

namespace XINSkan.Analyzers.FileHunter.Content;

/// <summary>Mod descriptor found inside a JAR.</summary>
public sealed record ModMetadata(string Loader, string? Id, string? Name, string? Version, string Descriptor);

/// <summary>Facts read from an archive. Classes are never loaded or executed; only names and small text files are read.</summary>
public sealed record ArchiveFacts
{
    public long DeclaredEntries { get; init; }

    public int ClassCount { get; init; }

    public bool IsJavaArchive => ClassCount > 0 || Manifest is not null || Mods.Count > 0;

    /// <summary>Most frequent class package prefixes (three segments), for example "net.example.client".</summary>
    public IReadOnlyList<string> TopPackages { get; init; } = [];

    public IReadOnlyList<ModMetadata> Mods { get; init; } = [];

    public IReadOnlyDictionary<string, string>? Manifest { get; init; }

    /// <summary>Paths of embedded JARs (Fabric META-INF/jars, Forge/NeoForge META-INF/jarjar).</summary>
    public IReadOnlyList<string> NestedJars { get; init; } = [];

    /// <summary>Mods declared by the embedded JARs that were inspected.</summary>
    public IReadOnlyList<ModMetadata> NestedMods { get; init; } = [];

    /// <summary>
    /// Classes whose name is in the feature catalog (<see cref="ArchiveLimits.FeatureVocabulary"/>), as entry paths
    /// without ".class"; at most <see cref="ArchiveLimits.MaxFeatureClasses"/>. Names only — classes are never read.
    /// </summary>
    public IReadOnlyList<string> FeatureClasses { get; init; } = [];

    /// <summary>The descriptor of a server plugin (plugin.yml, paper-plugin.yml, bungee.yml, velocity-plugin.json), if any.</summary>
    public string? ServerPlugin { get; init; }

    /// <summary>What could not be read and why; empty when the archive was read completely within limits.</summary>
    public IReadOnlyList<string> Problems { get; init; } = [];
}

public sealed record ArchiveLimits
{
    public long MaxEntries { get; init; } = 200_000;

    public long MaxDescriptorBytes { get; init; } = 1024 * 1024;

    public long MaxNestedJarBytes { get; init; } = 32L * 1024 * 1024;

    public int MaxNestedJars { get; init; } = 32;

    /// <summary>Keys of feature names (<see cref="ClassNames.FeatureKey"/>); null — class names are not collected.</summary>
    public IReadOnlySet<string>? FeatureVocabulary { get; init; }

    public int MaxFeatureClasses { get; init; } = 150;
}

/// <summary>
/// Reads JAR/ZIP structure safely: the entry count is checked in the end-of-central-directory record before the
/// archive is opened (an archive with millions of entries is not loaded), descriptors are read only up to a size
/// cap, and embedded JARs are inspected one level deep with their own size cap.
/// </summary>
public static class ArchiveInspector
{
    /// <summary>Manifest attributes that matter for Minecraft clients and Java agents.</summary>
    private static readonly string[] ManifestKeys =
    [
        "Main-Class", "Premain-Class", "Agent-Class", "Launcher-Agent-Class", "Implementation-Title",
        "Implementation-Version", "Implementation-Vendor", "Specification-Title", "Automatic-Module-Name",
        "MixinConfigs", "FMLCorePlugin", "FMLCorePluginContainsFMLMod", "TweakClass", "Can-Redefine-Classes",
        "Can-Retransform-Classes",
    ];

    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
        MaxDepth = 64,
    };

    public static ArchiveFacts Inspect(Stream archive, ArchiveLimits limits) => Inspect(archive, limits, nested: false);

    private static ArchiveFacts Inspect(Stream archive, ArchiveLimits limits, bool nested)
    {
        var problems = new List<string>();
        var declared = DeclaredEntryCount(archive);
        if (declared is null)
        {
            return new ArchiveFacts { Problems = ["Не найдена запись конца центрального каталога: архив обрезан или не является ZIP."] };
        }

        if (declared > limits.MaxEntries)
        {
            return new ArchiveFacts
            {
                DeclaredEntries = declared.Value,
                Problems = [$"Архив объявляет {declared} записей (предел {limits.MaxEntries}); он не открывался."],
            };
        }

        archive.Position = 0;
        ZipArchive zip;
        try
        {
            zip = new ZipArchive(archive, ZipArchiveMode.Read, leaveOpen: true);
        }
        catch (InvalidDataException ex)
        {
            return new ArchiveFacts { DeclaredEntries = declared.Value, Problems = [$"Архив не открывается: {ex.Message}"] };
        }

        using (zip)
        {
            var classes = 0;
            var packages = new Dictionary<string, int>(StringComparer.Ordinal);
            var mods = new List<ModMetadata>();
            var nestedJars = new List<string>();
            var nestedMods = new List<ModMetadata>();
            var featureClasses = new List<string>();
            var featureClassesSeen = 0;
            string? serverPlugin = null;
            IReadOnlyDictionary<string, string>? manifest = null;

            IReadOnlyList<ZipArchiveEntry> entries;
            try
            {
                entries = zip.Entries;
            }
            catch (InvalidDataException ex)
            {
                return new ArchiveFacts { DeclaredEntries = declared.Value, Problems = [$"Центральный каталог архива повреждён: {ex.Message}"] };
            }

            foreach (var e in entries)
            {
                var name = e.FullName.Replace('\\', '/');
                if (name.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                {
                    classes++;
                    var prefix = PackagePrefix(name);
                    if (prefix is not null)
                    {
                        packages[prefix] = packages.GetValueOrDefault(prefix) + 1;
                    }

                    if (limits.FeatureVocabulary is { } vocabulary && ClassNames.FeatureKey(name) is { } key && vocabulary.Contains(key))
                    {
                        featureClassesSeen++;
                        if (featureClasses.Count < limits.MaxFeatureClasses)
                        {
                            featureClasses.Add(name[..^".class".Length]);
                        }
                    }

                    continue;
                }

                switch (name.ToUpperInvariant())
                {
                    case "FABRIC.MOD.JSON":
                        AddMod(mods, problems, e, limits, "fabric", ParseFabric);
                        break;
                    case "QUILT.MOD.JSON":
                        AddMod(mods, problems, e, limits, "quilt", ParseQuilt);
                        break;
                    case "META-INF/MODS.TOML":
                        AddMod(mods, problems, e, limits, "forge", t => ParseModsToml(t, "forge", "META-INF/mods.toml"));
                        break;
                    case "META-INF/NEOFORGE.MODS.TOML":
                        AddMod(mods, problems, e, limits, "neoforge", t => ParseModsToml(t, "neoforge", "META-INF/neoforge.mods.toml"));
                        break;
                    case "MCMOD.INFO":
                        AddMod(mods, problems, e, limits, "forge-legacy", ParseMcmodInfo);
                        break;
                    case "PLUGIN.YML" or "PAPER-PLUGIN.YML" or "BUNGEE.YML" or "VELOCITY-PLUGIN.JSON":
                        serverPlugin ??= name;
                        break;
                    case "META-INF/MANIFEST.MF":
                        var text = ReadText(e, limits, problems);
                        if (text is not null)
                        {
                            manifest = ParseManifest(text);
                        }

                        break;
                }

                if (!nested && name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)
                    && (name.StartsWith("META-INF/jars/", StringComparison.OrdinalIgnoreCase) || name.StartsWith("META-INF/jarjar/", StringComparison.OrdinalIgnoreCase)))
                {
                    nestedJars.Add(name);
                    if (nestedJars.Count <= limits.MaxNestedJars)
                    {
                        InspectNested(e, limits, nestedMods, problems);
                    }
                }
            }

            if (nestedJars.Count > limits.MaxNestedJars)
            {
                problems.Add($"Вложенных JAR: {nestedJars.Count}; разобраны первые {limits.MaxNestedJars}.");
            }

            if (featureClassesSeen > featureClasses.Count)
            {
                problems.Add($"Классов с названиями функций: {featureClassesSeen}; записаны первые {featureClasses.Count}.");
            }

            return new ArchiveFacts
            {
                DeclaredEntries = declared.Value,
                ClassCount = classes,
                TopPackages = packages.OrderByDescending(p => p.Value).ThenBy(p => p.Key, StringComparer.Ordinal).Take(10).Select(p => p.Key).ToList(),
                Mods = mods,
                Manifest = manifest,
                NestedJars = nestedJars,
                NestedMods = nestedMods,
                FeatureClasses = featureClasses,
                ServerPlugin = serverPlugin,
                Problems = problems,
            };
        }
    }

    /// <summary>Total entries from the end-of-central-directory record (ZIP64 aware); null if no record is found.</summary>
    public static long? DeclaredEntryCount(Stream s)
    {
        ArgumentNullException.ThrowIfNull(s);
        const int EocdSize = 22;
        if (s.Length < EocdSize)
        {
            return null;
        }

        var tailLength = (int)Math.Min(s.Length, EocdSize + 0xFFFF);
        var tail = new byte[tailLength];
        s.Position = s.Length - tailLength;
        s.ReadExactly(tail);

        for (var i = tailLength - EocdSize; i >= 0; i--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(tail.AsSpan(i)) != 0x06054B50)
            {
                continue;
            }

            long total = BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(i + 10));
            if (total != 0xFFFF)
            {
                return total;
            }

            // ZIP64: locator sits 20 bytes before the EOCD and points to the ZIP64 EOCD record.
            if (i < 20 || BinaryPrimitives.ReadUInt32LittleEndian(tail.AsSpan(i - 20)) != 0x07064B50)
            {
                return total;
            }

            var zip64Offset = BinaryPrimitives.ReadInt64LittleEndian(tail.AsSpan(i - 20 + 8));
            if (zip64Offset < 0 || zip64Offset > s.Length - 56)
            {
                return null;
            }

            var rec = new byte[56];
            s.Position = zip64Offset;
            s.ReadExactly(rec);
            return BinaryPrimitives.ReadUInt32LittleEndian(rec) == 0x06064B50
                ? (long)Math.Min(BinaryPrimitives.ReadUInt64LittleEndian(rec.AsSpan(32)), long.MaxValue)
                : null;
        }

        return null;
    }

    private static void InspectNested(ZipArchiveEntry e, ArchiveLimits limits, List<ModMetadata> nestedMods, List<string> problems)
    {
        if (e.Length > limits.MaxNestedJarBytes)
        {
            problems.Add($"Вложенный {e.FullName} занимает {e.Length} байт (предел {limits.MaxNestedJarBytes}); не разбирался.");
            return;
        }

        try
        {
            using var copy = new MemoryStream((int)e.Length);
            using (var src = e.Open())
            {
                CopyCapped(src, copy, limits.MaxNestedJarBytes);
            }

            copy.Position = 0;
            var facts = Inspect(copy, limits, nested: true);
            nestedMods.AddRange(facts.Mods);
            problems.AddRange(facts.Problems.Select(p => $"{e.FullName}: {p}"));
        }
        catch (Exception ex) when (ex is InvalidDataException or NotSupportedException or IOException)
        {
            problems.Add($"Вложенный {e.FullName} не прочитан: {ex.Message}");
        }
    }

    private static void AddMod(List<ModMetadata> mods, List<string> problems, ZipArchiveEntry e, ArchiveLimits limits, string loader, Func<string, ModMetadata?> parse)
    {
        var text = ReadText(e, limits, problems);
        if (text is null)
        {
            return;
        }

        try
        {
            var mod = parse(text);
            if (mod is not null)
            {
                mods.Add(mod);
            }
            else
            {
                problems.Add($"В {e.FullName} нет распознаваемого описания мода {loader}.");
            }
        }
        catch (JsonException ex)
        {
            problems.Add($"{e.FullName} — некорректный JSON: {ex.Message}");
        }
        catch (InvalidOperationException ex)
        {
            problems.Add($"{e.FullName} имеет неожиданную структуру: {ex.Message}");
        }
    }

    private static string? ReadText(ZipArchiveEntry e, ArchiveLimits limits, List<string> problems)
    {
        if (e.Length > limits.MaxDescriptorBytes)
        {
            problems.Add($"{e.FullName} занимает {e.Length} байт (предел {limits.MaxDescriptorBytes}); не читался.");
            return null;
        }

        try
        {
            using var src = e.Open();
            using var buffer = new MemoryStream();
            CopyCapped(src, buffer, limits.MaxDescriptorBytes);
            return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length).TrimStart('﻿');
        }
        catch (Exception ex) when (ex is InvalidDataException or NotSupportedException or IOException)
        {
            problems.Add($"{e.FullName} не распаковывается: {ex.Message}");
            return null;
        }
    }

    /// <summary>Copies at most <paramref name="max"/> bytes; a declared size that lies about the real size cannot overflow.</summary>
    private static void CopyCapped(Stream src, Stream dst, long max)
    {
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = src.Read(buffer, 0, (int)Math.Min(buffer.Length, max + 1 - total))) > 0)
        {
            total += read;
            if (total > max)
            {
                throw new InvalidDataException($"Запись распаковывается больше чем в {max} байт.");
            }

            dst.Write(buffer, 0, read);
        }
    }

    private static string? PackagePrefix(string classPath)
    {
        var parts = classPath.Split('/');
        if (parts.Length < 2)
        {
            return null;
        }

        // Skip the version-specific prefix of multi-release JARs.
        var start = parts.Length > 4 && parts[0].Equals("META-INF", StringComparison.OrdinalIgnoreCase) && parts[1] == "versions" ? 3 : 0;
        var depth = Math.Min(3, parts.Length - 1 - start);
        return depth <= 0 ? null : string.Join('.', parts.Skip(start).Take(depth));
    }

    internal static ModMetadata? ParseFabric(string json)
    {
        using var doc = JsonDocument.Parse(json, JsonOptions);
        var r = doc.RootElement;
        if (r.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        return new ModMetadata("fabric", Str(r, "id"), Str(r, "name"), Str(r, "version"), "fabric.mod.json");
    }

    internal static ModMetadata? ParseQuilt(string json)
    {
        using var doc = JsonDocument.Parse(json, JsonOptions);
        if (!doc.RootElement.TryGetProperty("quilt_loader", out var loader) || loader.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        string? name = null;
        if (loader.TryGetProperty("metadata", out var meta) && meta.ValueKind == JsonValueKind.Object)
        {
            name = Str(meta, "name");
        }

        return new ModMetadata("quilt", Str(loader, "id"), name, Str(loader, "version"), "quilt.mod.json");
    }

    internal static ModMetadata? ParseMcmodInfo(string json)
    {
        using var doc = JsonDocument.Parse(json, JsonOptions);
        var r = doc.RootElement;
        var first = r.ValueKind switch
        {
            JsonValueKind.Array when r.GetArrayLength() > 0 => r[0],
            JsonValueKind.Object when r.TryGetProperty("modList", out var list) && list.ValueKind == JsonValueKind.Array && list.GetArrayLength() > 0 => list[0],
            _ => default,
        };

        return first.ValueKind == JsonValueKind.Object
            ? new ModMetadata("forge-legacy", Str(first, "modid"), Str(first, "name"), Str(first, "version"), "mcmod.info")
            : null;
    }

    /// <summary>
    /// Minimal TOML reading for mods.toml: the first [[mods]] table's modId, displayName and version.
    /// Not a general TOML parser; values in other forms are left empty rather than guessed.
    /// </summary>
    internal static ModMetadata? ParseModsToml(string toml, string loader, string descriptor)
    {
        string? id = null, name = null, version = null;
        var inMods = false;
        var seenMods = false;
        foreach (var raw in toml.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith('#') || line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith('['))
            {
                if (seenMods && inMods)
                {
                    break;
                }

                inMods = line.Replace(" ", string.Empty, StringComparison.Ordinal) == "[[mods]]";
                seenMods |= inMods;
                continue;
            }

            if (!inMods)
            {
                continue;
            }

            var eq = line.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0)
            {
                continue;
            }

            var key = line[..eq].Trim();
            var value = TomlString(line[(eq + 1)..].Trim());
            switch (key)
            {
                case "modId": id = value; break;
                case "displayName": name = value; break;
                case "version": version = value; break;
            }
        }

        return seenMods ? new ModMetadata(loader, id, name, version, descriptor) : null;
    }

    private static string? TomlString(string v)
    {
        if (v.Length >= 2 && (v[0] == '"' || v[0] == '\''))
        {
            var end = v.IndexOf(v[0], 1);
            return end > 0 ? v[1..end] : null;
        }

        return null;
    }

    /// <summary>MANIFEST.MF main section, with 72-byte continuation lines joined.</summary>
    internal static IReadOnlyDictionary<string, string> ParseManifest(string text)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? key = null;
        var value = new StringBuilder();

        void Flush()
        {
            if (key is not null && ManifestKeys.Contains(key, StringComparer.OrdinalIgnoreCase))
            {
                result[key] = value.ToString().Trim();
            }

            key = null;
            value.Clear();
        }

        foreach (var raw in text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            if (raw.Length == 0)
            {
                // A blank line ends the main section; per-entry sections follow.
                Flush();
                if (result.Count > 0)
                {
                    break;
                }

                continue;
            }

            if (raw[0] == ' ' && key is not null)
            {
                value.Append(raw.AsSpan(1));
                continue;
            }

            Flush();
            var colon = raw.IndexOf(':', StringComparison.Ordinal);
            if (colon > 0)
            {
                key = raw[..colon].Trim();
                value.Append(raw.AsSpan(colon + 1));
            }
        }

        Flush();
        return result;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
