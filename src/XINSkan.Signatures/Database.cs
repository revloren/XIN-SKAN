using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace XINSkan.Signatures;

/// <summary>Where a record of the database comes from and when it was checked.</summary>
public sealed record SourceRecord
{
    public required string Title { get; init; }

    public string? Url { get; init; }

    /// <summary>Commit of a source repository the facts were read at.</summary>
    public string? Commit { get; init; }

    /// <summary>Date of the last check, yyyy-MM-dd.</summary>
    public required string Checked { get; init; }
}

/// <summary>Identifiers that come from a project's own source (only for verified entries).</summary>
public sealed record Identifiers
{
    public IReadOnlyList<string> ModIds { get; init; } = [];

    /// <summary>Java packages ("net.wurstclient"); a class package that equals or starts with one of them matches.</summary>
    public IReadOnlyList<string> Packages { get; init; } = [];

    public IReadOnlyList<string> Entrypoints { get; init; } = [];

    /// <summary>Maven coordinates without version ("com.github.ImpactDevelopment:Impact").</summary>
    public IReadOnlyList<string> Libraries { get; init; } = [];

    /// <summary>
    /// Files and folders the client itself writes in the game directory, relative to it ("wurst/enabled-hacks.json"),
    /// as read from its source.
    /// </summary>
    public IReadOnlyList<string> DataPaths { get; init; } = [];
}

/// <summary>A verified project in which a feature exists as a module, and where its source says so.</summary>
public sealed record FeatureProject
{
    public required string Client { get; init; }

    /// <summary>The module's name in that project ("Killaura", "ModuleKillAura").</summary>
    public required string Module { get; init; }

    public required string Path { get; init; }
}

/// <summary>The official client JAR of one Minecraft version, as Mojang's version file states it.</summary>
public sealed record MojangVersion
{
    public required string Id { get; init; }

    /// <summary>release, snapshot, old_beta, old_alpha.</summary>
    public required string Type { get; init; }

    public string? ReleaseTime { get; init; }

    /// <summary>SHA-1 of the version file, as the version manifest gives it.</summary>
    public required string VersionJsonSha1 { get; init; }

    public required string ClientSha1 { get; init; }

    public long ClientSize { get; init; }
}

/// <summary>A function of cheat clients (TZ section 10). Its names are search terms, never evidence on their own.</summary>
public sealed record FeatureEntry
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    /// <summary>combat, movement, visual, world, player, misc.</summary>
    public required string Category { get; init; }

    public IReadOnlyList<string> Variants { get; init; } = [];

    /// <summary>
    /// strong — a name a legitimate mod or library rarely gives a class (KillAura, Scaffold); weak — a name that also
    /// means something ordinary (Timer, HUD, Speed, Freecam). Only strong ones count toward a Multiple Feature Match.
    /// </summary>
    public required string Strength { get; init; }

    /// <summary>verified — found as a module in a verified project's source; user-list — only in the customer's list.</summary>
    public required string Status { get; init; }

    /// <summary>"10" — the customer's list (TZ section 10); "research" — added from the verified projects.</summary>
    public required string List { get; init; }

    public IReadOnlyList<FeatureProject> Projects { get; init; } = [];

    public IReadOnlyList<SourceRecord> Sources { get; init; } = [];

    public string? Note { get; init; }
}

/// <summary>A known client, tool, launcher or term.</summary>
public sealed record ClientEntry
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    /// <summary>client, utility, dll, launcher, loader, tool, feature, generic.</summary>
    public required string Kind { get; init; }

    /// <summary>verified (identifiers from the project's own source), user-list (customer's list), candidate.</summary>
    public required string Status { get; init; }

    public bool Ambiguous { get; init; }

    /// <summary>Spellings as found in the sources, original case kept.</summary>
    public IReadOnlyList<string> Variants { get; init; } = [];

    /// <summary>Spellings that are ordinary words or too short to mean anything without Minecraft context.</summary>
    public IReadOnlyList<string> AmbiguousVariants { get; init; } = [];

    public Identifiers Identifiers { get; init; } = new();

    public IReadOnlyList<SourceRecord> Sources { get; init; } = [];

    public string? Note { get; init; }
}

/// <summary>An original spelling from a source list and the entry it belongs to.</summary>
public sealed record AliasEntry
{
    public required string Original { get; init; }

    public required string Normalized { get; init; }

    public required string Id { get; init; }

    public required string List { get; init; }
}

/// <summary>SHA-256 of a real file obtained from a stated source. No hash without a source.</summary>
public sealed record HashEntry
{
    public required string Sha256 { get; init; }

    public required string ClientId { get; init; }

    public required string FileName { get; init; }

    public string? Version { get; init; }

    public long? Size { get; init; }

    public required SourceRecord Source { get; init; }
}

public sealed record ChangelogEntry
{
    public required string Version { get; init; }

    public required string Date { get; init; }

    public IReadOnlyList<string> Changes { get; init; } = [];
}

/// <summary>Version, file hashes and change log of a database bundle.</summary>
public sealed record Manifest
{
    public int Format { get; init; } = 1;

    public required string Version { get; init; }

    public required string Created { get; init; }

    /// <summary>File name → SHA-256 (lowercase hex).</summary>
    public required IReadOnlyDictionary<string, string> Files { get; init; }

    public IReadOnlyList<ChangelogEntry> Changelog { get; init; } = [];
}

/// <summary>Detached signature of manifest.json: ECDSA P-256 over SHA-256, IEEE P1363 encoding, base64.</summary>
public sealed record ManifestSignature
{
    public required string KeyId { get; init; }

    public required string Signature { get; init; }
}

/// <summary>A loaded, validated database.</summary>
public sealed class SignatureDatabase
{
    public static readonly string[] DataFiles = ["clients.json", "aliases.json", "hashes.json", "features.json", "mojang.json"];

    internal static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        MaxDepth = 32,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private SignatureDatabase(Manifest manifest, string manifestSha256, string origin, string? keyId, List<ClientEntry> clients, List<AliasEntry> aliases, List<HashEntry> hashes, List<FeatureEntry> features, (SourceRecord? Source, List<MojangVersion> Versions) mojang, List<string> problems)
    {
        MojangSource = mojang.Source;
        MojangClients = mojang.Versions.ToDictionary(v => v.Id, StringComparer.Ordinal);
        Features = features;
        FeatureVocabulary = features.SelectMany(f => f.Variants.Append(f.Name)).Select(XINSkan.Core.Paths.ClassNames.Key).Where(k => k.Length >= 3).ToHashSet(StringComparer.Ordinal);
        Manifest = manifest;
        ManifestSha256 = manifestSha256;
        Origin = origin;
        KeyId = keyId;
        Clients = clients;
        Aliases = aliases;
        Hashes = hashes;
        Problems = problems;
    }

    public Manifest Manifest { get; }

    public string ManifestSha256 { get; }

    /// <summary>"embedded" or the folder of a signed update.</summary>
    public string Origin { get; }

    public string? KeyId { get; }

    public IReadOnlyList<ClientEntry> Clients { get; }

    public IReadOnlyList<AliasEntry> Aliases { get; }

    /// <summary>Only hashes that passed validation (a source with a URL and a date).</summary>
    public IReadOnlyList<HashEntry> Hashes { get; }

    /// <summary>Records rejected by validation, with the reason.</summary>
    public IReadOnlyList<string> Problems { get; }

    /// <summary>The feature catalog (TZ section 10).</summary>
    public IReadOnlyList<FeatureEntry> Features { get; }

    /// <summary>Keys of every feature spelling, for the archive reader to keep matching class names.</summary>
    public IReadOnlySet<string> FeatureVocabulary { get; }

    /// <summary>Official client JARs by version id (mojang.json); empty when the file lists none.</summary>
    public IReadOnlyDictionary<string, MojangVersion> MojangClients { get; }

    /// <summary>Where and when the official client list was read.</summary>
    public SourceRecord? MojangSource { get; }

    public Models.SignatureDatabaseInfo Info() => new(
        Manifest.Version, Origin, ManifestSha256, KeyId, Clients.Count, Clients.Count(c => c.Status == "verified"), Hashes.Count, Problems);

    private sealed record ClientsFile(int Schema, List<ClientEntry> Entries);

    private sealed record AliasesFile(int Schema, List<AliasEntry> Aliases);

    private sealed record HashesFile(int Schema, List<HashEntry> Entries);

    private sealed record FeaturesFile(int Schema, List<FeatureEntry> Features);

    private sealed record MojangFile(int Schema, SourceRecord? Source, List<MojangVersion> Versions);

    /// <summary>
    /// Builds a database from bundle bytes after checking every file against the manifest. Records that break the
    /// rules (a verified entry without a source, a hash without a URL, an alias without an entry) are dropped and
    /// listed in <see cref="Problems"/>; the rest is used.
    /// </summary>
    /// <exception cref="InvalidDataException">The manifest or a file is missing, damaged or does not match its hash.</exception>
    public static SignatureDatabase Load(byte[] manifestBytes, Func<string, byte[]?> file, string origin, string? keyId)
    {
        Manifest manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<Manifest>(manifestBytes, Json) ?? throw new InvalidDataException("manifest.json пуст.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("manifest.json не разобран: " + ex.Message, ex);
        }

        if (manifest.Format != 1)
        {
            throw new InvalidDataException($"Формат базы {manifest.Format} не поддерживается.");
        }

        var data = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var name in DataFiles)
        {
            var bytes = file(name) ?? throw new InvalidDataException($"В базе нет файла {name}.");
            if (!manifest.Files.TryGetValue(name, out var expected) || !string.Equals(expected, Sha256(bytes), StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"{name} не совпадает с хешем в manifest.json: файл изменён после подписи.");
            }

            data[name] = bytes;
        }

        try
        {
            var clients = JsonSerializer.Deserialize<ClientsFile>(data["clients.json"], Json)?.Entries ?? [];
            var aliases = JsonSerializer.Deserialize<AliasesFile>(data["aliases.json"], Json)?.Aliases ?? [];
            var hashes = JsonSerializer.Deserialize<HashesFile>(data["hashes.json"], Json)?.Entries ?? [];
            var features = JsonSerializer.Deserialize<FeaturesFile>(data["features.json"], Json)?.Features ?? [];
            var problems = new List<string>();
            var valid = Validate(clients, aliases, hashes, problems);
            var goodFeatures = ValidateFeatures(features, valid.Clients, problems);
            var mojang = JsonSerializer.Deserialize<MojangFile>(data["mojang.json"], Json);
            var goodMojang = ValidateMojang(mojang?.Source, mojang?.Versions ?? [], problems);
            return new SignatureDatabase(manifest, Sha256(manifestBytes), origin, keyId, valid.Clients, valid.Aliases, valid.Hashes, goodFeatures, (mojang?.Source, goodMojang), problems);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("Файл базы не разобран: " + ex.Message, ex);
        }
    }

    internal static (List<ClientEntry> Clients, List<AliasEntry> Aliases, List<HashEntry> Hashes) Validate(
        List<ClientEntry> clients, List<AliasEntry> aliases, List<HashEntry> hashes, List<string> problems)
    {
        string[] kinds = ["client", "utility", "dll", "launcher", "loader", "tool", "feature", "generic"];
        string[] statuses = ["verified", "user-list", "candidate"];
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var goodClients = new List<ClientEntry>();
        foreach (var c in clients)
        {
            string? why = null;
            if (string.IsNullOrWhiteSpace(c.Id) || !ids.Add(c.Id))
            {
                why = "повтор или пустой идентификатор";
            }
            else if (!kinds.Contains(c.Kind) || !statuses.Contains(c.Status))
            {
                why = $"неизвестный вид «{c.Kind}» или статус «{c.Status}»";
            }
            else if (c.Variants.Count == 0 || c.Sources.Count == 0 || c.Sources.Any(s => !IsDate(s.Checked)))
            {
                why = "нет написаний, источника или даты проверки";
            }
            else if (c.Status == "verified" && !c.Sources.Any(s => s.Url is not null && s.Url.StartsWith("https://", StringComparison.Ordinal)))
            {
                why = "статус verified без источника со ссылкой";
            }
            else if (c.Status != "verified" && HasIdentifiers(c.Identifiers))
            {
                why = "идентификаторы компонентов допустимы только у проверенных записей";
            }
            else if (c.AmbiguousVariants.Any(v => !c.Variants.Contains(v)))
            {
                why = "неоднозначное написание не входит в список написаний";
            }

            if (why is null)
            {
                goodClients.Add(c);
            }
            else
            {
                problems.Add($"Запись {c.Id}: {why}.");
                ids.Remove(c.Id);
                ids.Add(c.Id + "\u0000rejected");
            }
        }

        var goodAliases = new List<AliasEntry>();
        foreach (var a in aliases)
        {
            if (goodClients.Any(c => c.Id == a.Id) && !string.IsNullOrWhiteSpace(a.Original))
            {
                goodAliases.Add(a);
            }
            else
            {
                problems.Add($"Написание «{a.Original}» ссылается на отсутствующую запись {a.Id}.");
            }
        }

        var goodHashes = new List<HashEntry>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in hashes)
        {
            if (h.Sha256 is not { Length: 64 } || !h.Sha256.All(Uri.IsHexDigit))
            {
                problems.Add($"Хеш «{h.Sha256}» не SHA-256.");
            }
            else if (!goodClients.Any(c => c.Id == h.ClientId))
            {
                problems.Add($"Хеш {h.Sha256}: нет записи {h.ClientId}.");
            }
            else if (h.Source.Url is not { } url || !url.StartsWith("https://", StringComparison.Ordinal) || !IsDate(h.Source.Checked))
            {
                problems.Add($"Хеш {h.Sha256}: нет источника со ссылкой и датой — неподтверждённые хеши не используются.");
            }
            else if (!seen.Add(h.Sha256))
            {
                problems.Add($"Хеш {h.Sha256} повторяется.");
            }
            else
            {
                goodHashes.Add(h with { Sha256 = h.Sha256.ToLowerInvariant() });
            }
        }

        return (goodClients, goodAliases, goodHashes);
    }

    internal static List<FeatureEntry> ValidateFeatures(List<FeatureEntry> features, List<ClientEntry> clients, List<string> problems)
    {
        string[] categories = ["combat", "movement", "visual", "world", "player", "misc"];
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var keys = new Dictionary<string, string>(StringComparer.Ordinal);
        var good = new List<FeatureEntry>();
        var verifiedClients = clients.Where(c => c.Status == "verified").Select(c => c.Id).ToHashSet(StringComparer.Ordinal);
        foreach (var f in features)
        {
            string? why = null;
            if (string.IsNullOrWhiteSpace(f.Id) || !ids.Add(f.Id))
            {
                why = "повтор или пустой идентификатор";
            }
            else if (!categories.Contains(f.Category) || f.Strength is not ("strong" or "weak") || f.Status is not ("verified" or "user-list") || f.List is not ("10" or "research"))
            {
                why = $"неизвестная категория «{f.Category}», сила «{f.Strength}», статус «{f.Status}» или список «{f.List}»";
            }
            else if (f.Variants.Count == 0 || f.Sources.Count == 0 || f.Sources.Any(s => !IsDate(s.Checked)))
            {
                why = "нет написаний, источника или даты проверки";
            }
            else if (f.Status == "verified" && (f.Projects.Count == 0 || f.Projects.Any(p => !verifiedClients.Contains(p.Client))
                                                || !f.Sources.Any(s => s.Url?.StartsWith("https://", StringComparison.Ordinal) == true && s.Commit is { Length: 40 })))
            {
                why = "статус verified без проекта из проверенных записей или без источника с коммитом";
            }
            else if (f.Status != "verified" && f.Projects.Count > 0)
            {
                why = "подтверждённые проекты допустимы только у проверенной функции";
            }
            else if (f.List == "research" && f.Status != "verified")
            {
                why = "функция, добавленная по исследованию, должна быть подтверждена исходным кодом";
            }
            else if (f.Variants.Select(XINSkan.Core.Paths.ClassNames.Key).FirstOrDefault(k => keys.TryGetValue(k, out var other) && other != f.Id) is { } clash)
            {
                why = $"написание с ключом «{clash}» уже принадлежит функции {keys[clash]}";
            }

            if (why is null)
            {
                foreach (var k in f.Variants.Select(XINSkan.Core.Paths.ClassNames.Key))
                {
                    keys[k] = f.Id;
                }

                good.Add(f);
            }
            else
            {
                problems.Add($"Функция {f.Id}: {why}.");
            }
        }

        return good;
    }

    internal static List<MojangVersion> ValidateMojang(SourceRecord? source, List<MojangVersion> versions, List<string> problems)
    {
        if (versions.Count == 0)
        {
            return [];
        }

        if (source?.Url is not { } url || !url.StartsWith("https://piston-meta.mojang.com/", StringComparison.Ordinal) || !IsDate(source.Checked))
        {
            problems.Add("Список официальных клиентов без источника piston-meta.mojang.com и даты: не используется.");
            return [];
        }

        var ids = new HashSet<string>(StringComparer.Ordinal);
        var good = new List<MojangVersion>();
        foreach (var v in versions)
        {
            if (string.IsNullOrWhiteSpace(v.Id) || !ids.Add(v.Id))
            {
                problems.Add($"Версия Mojang «{v.Id}»: повтор или пустой идентификатор.");
            }
            else if (!IsSha1(v.ClientSha1) || !IsSha1(v.VersionJsonSha1) || v.ClientSize <= 0)
            {
                problems.Add($"Версия Mojang {v.Id}: хеш не SHA-1 или нет размера.");
            }
            else
            {
                good.Add(v with { ClientSha1 = v.ClientSha1.ToLowerInvariant() });
            }
        }

        return good;
    }

    private static bool IsSha1(string? s) => s is { Length: 40 } && s.All(Uri.IsHexDigit);

    private static bool HasIdentifiers(Identifiers i) => i.ModIds.Count + i.Packages.Count + i.Entrypoints.Count + i.Libraries.Count + i.DataPaths.Count > 0;

    private static bool IsDate(string? s) => DateOnly.TryParseExact(s, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out _);

    public static string Sha256(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
}
