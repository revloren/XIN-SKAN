using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using XINSkan.Core.Paths;
using XINSkan.Correlation;
using XINSkan.Models;
using XINSkan.Signatures;

namespace XINSkan.SignaturesTests;

/// <summary>Bundles built in memory: data files, a manifest with their hashes, a signature.</summary>
internal static class Bundle
{
    public static Dictionary<string, byte[]> Make(string version, object clients, object? hashes = null, object? aliases = null)
    {
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["clients.json"] = JsonSerializer.SerializeToUtf8Bytes(new { schema = 1, entries = clients }),
            ["aliases.json"] = JsonSerializer.SerializeToUtf8Bytes(aliases ?? new { schema = 1, aliases = Array.Empty<object>() }),
            ["hashes.json"] = JsonSerializer.SerializeToUtf8Bytes(new { schema = 1, entries = hashes ?? Array.Empty<object>() }),
        };
        files["manifest.json"] = JsonSerializer.SerializeToUtf8Bytes(new
        {
            format = 1,
            version,
            created = "2026-11-10",
            files = files.ToDictionary(f => f.Key, f => SignatureDatabase.Sha256(f.Value)),
        });
        return files;
    }

    public static void Sign(Dictionary<string, byte[]> files, ECDsa key, string keyId) =>
        files["manifest.sig"] = JsonSerializer.SerializeToUtf8Bytes(new { keyId, signature = Convert.ToBase64String(key.SignData(files["manifest.json"], HashAlgorithmName.SHA256)) });

    public static object Client(string id, string status = "verified", string[]? variants = null, string[]? modIds = null, string[]? packages = null, string kind = "client") => new
    {
        id,
        name = id,
        kind,
        status,
        variants = variants ?? [id],
        identifiers = new { modIds = modIds ?? [], packages = packages ?? [] },
        sources = new[] { new { title = "test", url = status == "verified" ? "https://example.org/src" : null, commit = "abc", @checked = "2026-11-10" } },
    };

    public static SignatureDatabase Load(Dictionary<string, byte[]> files) =>
        SignatureDatabase.Load(files["manifest.json"], n => files.GetValueOrDefault(n), "test", null);
}

public sealed class SignatureDatabaseTests
{
    private static readonly string[] UserList = "Baritone, Cabaletta, Jigsaw, LiquidBounce, Wurst, GishCode, Inertia, Impact, rename_me_please.dll, Future, RusherHack, Pyro, Zamorozka, Konas, WintWare, Nursultan, Norules, Akrien, Sigma, DeadCode, Eternity, WEXSIDE, Rich, RichPremium, EdItMe.dll, mc100.dll, Matix, R3D, Celestial, Wild, Destroy, ArchWare, NightMare, BoberWare, FLauncher, ExLoader, MrLauncher, R-launcher, McLauncher, CheatEngine, WWE, Grey, Jessica, SkillClient, SkSkyClient, Wolfram, Huzuni, Squad, tools.jar, kyprak, Aristois, OYMINE, HCL, Advanced, Xray, X-ray, hvii, ErbaevHacks, NeverHook, Vape, Lite, Cortex, Autoclicker, Auto-clicker, Nathox, Reverse, Never, Rage, R9, Bypass, Matrix, Trash, Undetectable, EditMe, Freecam, Infinity, ForceWare, Groza, GrozaClient, ZenWare, Ghost, WaterClient, External, Stress Client, R8, ExtremeHack, Ares, SalHack, Kami, Blue, Heracles, Summer, Summit, Xulu, EaZy, Sky, Kompl, Vane, Shit, Nemezida, Haruka, Nix, NightDLC"
        .Split(", ");

    [Fact]
    public void The_built_in_database_keeps_every_spelling_of_the_customer_list_and_validates()
    {
        var db = DatabaseLoader.Embedded();
        Assert.Empty(db.Problems);
        Assert.Equal("embedded", db.Origin);
        Assert.Equal(103, UserList.Length);
        Assert.Equal(UserList, db.Aliases.Where(a => a.List == "9.1").Select(a => a.Original));
        Assert.Equal(new[] { "Meteor Client", "Raven", "Raven XD", "Boze", "Doomsday", "BleachHack", "Phobos" }, db.Aliases.Where(a => a.List == "9.2").Select(a => a.Original));

        // Spellings of one project share an entry; different projects never do.
        string Of(string spelling) => db.Aliases.Single(a => a.Original == spelling).Id;
        Assert.Equal(Of("Xray"), Of("X-ray"));
        Assert.Equal(Of("Autoclicker"), Of("Auto-clicker"));
        Assert.Equal(Of("EdItMe.dll"), Of("EditMe"));
        Assert.Equal(Of("Groza"), Of("GrozaClient"));
        Assert.NotEqual(Of("Rich"), Of("RichPremium"));
        Assert.NotEqual(Of("Raven"), Of("Raven XD"));
        Assert.NotEqual("kami-blue", Of("Kami"));
        Assert.Equal(Of("Baritone"), Of("Cabaletta"));

        var verified = db.Clients.Where(c => c.Status == "verified").Select(c => c.Id).Order(StringComparer.Ordinal).ToList();
        Assert.Equal(new[] { "3arthh4ck", "baritone", "bleachhack", "impact", "kami-blue", "liquidbounce", "meteor", "salhack", "wurst" }, verified);
        Assert.All(db.Clients.Where(c => c.Status == "verified"), c => Assert.Contains(c.Sources, s => s.Url?.StartsWith("https://github.com/", StringComparison.Ordinal) == true && s.Commit is { Length: 40 }));
        Assert.All(db.Clients.Where(c => c.Status != "verified"), c => Assert.Empty(c.Identifiers.ModIds.Concat(c.Identifiers.Packages)));
        Assert.Equal(new[] { "wurst" }, db.Clients.Single(c => c.Id == "wurst").Identifiers.ModIds);

        // Every hash is of a file downloaded from a release of a verified project, and says which file and where from.
        Assert.Equal(57, db.Hashes.Count);
        Assert.All(db.Hashes, h =>
        {
            Assert.Equal("verified", db.Clients.Single(c => c.Id == h.ClientId).Status);
            Assert.Matches("^[0-9a-f]{64}$", h.Sha256);
            Assert.EndsWith(".jar", h.FileName, StringComparison.Ordinal);
            Assert.StartsWith("https://github.com/", h.Source.Url, StringComparison.Ordinal);
            Assert.Contains("/releases/download/", h.Source.Url, StringComparison.Ordinal);
            Assert.EndsWith("/" + h.FileName, h.Source.Url, StringComparison.Ordinal);
            Assert.True(h.Size > 0);
        });
        var baritone = db.Hashes.Single(h => h.FileName == "baritone-standalone-fabric-1.20.0.jar");
        Assert.Equal("baritone", baritone.ClientId);
        Assert.Equal("v1.20.0", baritone.Version);

        var groza = db.Clients.Single(c => c.Id == "groza");
        Assert.Equal(new[] { "Groza" }, groza.AmbiguousVariants);
        Assert.True(db.Clients.Single(c => c.Id == Of("tools.jar")).Ambiguous);
        Assert.Contains("JDK", db.Clients.Single(c => c.Id == Of("tools.jar")).Note, StringComparison.Ordinal);
        Assert.Equal("launcher", db.Clients.Single(c => c.Id == Of("FLauncher")).Kind);
        Assert.Contains(db.Manifest.Changelog, c => c.Version == db.Manifest.Version);
    }

    [Fact]
    public void Records_that_break_the_rules_are_dropped_and_named()
    {
        var files = Bundle.Make("1", new[]
        {
            Bundle.Client("good"),
            new { id = "nourl", name = "x", kind = "client", status = "verified", variants = new[] { "x" }, identifiers = new { modIds = Array.Empty<string>(), packages = Array.Empty<string>() }, sources = new[] { new { title = "t", url = (string?)null, commit = (string?)null, @checked = "2026-11-10" } } },
            Bundle.Client("unverified-ids", "user-list", modIds: ["x"]),
            Bundle.Client("good"),
        }, hashes: new object[]
        {
            new { sha256 = new string('a', 64), clientId = "good", fileName = "a.jar", source = new { title = "t", url = "https://example.org/a.jar", @checked = "2026-11-10" } },
            new { sha256 = new string('b', 64), clientId = "good", fileName = "b.jar", source = new { title = "сказали в чате", @checked = "2026-11-10" } },
            new { sha256 = "1234", clientId = "good", fileName = "c.jar", source = new { title = "t", url = "https://example.org", @checked = "2026-11-10" } },
        }, aliases: new { schema = 1, aliases = new[] { new { original = "Ghost", normalized = "ghost", id = "missing", list = "9.1" } } });

        var db = Bundle.Load(files);
        Assert.Equal(new[] { "good" }, db.Clients.Select(c => c.Id));
        Assert.Single(db.Hashes);
        Assert.Contains(db.Problems, p => p.Contains("nourl", StringComparison.Ordinal) && p.Contains("ссылкой", StringComparison.Ordinal));
        Assert.Contains(db.Problems, p => p.Contains("unverified-ids", StringComparison.Ordinal));
        Assert.Contains(db.Problems, p => p.Contains("неподтверждённые хеши", StringComparison.Ordinal));
        Assert.Contains(db.Problems, p => p.Contains("не SHA-256", StringComparison.Ordinal));
        Assert.Contains(db.Problems, p => p.Contains("Ghost", StringComparison.Ordinal));
        Assert.Contains(db.Problems, p => p.Contains("повтор", StringComparison.Ordinal));

        files["clients.json"] = Encoding.UTF8.GetBytes("{\"schema\":1,\"entries\":[]}");
        Assert.Throws<InvalidDataException>(() => Bundle.Load(files)); // changed after the manifest
    }

    [Fact]
    public void Signed_updates_are_used_only_when_trusted_intact_and_newer()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spki = key.ExportSubjectPublicKeyInfo();
        var keyId = DatabaseLoader.KeyId(spki);
        var trusted = new Dictionary<string, string> { [keyId] = Convert.ToBase64String(spki) };
        var folder = Path.Combine(Path.GetTempPath(), "xinskan-db-test");

        LoadResult Load(Dictionary<string, byte[]> files, IReadOnlyDictionary<string, string> keys) =>
            DatabaseLoader.Load(folder, p => files.GetValueOrDefault(Path.GetFileName(p)), keys);

        var update = Bundle.Make("9999.1.1.1", new[] { Bundle.Client("newclient") });
        Bundle.Sign(update, key, keyId);
        var ok = Load(update, trusted);
        Assert.Equal("9999.1.1.1", ok.Database.Manifest.Version);
        Assert.Equal(keyId, ok.Database.KeyId);
        Assert.Equal(folder, ok.Database.Origin);

        // Any change after signing, a stranger's key, no trusted key, an old version: the built-in database is used.
        var tampered = new Dictionary<string, byte[]>(update) { ["clients.json"] = JsonSerializer.SerializeToUtf8Bytes(new { schema = 1, entries = new[] { Bundle.Client("evil") } }) };
        Assert.Equal("embedded", Load(tampered, trusted).Database.Origin);
        Assert.Contains("изменён", Load(tampered, trusted).Notes.Single(), StringComparison.Ordinal);

        var forgedManifest = new Dictionary<string, byte[]>(update) { ["manifest.json"] = Bundle.Make("9999.1.1.2", new[] { Bundle.Client("evil") })["manifest.json"] };
        Assert.Contains("неверна", Load(forgedManifest, trusted).Notes.Single(), StringComparison.Ordinal);

        using var stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var foreign = Bundle.Make("9999.1.1.1", new[] { Bundle.Client("newclient") });
        Bundle.Sign(foreign, stranger, "stranger");
        Assert.Contains("нет среди доверенных", Load(foreign, trusted).Notes.Single(), StringComparison.Ordinal);
        Assert.Contains("ни один доверенный ключ", Load(update, new Dictionary<string, string>()).Notes.Single(), StringComparison.Ordinal);

        var old = Bundle.Make("2000.1.1.1", new[] { Bundle.Client("newclient") });
        Bundle.Sign(old, key, keyId);
        Assert.Equal("embedded", Load(old, trusted).Database.Origin);

        var unsigned = Bundle.Make("9999.1.1.1", new[] { Bundle.Client("newclient") });
        Assert.Contains("без подписи", Load(unsigned, trusted).Notes.Single(), StringComparison.Ordinal);
        Assert.Empty(Load(new Dictionary<string, byte[]>(), trusted).Notes); // no update folder content: nothing to say
    }

    [Theory]
    [InlineData("2026.11.10.1", "2026.11.10.1", 0)]
    [InlineData("2026.11.10.2", "2026.11.10.10", -1)]
    [InlineData("2027.1.1.1", "2026.12.31.9", 1)]
    public void Versions_compare_number_by_number(string a, string b, int expected) => Assert.Equal(expected, Math.Sign(DatabaseLoader.CompareVersions(a, b)));
}

public sealed class MatcherTests
{
    private static readonly Matcher Builtin = new(DatabaseLoader.Embedded());

    private static EvidenceFacts Fact(string? path, EvidenceSourceKind source = EvidenceSourceKind.FileSystem, EvidenceEventType type = EvidenceEventType.Existed, Sha256Hash? sha = null, params (string Key, string Value)[] attrs) =>
        new(Ulid.NewUlid(DateTimeOffset.UtcNow), "m", source, type, null, path, PathNormalizer.Normalize(path), path is null ? null : path[(path.LastIndexOfAny(['\\', '/']) + 1)..],
            null, null, null, sha, Confidence.Informational, attrs.ToDictionary(a => a.Key, a => a.Value, StringComparer.Ordinal));

    private static SignatureMatch? Single(EvidenceFacts f, string client) => Builtin.Match([f]).SingleOrDefault(m => m.ClientId == client);

    [Fact]
    public void A_mod_with_the_projects_own_identifiers_is_a_verified_component_match()
    {
        var jar = Fact(@"C:\Users\p\AppData\Roaming\.minecraft\mods\renamed.jar", attrs: [("Mod.Id", "wurst"), ("Jar.TopPackages", "net.wurstclient.hacks, net.wurstclient.mixin"), ("MinecraftRoot", "x")]);
        var m = Single(jar, "wurst")!;
        Assert.Equal(SignatureMatchKind.VerifiedComponentMatch, m.Kind);
        Assert.Contains("github.com/Wurst-Imperium/Wurst7", m.Detail, StringComparison.Ordinal);

        var log = Fact(@"C:\Users\p\AppData\Roaming\.minecraft\logs\latest.log", EvidenceSourceKind.MinecraftLog, EvidenceEventType.Observed, attrs: ("Game.Mods", "sodium@0.5.8, meteor-client@0.5.8, fabric-api@0.92"));
        Assert.Equal(SignatureMatchKind.VerifiedComponentMatch, Single(log, "meteor")!.Kind);

        var agent = Fact(@"C:\x\agent.jar", attrs: ("Manifest.Main-Class", "org.bleachhack.BleachHack"));
        Assert.Equal(SignatureMatchKind.VerifiedComponentMatch, Single(agent, "bleachhack")!.Kind);

        var baritoneForge = Fact(@"C:\x\b.jar", attrs: ("Mod.Id", "baritoe")); // the upstream typo is the real identifier
        Assert.Equal(SignatureMatchKind.VerifiedComponentMatch, Single(baritoneForge, "baritone")!.Kind);
    }

    [Theory]
    [InlineData(@"C:\Users\p\Downloads\Wurst-Client-v7.40-MC1.20.4.jar", "wurst")]
    [InlineData(@"C:\Users\p\Downloads\LiquidBounceInstaller.exe", "liquidbounce")]
    [InlineData(@"C:\Users\p\Desktop\NightDLC.jar", "nightdlc")]
    [InlineData(@"C:\Users\p\Desktop\WEXSIDE_loader.exe", "wexside")]
    [InlineData(@"C:\Windows\Temp\rename_me_please.dll", "renamemeplease")]
    [InlineData(@"C:\Users\p\Downloads\stress_client_v2.zip", "stressclient")]
    [InlineData(@"C:\Users\p\Downloads\raven-xd.jar", "ravenxd")]
    public void Specific_names_match_in_any_place(string path, string client)
    {
        var m = Single(Fact(path), client);
        Assert.NotNull(m);
        Assert.Equal(SignatureMatchKind.NameMatch, m.Kind);
    }

    [Theory]
    [InlineData(@"C:\Program Files\Java\jdk1.8.0\lib\tools.jar")]
    [InlineData(@"C:\Users\p\Pictures\sky.png")]
    [InlineData(@"C:\Users\p\Documents\Matrix.pdf")]
    [InlineData(@"C:\Program Files\NVIDIA\ForceWare\setup.exe")]
    [InlineData(@"C:\Users\p\Downloads\rename_me_please_v2.dll")]
    [InlineData(@"C:\Windows\System32\notepad.exe")]
    [InlineData(@"C:\Program Files\Java\bin\javaw.exe")]
    public void Ordinary_words_and_unrelated_files_do_not_match_outside_minecraft(string path) =>
        Assert.Empty(Builtin.Match([Fact(path)]));

    [Fact]
    public void Ordinary_words_inside_minecraft_are_only_possible_matches()
    {
        var sky = Builtin.Match([Fact(@"C:\Users\p\AppData\Roaming\.minecraft\mods\Sky.jar")]);
        Assert.Equal(SignatureMatchKind.PossibleMatch, sky.Single(m => m.ClientId == "sky").Kind);
        var tools = Builtin.Match([Fact(@"C:\Users\p\AppData\Roaming\.minecraft\mods\tools.jar")]);
        Assert.Equal(SignatureMatchKind.PossibleMatch, tools.Single().Kind);
        var groza = Builtin.Match([Fact(@"C:\Users\p\Downloads\GrozaClient.jar")]);
        Assert.Equal(SignatureMatchKind.NameMatch, groza.Single().Kind); // the specific spelling
    }

    [Fact]
    public void A_real_release_hash_in_the_built_in_database_is_an_exact_match_whatever_the_file_is_called()
    {
        var db = DatabaseLoader.Embedded();
        var known = db.Hashes.Single(h => h.FileName == "3arthh4ck-1.8.5-release.jar");
        var facts = new[] { Fact(@"C:\Users\p\AppData\Roaming\.minecraft\mods\optifine-fix.jar", sha: Sha256Hash.Parse(known.Sha256)) };
        var m = Assert.Single(new Matcher(db).Match(facts));
        Assert.Equal(SignatureMatchKind.ExactHashMatch, m.Kind);
        Assert.Equal("3arthh4ck", m.ClientId);
    }

    [Fact]
    public void An_exact_hash_from_a_stated_source_is_the_strongest_match()
    {
        var bytes = Encoding.ASCII.GetBytes("a real release file");
        var sha = SignatureDatabase.Sha256(bytes);
        var db = Bundle.Load(Bundle.Make("1", new[] { Bundle.Client("wurst", modIds: ["wurst"]) }, hashes: new[]
        {
            new { sha256 = sha, clientId = "wurst", fileName = "Wurst-Client-v7.40.jar", version = "7.40", source = new { title = "release", url = "https://github.com/x/releases/7.40", @checked = "2026-11-10" } },
        }));
        var f = Fact(@"C:\Users\p\Downloads\homework.txt", sha: Sha256Hash.FromBytes(SHA256.HashData(bytes)), attrs: ("Mod.Id", "wurst"));
        var m = new Matcher(db).Match([f]).Single();
        Assert.Equal(SignatureMatchKind.ExactHashMatch, m.Kind); // one match per entry and record: the strongest
        Assert.Contains("Wurst-Client-v7.40.jar", m.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Wurst-Client-v7.40.jar", new[] { "wurst", "client", "v7", "40", "wurstclient", "wurstclientv7" })]
    [InlineData("LiquidBounce", new[] { "liquid", "bounce", "liquidbounce" })]
    [InlineData("NightDLC.jar", new[] { "night", "dlc", "nightdlc" })]
    public void Names_are_read_as_words_and_runs_of_words(string name, string[] contains)
    {
        var p = Matcher.Phrases(name);
        Assert.All(contains, c => Assert.Contains(c, p));
    }
}

public sealed class SignatureCorrelationTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 8, 18, 0, 0, TimeSpan.Zero);
    private const string Jar = @"C:\Users\p\AppData\Roaming\.minecraft\mods\renamed.jar";

    private static EvidenceFacts Fact(EvidenceSourceKind source, EvidenceEventType type, DateTimeOffset? at = null, params (string Key, string Value)[] attrs) =>
        new(Ulid.NewUlid(DateTimeOffset.UtcNow), "m", source, type, at, Jar, PathNormalizer.Normalize(Jar), "renamed.jar", null, 500, 3, null, Confidence.Informational,
            attrs.ToDictionary(a => a.Key, a => a.Value, StringComparer.Ordinal));

    private static CorrelationResult Run(params EvidenceFacts[] facts)
    {
        var matches = new Matcher(DatabaseLoader.Embedded()).Match(facts);
        return new CorrelationEngine(Ulid.NewUlid(T0), T0.AddHours(1), TimeProvider.System).Run(facts, matches);
    }

    [Fact]
    public void A_verified_identification_with_two_other_sources_of_use_is_high()
    {
        var file = Fact(EvidenceSourceKind.FileSystem, EvidenceEventType.Existed, attrs: [("Mod.Id", "wurst"), ("MinecraftRoot", "x")]);
        var loaded = Fact(EvidenceSourceKind.Prefetch, EvidenceEventType.Loaded, T0);
        var deleted = Fact(EvidenceSourceKind.UsnJournal, EvidenceEventType.Deleted, T0.AddMinutes(30));

        var r = Run(file, loaded, deleted);
        var sig = r.Findings.Single(f => f.RuleId == "SIGNATURE_MATCH");
        Assert.Equal(Confidence.Medium, sig.Confidence); // direct identification, one source
        Assert.Equal(SignatureMatchKind.VerifiedComponentMatch, sig.MatchKind);
        Assert.True(sig.VerifiedIdentification);
        Assert.Equal("wurst", sig.ClientId);

        var known = r.Findings.Single(f => f.RuleId == "KNOWN_CLIENT_ACTIVITY");
        Assert.Equal(Confidence.High, known.Confidence);
        Assert.Equal(new[] { "files", "prefetch", "usn" }, known.IndependentFamilies);
        Assert.Empty(known.Validate());
        Assert.Contains("решение о нарушении принимает человек", known.Rationale, StringComparison.Ordinal);

        Assert.Equal(Confidence.Medium, Run(file, loaded).Findings.Single(f => f.RuleId == "KNOWN_CLIENT_ACTIVITY").Confidence);
        Assert.DoesNotContain(Run(file).Findings, f => f.RuleId == "KNOWN_CLIENT_ACTIVITY");
    }

    [Fact]
    public void A_name_match_never_reaches_identification()
    {
        var named = new EvidenceFacts(Ulid.NewUlid(T0), "m", EvidenceSourceKind.FileSystem, EvidenceEventType.Existed, null, @"C:\Users\p\Downloads\wurst.jar",
            PathNormalizer.Normalize(@"C:\Users\p\Downloads\wurst.jar"), "wurst.jar", null, 7, 1, null, Confidence.Informational, new Dictionary<string, string>());
        var loaded = named with { Id = Ulid.NewUlid(T0), Source = EvidenceSourceKind.Prefetch, Type = EvidenceEventType.Loaded, Time = T0 };
        var deleted = named with { Id = Ulid.NewUlid(T0), Source = EvidenceSourceKind.UsnJournal, Type = EvidenceEventType.Deleted, Time = T0.AddMinutes(1) };
        var r = new CorrelationEngine(Ulid.NewUlid(T0), T0, TimeProvider.System).Run([named, loaded, deleted], new Matcher(DatabaseLoader.Embedded()).Match([named, loaded, deleted]));
        var sig = r.Findings.Single(f => f.RuleId == "SIGNATURE_MATCH");
        Assert.Equal(Confidence.Low, sig.Confidence);
        Assert.Equal(SignatureMatchKind.NameMatch, sig.MatchKind);
        Assert.False(sig.VerifiedIdentification);
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "KNOWN_CLIENT_ACTIVITY");
        Assert.DoesNotContain(r.Findings, f => f.Confidence == Confidence.High);
    }
}
