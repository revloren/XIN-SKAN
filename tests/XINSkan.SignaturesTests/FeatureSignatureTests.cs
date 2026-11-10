using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using XINSkan.Analyzers.FileHunter;
using XINSkan.Analyzers.FileHunter.Content;
using XINSkan.Core.Paths;
using XINSkan.Correlation;
using XINSkan.Models;
using XINSkan.Signatures;

namespace XINSkan.SignaturesTests;

public sealed class ClassNameTests
{
    [Theory]
    [InlineData("net/wurstclient/hacks/KillauraHack.class", "killaura")] // Wurst
    [InlineData("net/ccbluex/liquidbounce/features/module/modules/combat/killaura/ModuleKillAura.class", "killaura")] // LiquidBounce
    [InlineData("me/ionar/salhack/module/combat/KillAuraModule.class", "killaura")] // SalHack
    [InlineData("meteordevelopment/meteorclient/systems/modules/combat/KillAura.class", "killaura")] // Meteor
    [InlineData("net/wurstclient/hacks/SpeedHackHack.class", "speedhack")] // one suffix only
    [InlineData(@"a\b\Scaffold.class", "scaffold")]
    public void A_class_entry_reduces_to_its_feature_key(string entry, string key) => Assert.Equal(key, ClassNames.FeatureKey(entry));

    [Theory]
    [InlineData("x/y/KillAura$1.class")] // inner and synthetic classes
    [InlineData("java/util/Timer.class")] // JDK
    [InlineData("java/util/ArrayList.class")]
    [InlineData("net/minecraft/client/gui/hud/Hud.class")] // the game itself
    [InlineData("kotlin/collections/ArrayList.class")]
    [InlineData("x/y/package-info.class")]
    [InlineData("x/y/Ab.class")] // too short to mean anything
    [InlineData("x/y/KillAura.txt")]
    public void Library_inner_and_tiny_classes_have_no_key(string entry) => Assert.Null(ClassNames.FeatureKey(entry));
}

public sealed class FeatureCatalogTests
{
    private static readonly SignatureDatabase Db = DatabaseLoader.Embedded();

    // TZ section 10, as written, by category.
    private static readonly (string Category, string Names)[] Tz =
    [
        ("combat", "KillAura, AimBot, TriggerBot, AutoClicker, Reach, Criticals, Velocity, AntiKnockback, AutoCrystal, CrystalAura, AutoTotem, AutoWeapon, AutoBow, AutoPearl, AutoArmor, AutoPot, FastBow"),
        ("movement", "Fly, Flight, Speed, BHop, LongJump, Step, Spider, NoFall, NoSlow, Jesus, SafeWalk, Scaffold, ElytraFly, Blink, Phase, NoClip"),
        ("visual", "ESP, PlayerESP, EntityESP, ItemESP, ChestESP, StorageESP, BlockESP, XRay, Tracers, Chams, Nametags, FullBright, FreeCam, FreeLook, Radar, HoleESP, Breadcrumbs"),
        ("world", "Baritone, AutoMine, Nuker, AutoBuild, AutoFarm, AutoFish, AutoTool, ChestStealer, FastBreak, VeinMiner, AutoWalk"),
        ("player", "AutoEat, AutoRespawn, AntiAFK, AutoReconnect, AutoLog, Regen, InventoryMove, FastUse"),
        ("misc", "ClickGUI, HUD, ArrayList, Friends, AntiBlind, NoHurtCam, NoSwing, Timer, DiscordRPC, CustomKeybinds"),
    ];

    [Fact]
    public void Every_feature_of_the_customer_list_is_in_the_catalog_with_its_category()
    {
        Assert.DoesNotContain(Db.Problems, p => p.StartsWith("Функция", StringComparison.Ordinal));
        var fromList = Db.Features.Where(f => f.List == "10").ToList();
        Assert.Equal(Tz.SelectMany(t => t.Names.Split(", ")), fromList.Select(f => f.Name));
        foreach (var (category, names) in Tz)
        {
            Assert.All(names.Split(", "), n => Assert.Equal(category, fromList.Single(f => f.Name == n).Category));
        }

        // Not found in any verified project's source: they stay unverified, with the customer's list as their only source.
        Assert.Equal(new[] { "FastBow", "BHop", "Regen", "ArrayList", "CustomKeybinds" }, Db.Features.Where(f => f.Status != "verified").Select(f => f.Name));
        Assert.All(Db.Features.Where(f => f.Status != "verified"), f => Assert.Empty(f.Projects));
    }

    [Fact]
    public void A_verified_feature_names_the_projects_and_source_files_it_was_found_in()
    {
        var verifiedClients = Db.Clients.Where(c => c.Status == "verified").Select(c => c.Id).ToHashSet();
        Assert.All(Db.Features.Where(f => f.Status == "verified"), f =>
        {
            Assert.NotEmpty(f.Projects);
            Assert.All(f.Projects, p => Assert.Contains(p.Client, verifiedClients));
            Assert.All(f.Projects, p => Assert.Contains(p.Module, p.Path, StringComparison.Ordinal));
            Assert.Contains(f.Sources, s => s.Url?.StartsWith("https://github.com/", StringComparison.Ordinal) == true && s.Commit is { Length: 40 });
        });

        var killaura = Db.Features.Single(f => f.Name == "KillAura");
        Assert.Equal(new[] { "3arthh4ck", "bleachhack", "kami-blue", "liquidbounce", "meteor", "salhack", "wurst" }, killaura.Projects.Select(p => p.Client).Distinct());
        Assert.Contains("Killaura", killaura.Variants); // Wurst's spelling
        Assert.Contains("AutoPotion", Db.Features.Single(f => f.Name == "AutoPot").Variants);

        // Added from the projects themselves, each in at least four of them.
        var research = Db.Features.Where(f => f.List == "research").ToList();
        Assert.Equal(18, research.Count);
        Assert.All(research, f => Assert.True(f.Projects.Select(p => p.Client).Distinct().Count() >= 4, f.Name));
    }

    [Fact]
    public void Ordinary_words_are_weak_features()
    {
        string Strength(string name) => Db.Features.Single(f => f.Name == name).Strength;
        Assert.All(new[] { "KillAura", "Scaffold", "XRay", "NoFall", "Nuker", "InventoryMove", "AutoCrystal" }, n => Assert.Equal("strong", Strength(n)));
        Assert.All(new[] { "Timer", "ArrayList", "HUD", "Velocity", "Speed", "Fly", "FreeCam", "FullBright", "Radar", "Zoom", "Sprint", "Baritone" }, n => Assert.Equal("weak", Strength(n)));
        Assert.Contains("java.util", Db.Features.Single(f => f.Name == "ArrayList").Note, StringComparison.Ordinal);
    }

    [Fact]
    public void Feature_records_that_break_the_rules_are_dropped()
    {
        var src = new { title = "src", url = "https://github.com/x/y", commit = new string('a', 40), @checked = "2026-11-10" };
        var db = Bundle.Load(Bundle.Make("1", new[] { Bundle.Client("wurst", modIds: ["wurst"]) }, features: new object[]
        {
            new { id = "killaura", name = "KillAura", category = "combat", variants = new[] { "KillAura" }, strength = "strong", status = "verified", list = "10", projects = new[] { new { client = "wurst", module = "Killaura", path = "a/KillauraHack.java" } }, sources = new[] { src } },
            new { id = "noproject", name = "NoFall", category = "movement", variants = new[] { "NoFall" }, strength = "strong", status = "verified", list = "10", projects = Array.Empty<object>(), sources = new[] { src } },
            new { id = "clash", name = "Kill-Aura", category = "combat", variants = new[] { "Kill-Aura" }, strength = "strong", status = "user-list", list = "10", projects = Array.Empty<object>(), sources = new[] { src } },
            new { id = "made-up", name = "Ghost", category = "misc", variants = new[] { "Ghost" }, strength = "weak", status = "user-list", list = "research", projects = Array.Empty<object>(), sources = new[] { src } },
            new { id = "stranger", name = "Reach", category = "combat", variants = new[] { "Reach" }, strength = "strong", status = "verified", list = "10", projects = new[] { new { client = "unknown", module = "Reach", path = "a/Reach.java" } }, sources = new[] { src } },
        }));
        Assert.Equal(new[] { "killaura" }, db.Features.Select(f => f.Id));
        Assert.Contains(db.Problems, p => p.Contains("noproject", StringComparison.Ordinal));
        Assert.Contains(db.Problems, p => p.Contains("clash", StringComparison.Ordinal) && p.Contains("killaura", StringComparison.Ordinal));
        Assert.Contains(db.Problems, p => p.Contains("made-up", StringComparison.Ordinal));
        Assert.Contains(db.Problems, p => p.Contains("stranger", StringComparison.Ordinal));
    }
}

public sealed class FeatureMatchTests
{
    private static readonly SignatureDatabase Db = DatabaseLoader.Embedded();
    private static readonly Matcher Builtin = new(Db);
    private const string Mods = @"C:\Users\p\AppData\Roaming\.minecraft\mods\";

    internal static EvidenceFacts Jar(string path, params (string Key, string Value)[] attrs) =>
        new(Ulid.NewUlid(DateTimeOffset.UtcNow), "m", EvidenceSourceKind.FileSystem, EvidenceEventType.Existed, null, path, PathNormalizer.Normalize(path),
            path[(path.LastIndexOf('\\') + 1)..], null, 1000, 5, null, Confidence.Informational, attrs.ToDictionary(a => a.Key, a => a.Value, StringComparer.Ordinal));

    private static SignatureMatch? Features(EvidenceFacts f) => Builtin.Match([f]).SingleOrDefault(m => m.ClientId == "feature-set");

    [Fact]
    public void Strong_features_from_several_categories_in_one_jar_are_a_multiple_feature_match()
    {
        var jar = Jar(Mods + "optimization.jar", ("Jar.FeatureClasses",
            "com/x/m/combat/KillAura, com/x/m/combat/Reach, com/x/m/movement/Scaffold, com/x/m/render/XRay, com/x/util/Timer, com/x/gui/Hud"));
        var m = Features(jar)!;
        Assert.Equal(SignatureMatchKind.MultipleFeatureMatch, m.Kind);
        Assert.Equal("KillAura, Reach, Scaffold, XRay, HUD, Timer", m.Matched);
        Assert.Contains("Сильных признаков 4 из 3 категорий, слабых 2", m.Detail, StringComparison.Ordinal);
        Assert.Contains("сходство набора, а не опознание", m.Detail, StringComparison.Ordinal);
        Assert.Equal("verified", m.EntryStatus);
    }

    [Fact]
    public void A_server_plugin_with_the_same_names_is_only_a_possible_match()
    {
        // Anti-cheat plugins name their checks after the cheats they detect.
        var plugin = Jar(@"C:\Server\plugins\anticheat.jar", ("Jar.FeatureClasses", "com/ac/KillAura, com/ac/Reach, com/ac/Scaffold, com/ac/NoFall"), ("Jar.ServerPlugin", "plugin.yml"));
        var m = Features(plugin)!;
        Assert.Equal(SignatureMatchKind.PossibleMatch, m.Kind);
        Assert.Contains("серверный плагин", m.Detail, StringComparison.Ordinal);

        var checks = Jar(Mods + "ac.jar", ("Jar.FeatureClasses", "ac/grim/checks/impl/combat/KillAura, ac/grim/checks/impl/combat/Reach, ac/grim/checks/impl/movement/NoFall, ac/grim/checks/impl/scaffolding/Scaffold"));
        Assert.Null(Features(checks)); // every class is a check
    }

    [Theory]
    [InlineData("com/m/Timer, com/m/Hud, com/m/Zoom, com/m/FreeCam, com/m/Radar, com/m/FullBright, com/m/Sprint")] // weak only: a utility mod
    [InlineData("com/m/KillAura")] // one strong
    [InlineData("com/m/KillAura, com/m/Timer")] // one strong, one weak
    public void Ordinary_and_lone_names_are_not_a_match(string classes) => Assert.Null(Features(Jar(Mods + "util.jar", ("Jar.FeatureClasses", classes))));

    [Theory]
    [InlineData("com/m/KillAura, com/m/Reach")] // two strong
    [InlineData("com/m/KillAura, com/m/Reach, com/m/Criticals")] // three strong, one category
    [InlineData("com/m/Scaffold, com/m/Timer, com/m/Hud")] // one strong, two weak
    public void Fewer_strong_features_are_only_possible(string classes) =>
        Assert.Equal(SignatureMatchKind.PossibleMatch, Features(Jar(Mods + "x.jar", ("Jar.FeatureClasses", classes)))!.Kind);

    [Theory]
    [InlineData(@"C:\Users\p\AppData\Roaming\.minecraft\wurst\enabled-hacks.json", "wurst", SignatureMatchKind.VerifiedComponentMatch)]
    [InlineData(@"C:\Users\p\AppData\Roaming\PrismLauncher\instances\pvp\minecraft\meteor-client\modules.nbt", "meteor", SignatureMatchKind.VerifiedComponentMatch)]
    [InlineData(@"C:\Users\p\AppData\Roaming\.minecraft\LiquidBounce\modules.json", "liquidbounce", SignatureMatchKind.VerifiedComponentMatch)]
    [InlineData(@"C:\Users\p\AppData\Roaming\.minecraft\SalHack\Modules\KillAura.json", "salhack", SignatureMatchKind.VerifiedComponentMatch)] // inside a data folder
    [InlineData(@"C:\Users\p\AppData\Roaming\.minecraft\baritone\settings.txt", "baritone", SignatureMatchKind.VerifiedComponentMatch)]
    [InlineData(@"D:\backup\wurst\enabled-hacks.json", "wurst", SignatureMatchKind.NameMatch)] // not in a game folder
    public void Files_the_client_writes_in_the_game_folder_identify_it(string path, string client, SignatureMatchKind kind)
    {
        var f = new EvidenceFacts(Ulid.NewUlid(DateTimeOffset.UtcNow), "m", EvidenceSourceKind.UsnJournal, EvidenceEventType.Created, null, path, PathNormalizer.Normalize(path),
            path[(path.LastIndexOf('\\') + 1)..], null, null, null, null, Confidence.Informational, new Dictionary<string, string>());
        var m = Builtin.Match([f]).Single(x => x.ClientId == client);
        Assert.Equal(kind, m.Kind);
    }

    [Fact]
    public void A_game_folder_named_by_the_file_hunter_counts_as_a_game_folder()
    {
        var f = Jar(@"E:\Games\MyPack\wurst\enabled-hacks.json", ("MinecraftRoot", @"E:\Games\MyPack"));
        Assert.Equal(SignatureMatchKind.VerifiedComponentMatch, Builtin.Match([f]).Single(x => x.ClientId == "wurst").Kind);
        Assert.DoesNotContain(Builtin.Match([Jar(@"C:\Users\p\AppData\Roaming\.minecraft\wurst\enabled-hacks.json.bak")]), x => x.ClientId == "wurst");
    }
}

public sealed class FeatureArchiveTests
{
    private static byte[] MakeJar(params string[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var e in entries)
            {
                using var w = zip.CreateEntry(e).Open();
                w.Write(Encoding.ASCII.GetBytes(e.EndsWith(".yml", StringComparison.Ordinal) ? "name: x\nmain: a.B\n" : "\u00ca\u00fe"));
            }
        }

        return ms.ToArray();
    }

    [Fact]
    public void The_archive_reader_keeps_only_classes_named_after_catalog_features()
    {
        var vocabulary = DatabaseLoader.Embedded().FeatureVocabulary;
        Assert.Contains("killaura", vocabulary);
        Assert.Contains("autopotion", vocabulary);

        var jar = MakeJar(
            "meteordevelopment/meteorclient/systems/modules/combat/KillAura.class",
            "meteordevelopment/meteorclient/systems/modules/combat/KillAura$Mode.class",
            "meteordevelopment/meteorclient/systems/modules/movement/Scaffold.class",
            "meteordevelopment/meteorclient/systems/modules/render/Xray.class",
            "meteordevelopment/meteorclient/utils/Utils.class",
            "java/util/Timer.class",
            "fabric.mod.json");
        var facts = ArchiveInspector.Inspect(new MemoryStream(jar), new ArchiveLimits { FeatureVocabulary = vocabulary });
        Assert.Equal(new[]
        {
            "meteordevelopment/meteorclient/systems/modules/combat/KillAura",
            "meteordevelopment/meteorclient/systems/modules/movement/Scaffold",
            "meteordevelopment/meteorclient/systems/modules/render/Xray",
        }, facts.FeatureClasses);
        Assert.Null(facts.ServerPlugin);

        // Without a vocabulary nothing is collected; a cap is stated.
        Assert.Empty(ArchiveInspector.Inspect(new MemoryStream(jar), new ArchiveLimits()).FeatureClasses);
        var capped = ArchiveInspector.Inspect(new MemoryStream(jar), new ArchiveLimits { FeatureVocabulary = vocabulary, MaxFeatureClasses = 1 });
        Assert.Single(capped.FeatureClasses);
        Assert.Contains(capped.Problems, p => p.Contains("записаны первые 1", StringComparison.Ordinal));
    }

    [Fact]
    public void A_server_plugin_descriptor_is_recorded()
    {
        var facts = ArchiveInspector.Inspect(new MemoryStream(MakeJar("plugin.yml", "ac/checks/KillAura.class")), new ArchiveLimits { FeatureVocabulary = DatabaseLoader.Embedded().FeatureVocabulary });
        Assert.Equal("plugin.yml", facts.ServerPlugin);
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal);
        FileHunterAnalyzer.AddArchiveAttributes(attrs, facts);
        Assert.Equal("plugin.yml", attrs["Jar.ServerPlugin"]);
        Assert.Equal("ac/checks/KillAura", attrs["Jar.FeatureClasses"]);
    }
}

public sealed class FeatureCorrelationTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 8, 18, 0, 0, TimeSpan.Zero);
    private const string Path = @"C:\Users\p\AppData\Roaming\.minecraft\mods\fps-boost.jar";

    private static EvidenceFacts Fact(EvidenceSourceKind source, EvidenceEventType type, DateTimeOffset? at, params (string Key, string Value)[] attrs) =>
        new(Ulid.NewUlid(DateTimeOffset.UtcNow), "m", source, type, at, Path, PathNormalizer.Normalize(Path), "fps-boost.jar", null, 700, 2, null, Confidence.Informational,
            attrs.ToDictionary(a => a.Key, a => a.Value, StringComparer.Ordinal));

    [Fact]
    public void A_loaded_jar_with_a_feature_set_is_medium_and_never_high()
    {
        var jar = Fact(EvidenceSourceKind.FileSystem, EvidenceEventType.Existed, null, ("Jar.FeatureClasses", "a/KillAura, a/Reach, a/Scaffold, a/Xray"), ("MinecraftRoot", "x"));
        var loaded = Fact(EvidenceSourceKind.Prefetch, EvidenceEventType.Loaded, T0);
        var deleted = Fact(EvidenceSourceKind.UsnJournal, EvidenceEventType.Deleted, T0.AddMinutes(5));
        var facts = new[] { jar, loaded, deleted };
        var r = new CorrelationEngine(Ulid.NewUlid(T0), T0.AddHours(1), TimeProvider.System).Run(facts, new Matcher(DatabaseLoader.Embedded()).Match(facts));

        var sig = r.Findings.Single(f => f.RuleId == "SIGNATURE_MATCH" && f.ClientId == "feature-set");
        Assert.Equal(Confidence.Low, sig.Confidence);
        Assert.Equal(SignatureMatchKind.MultipleFeatureMatch, sig.MatchKind);
        Assert.False(sig.VerifiedIdentification);
        Assert.Contains("поисковые признаки", sig.Rationale, StringComparison.Ordinal);

        var loadedSet = r.Findings.Single(f => f.RuleId == "FEATURE_SET_LOADED");
        Assert.Equal(Confidence.Medium, loadedSet.Confidence);
        Assert.Empty(loadedSet.Validate());
        Assert.DoesNotContain(r.Findings, f => f.Confidence == Confidence.High || f.RuleId == "KNOWN_CLIENT_ACTIVITY");

        // Without a load there is nothing more than the Low match.
        var alone = new CorrelationEngine(Ulid.NewUlid(T0), T0.AddHours(1), TimeProvider.System).Run([jar], new Matcher(DatabaseLoader.Embedded()).Match([jar]));
        Assert.DoesNotContain(alone.Findings, f => f.RuleId == "FEATURE_SET_LOADED");
    }
}

/// <summary>Skipped without XINSKAN_CLIENT_SAMPLES unless XINSKAN_REQUIRE_SAMPLES=1.</summary>
public sealed class ClientSampleFactAttribute : FactAttribute
{
    public ClientSampleFactAttribute()
    {
        if (Root is null && Environment.GetEnvironmentVariable("XINSKAN_REQUIRE_SAMPLES") != "1")
        {
            Skip = "XINSKAN_CLIENT_SAMPLES is not set.";
        }
    }

    public static string? Root => Environment.GetEnvironmentVariable("XINSKAN_CLIENT_SAMPLES") is { Length: > 0 } p ? p : null;
}

/// <summary>
/// Real release files (CI downloads them from the projects' GitHub releases into "cheat" and "legit" folders): the
/// whole path File Hunter takes — archive reader with the feature vocabulary, record attributes, matcher.
/// </summary>
public sealed class RealClientJarTests(ITestOutputHelper output)
{
    private static (EvidenceFacts Fact, IReadOnlyList<SignatureMatch> Matches) Read(string file, SignatureDatabase db)
    {
        var bytes = File.ReadAllBytes(file);
        var facts = ArchiveInspector.Inspect(new MemoryStream(bytes), new ArchiveLimits { FeatureVocabulary = db.FeatureVocabulary });
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal) { ["MinecraftRoot"] = "samples" };
        FileHunterAnalyzer.AddArchiveAttributes(attrs, facts);
        var path = @"C:\Users\p\AppData\Roaming\.minecraft\mods\" + System.IO.Path.GetFileName(file);
        var f = new EvidenceFacts(Ulid.NewUlid(DateTimeOffset.UtcNow), "file-hunter", EvidenceSourceKind.FileSystem, EvidenceEventType.Existed, null, path,
            PathNormalizer.Normalize(path), System.IO.Path.GetFileName(file), null, null, null, Sha256Hash.FromBytes(SHA256.HashData(bytes)), Confidence.Informational, attrs);
        return (f, new Matcher(db).Match([f]));
    }

    [ClientSampleFact]
    public void Release_jars_of_cheat_clients_are_identified_and_legitimate_mods_are_not()
    {
        var root = ClientSampleFactAttribute.Root ?? throw new InvalidOperationException("XINSKAN_CLIENT_SAMPLES is required.");
        var db = DatabaseLoader.Embedded();
        var cheats = Directory.GetFiles(Path.Combine(root, "cheat"), "*.jar");
        Assert.NotEmpty(cheats);
        var featureSets = 0;
        foreach (var file in cheats)
        {
            var (fact, matches) = Read(file, db);
            output.WriteLine($"{System.IO.Path.GetFileName(file)}: {string.Join("; ", matches.Select(m => $"{m.ClientId} {m.Kind} [{m.Matched}]"))}");
            output.WriteLine($"  классы функций: {fact.Attr("Jar.FeatureClasses")?.Split(", ").Length ?? 0}");
            Assert.Contains(matches, m => m.Kind == SignatureMatchKind.ExactHashMatch); // these very files are in hashes.json
            featureSets += matches.Count(m => m.Kind == SignatureMatchKind.MultipleFeatureMatch);
        }

        Assert.True(featureSets >= 2, $"Multiple Feature Match only in {featureSets} of {cheats.Length} release files.");

        var legit = Directory.Exists(Path.Combine(root, "legit")) ? Directory.GetFiles(Path.Combine(root, "legit"), "*.jar") : [];
        foreach (var file in legit)
        {
            var (fact, matches) = Read(file, db);
            output.WriteLine($"{System.IO.Path.GetFileName(file)} (легальный): {string.Join("; ", matches.Select(m => $"{m.ClientId} {m.Kind} [{m.Matched}]"))}; сервер: {fact.Attr("Jar.ServerPlugin") ?? "-"}");
            Assert.DoesNotContain(matches, m => m.Kind is SignatureMatchKind.ExactHashMatch or SignatureMatchKind.VerifiedComponentMatch or SignatureMatchKind.MultipleFeatureMatch);
        }
    }
}
