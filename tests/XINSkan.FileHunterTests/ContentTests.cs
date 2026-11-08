using System.IO.Compression;
using System.Text;
using XINSkan.Analyzers.FileHunter.Content;
using XINSkan.Analyzers.FileHunter.Scanning;
using XINSkan.Core.IO;
using XINSkan.FileHunterTests.Support;

namespace XINSkan.FileHunterTests;

public class ContentSnifferTests
{
    [Fact]
    public void Recognises_zip_pe_class_and_empty()
    {
        Assert.Equal(ContentType.Zip, ContentSniffer.Detect(Jar.FabricMod("a", "A", "1"), 100));
        Assert.Equal(ContentType.PortableExecutable, ContentSniffer.Detect(File.ReadAllBytes(typeof(object).Assembly.Location).AsSpan(0, 1024), 1024));
        Assert.Equal(ContentType.JavaClass, ContentSniffer.Detect([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 61], 8));
        Assert.Equal(ContentType.Empty, ContentSniffer.Detect([], 0));
        Assert.Equal(ContentType.Unknown, ContentSniffer.Detect("hello world"u8, 11));
    }

    [Fact]
    public void Mz_without_a_plausible_pe_header_is_not_an_executable()
    {
        var b = new byte[0x80];
        b[0] = (byte)'M';
        b[1] = (byte)'Z';
        BitConverter.GetBytes(-5).CopyTo(b, 0x3C);
        Assert.Equal(ContentType.Unknown, ContentSniffer.Detect(b, b.Length));
    }

    [Theory]
    [InlineData(".JAR", ContentType.Zip)]
    [InlineData(".dll", ContentType.PortableExecutable)]
    [InlineData(".txt", ContentType.Unknown)]
    public void Extension_implies_type(string ext, ContentType expected) => Assert.Equal(expected, ContentSniffer.ImpliedBy(ext));
}

public class ArchiveInspectorTests
{
    private static readonly ArchiveLimits Limits = new();

    private static ArchiveFacts Inspect(byte[] jar, ArchiveLimits? limits = null) => ArchiveInspector.Inspect(new MemoryStream(jar), limits ?? Limits);

    [Fact]
    public void Quilt_and_legacy_forge_descriptors_are_read()
    {
        var quilt = Inspect(Jar.Build(z => z.Text("quilt.mod.json", """{ "quilt_loader": { "id": "qmod", "version": "1.2", "metadata": { "name": "Q Mod" } } }""")));
        Assert.Equal(new ModMetadata("quilt", "qmod", "Q Mod", "1.2", "quilt.mod.json"), Assert.Single(quilt.Mods));

        var legacy = Inspect(Jar.Build(z => z.Text("mcmod.info", """[ { "modid": "old", "name": "Old Mod", "version": "1.7.10" } ]""")));
        Assert.Equal("old", Assert.Single(legacy.Mods).Id);

        var modList = Inspect(Jar.Build(z => z.Text("mcmod.info", """{ "modListVersion": 2, "modList": [ { "modid": "old2" } ] }""")));
        Assert.Equal("old2", Assert.Single(modList.Mods).Id);
    }

    [Fact]
    public void Neoforge_descriptor_is_read()
    {
        var facts = Inspect(Jar.Build(z => z.Text("META-INF/neoforge.mods.toml", "modLoader=\"javafml\"\n[[mods]]\nmodId='neomod'\nversion=\"5\"\n")));
        var m = Assert.Single(facts.Mods);
        Assert.Equal(("neoforge", "neomod", "5"), (m.Loader, m.Id, m.Version));
    }

    [Fact]
    public void Nested_jars_are_inspected_one_level_deep()
    {
        var inner = Jar.FabricMod("inner", "Inner", "1");
        var deeper = Jar.Build(z => z.Bytes("META-INF/jars/deepest.jar", Jar.FabricMod("deepest", "Deepest", "1")));
        var outer = Jar.Build(z =>
        {
            z.Text("fabric.mod.json", """{ "id": "outer" }""");
            z.Bytes("META-INF/jars/inner.jar", inner);
            z.Bytes("META-INF/jarjar/deeper.jar", deeper);
        });

        var facts = Inspect(outer);
        Assert.Equal(new[] { "META-INF/jars/inner.jar", "META-INF/jarjar/deeper.jar" }, facts.NestedJars);
        Assert.Equal(new[] { "inner" }, facts.NestedMods.Select(m => m.Id)); // deeper.jar has no own descriptor; deepest is not reached
    }

    [Fact]
    public void Too_many_entries_are_refused_before_the_archive_is_opened()
    {
        var many = Jar.Build(z =>
        {
            for (var i = 0; i < 150; i++)
            {
                z.Class($"x/C{i}.class");
            }
        });

        var facts = Inspect(many, new ArchiveLimits { MaxEntries = 100 });
        Assert.Equal(150, facts.DeclaredEntries);
        Assert.Equal(0, facts.ClassCount);
        Assert.Contains(facts.Problems, p => p.Contains("не открывался", StringComparison.Ordinal));
    }

    [Fact]
    public void Oversized_descriptor_is_not_read()
    {
        var big = Jar.Build(z => z.Text("fabric.mod.json", "{\"id\":\"x\",\"pad\":\"" + new string('a', 5000) + "\"}"));
        var facts = Inspect(big, new ArchiveLimits { MaxDescriptorBytes = 1000 });
        Assert.Empty(facts.Mods);
        Assert.Contains(facts.Problems, p => p.Contains("не читался", StringComparison.Ordinal));
    }

    [Fact]
    public void Invalid_json_is_reported_not_thrown()
    {
        var facts = Inspect(Jar.Build(z => z.Text("fabric.mod.json", "{ not json")));
        Assert.Empty(facts.Mods);
        Assert.Contains(facts.Problems, p => p.Contains("некорректный JSON", StringComparison.Ordinal));
    }

    [Fact]
    public void Zip64_entry_count_is_read()
    {
        // Small archive written in ZIP64 form: a ZipArchive entry larger than 4 GB is impractical, so build the records by hand.
        var ms = new MemoryStream();
        var eocd64Offset = 0L;
        var w = new BinaryWriter(ms);
        w.Write(0x06064B50u);
        w.Write(44UL);
        w.Write((ushort)45);
        w.Write((ushort)45);
        w.Write(0u);
        w.Write(0u);
        w.Write(7_000_000UL);
        w.Write(7_000_000UL);
        w.Write(0UL);
        w.Write(0UL);
        w.Write(0x07064B50u);
        w.Write(0u);
        w.Write(eocd64Offset);
        w.Write(1u);
        w.Write(0x06054B50u);
        w.Write((ushort)0);
        w.Write((ushort)0);
        w.Write((ushort)0xFFFF);
        w.Write((ushort)0xFFFF);
        w.Write(0xFFFFFFFFu);
        w.Write(0xFFFFFFFFu);
        w.Write((ushort)0);
        Assert.Equal(7_000_000, ArchiveInspector.DeclaredEntryCount(new MemoryStream(ms.ToArray())));
    }

    [Fact]
    public void Corrupted_archives_never_throw()
    {
        var original = Jar.Build(z =>
        {
            z.Text("fabric.mod.json", """{ "id": "fuzz", "name": "Fuzz", "version": "1" }""");
            z.Text("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nMain-Class: a.B\r\n\r\n");
            z.Bytes("META-INF/jars/inner.jar", Jar.FabricMod("inner", "Inner", "1"));
            z.Class("a/b/c/D.class");
        });

        var rnd = new Random(20261109);
        for (var i = 0; i < 2000; i++)
        {
            var m = (byte[])original.Clone();
            switch (i % 3)
            {
                case 0:
                    for (var k = 0; k < 1 + rnd.Next(12); k++)
                    {
                        m[rnd.Next(m.Length)] = (byte)rnd.Next(256);
                    }

                    break;
                case 1:
                    m = m[..rnd.Next(m.Length)];
                    break;
                default:
                    var off = rnd.Next(m.Length - 4);
                    BitConverter.GetBytes(rnd.Next(2) == 0 ? uint.MaxValue : 0x7FFF_FFFFu).CopyTo(m, off);
                    break;
            }

            var facts = ArchiveInspector.Inspect(new MemoryStream(m), Limits);
            Assert.NotNull(facts);
        }
    }
}

public class ManifestAndTomlTests
{
    [Fact]
    public void Manifest_main_section_only_with_continuations()
    {
        var mf = ArchiveInspector.ParseManifest("Manifest-Version: 1.0\nMain-Class: com.example.Very\n LongName\nTweakClass: com.example.Tweaker\n\nName: com/example/\nMain-Class: ignored\n");
        Assert.Equal("com.example.VeryLongName", mf["Main-Class"]);
        Assert.Equal("com.example.Tweaker", mf["TweakClass"]);
        Assert.False(mf.ContainsKey("Manifest-Version"));
    }

    [Fact]
    public void Toml_without_mods_table_is_not_a_mod()
    {
        Assert.Null(ArchiveInspector.ParseModsToml("modLoader=\"javafml\"\n", "forge", "META-INF/mods.toml"));
    }

    [Fact]
    public void Toml_reads_only_the_first_mods_table()
    {
        var m = ArchiveInspector.ParseModsToml("[[mods]]\nmodId=\"first\"\n[[mods]]\nmodId=\"second\"\n", "forge", "x");
        Assert.Equal("first", m!.Id);
    }
}

public class PeInspectorTests
{
    private static readonly byte[] CoreLib = File.ReadAllBytes(typeof(object).Assembly.Location);

    [Fact]
    public void Reads_headers_and_version_resource()
    {
        var pe = PeInspector.Inspect(new MemoryStream(CoreLib));
        Assert.Empty(pe.Problems);
        Assert.True(pe.IsDll);
        Assert.True(pe.IsDotNet);
        Assert.Equal("System.Private.CoreLib.dll", pe.Version["OriginalFilename"]);
        Assert.Equal("Microsoft Corporation", pe.Version["CompanyName"]);
        Assert.Matches(@"^\d+\.\d+\.\d+\.\d+$", pe.FixedFileVersion!);
    }

    [Fact]
    public void Corrupted_executables_never_throw()
    {
        var head = CoreLib[..Math.Min(CoreLib.Length, 256 * 1024)];
        var rnd = new Random(42);
        for (var i = 0; i < 1500; i++)
        {
            var m = (byte[])head.Clone();
            if (i % 2 == 0)
            {
                for (var k = 0; k < 1 + rnd.Next(16); k++)
                {
                    m[rnd.Next(Math.Min(m.Length, 4096))] = (byte)rnd.Next(256);
                }
            }
            else
            {
                m = m[..rnd.Next(64, m.Length)];
            }

            var pe = PeInspector.Inspect(new MemoryStream(m));
            Assert.NotNull(pe);
        }
    }

    [Fact]
    public void Garbage_is_reported_as_unreadable()
    {
        var pe = PeInspector.Inspect(new MemoryStream(Encoding.ASCII.GetBytes("MZ this is not a real executable")));
        Assert.NotEmpty(pe.Problems);
    }
}

public class ZoneInfoTests
{
    [Fact]
    public void Utf16_with_bom_is_parsed()
    {
        var bytes = new byte[] { 0xFF, 0xFE }.Concat(Encoding.Unicode.GetBytes("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://h/x.jar\r\n")).ToArray();
        var z = ZoneInfo.Parse(bytes)!;
        Assert.Equal(3, z.ZoneId);
        Assert.Equal("https://h/x.jar", z.HostUrl);
        Assert.Equal("Интернет", z.ZoneName);
    }

    [Fact]
    public void Keys_outside_the_zone_transfer_section_are_ignored()
    {
        Assert.Null(ZoneInfo.Parse("[Other]\nHostUrl=https://h/\n"u8));
        Assert.Null(ZoneInfo.Parse("garbage"u8));
        Assert.Null(ZoneInfo.Parse([]));
    }
}

public sealed class ScopeAndRelevanceTests : IDisposable
{
    private readonly PlayerProfile _p = new();

    public void Dispose() => _p.Dispose();

    [Fact]
    public void Nested_and_duplicate_roots_are_merged()
    {
        var scope = ScopeBuilder.Build(SystemDirectoryLister.Instance, _p.Users, _p.Player, canReadOtherProfiles: false,
            [_p.WindowsTemp], [_p.P("Downloads"), _p.WindowsTemp, Path.Combine(_p.Root, "missing")]);

        Assert.Equal(new[] { _p.Player, _p.WindowsTemp }, scope.Roots.Select(r => r.Path));
        Assert.Contains(scope.Excluded, x => x.Contains("missing", StringComparison.Ordinal));
    }

    [Fact]
    public void Unreadable_users_folder_falls_back_to_the_current_profile()
    {
        var lister = new FaultyLister(d => d == _p.Users ? new UnauthorizedAccessException("no") : null);
        var scope = ScopeBuilder.Build(lister, _p.Users, _p.Player, canReadOtherProfiles: true, [], []);
        Assert.Equal(_p.Player, Assert.Single(scope.Roots).Path);
        Assert.Contains(scope.Excluded, x => x.Contains("только текущий профиль", StringComparison.Ordinal));
    }

    [Fact]
    public void Minecraft_root_is_recognised_by_name_or_by_markers()
    {
        static FsEntry F(string n, bool dir) => new(n, n, dir, 0, dir ? FileAttributes.Directory : FileAttributes.Normal, default, default, default);

        Assert.True(Relevance.IsMinecraftRoot(".minecraft", []));
        Assert.True(Relevance.IsMinecraftRoot("instance", [F("options.txt", false), F("mods", true)]));
        Assert.False(Relevance.IsMinecraftRoot("instance", [F("options.txt", false)]));
        Assert.False(Relevance.IsMinecraftRoot("instance", [F("mods", true)]));
    }

    [Fact]
    public void Drop_locations_are_relative_to_the_profile()
    {
        var root = new ScopeRoot(_p.Player, RootKind.Profile, "player");
        Assert.True(Relevance.IsDropLocation(root, _p.Player));
        Assert.True(Relevance.IsDropLocation(root, _p.P("Downloads", "sub")));
        Assert.True(Relevance.IsDropLocation(root, _p.P("AppData", "Local", "Temp")));
        Assert.False(Relevance.IsDropLocation(root, _p.P("AppData", "Local")));
        Assert.False(Relevance.IsDropLocation(root, _p.P("DownloadsArchive")));
        Assert.True(Relevance.IsDropLocation(new ScopeRoot(_p.WindowsTemp, RootKind.Temp, null), Path.Combine(_p.WindowsTemp, "x")));
    }
}
