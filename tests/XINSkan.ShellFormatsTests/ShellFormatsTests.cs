using System.Buffers.Binary;
using XINSkan.ShellFormats;

namespace XINSkan.ShellFormatsTests;

public sealed class ShellItemTests
{
    private static readonly DateTime T = new(2026, 11, 8, 10, 20, 30, DateTimeKind.Utc);

    [Theory]
    [InlineData(3)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    public void File_entries_give_long_name_times_and_mft_reference_for_every_block_version(int version)
    {
        var item = ShellItemParser.Parse(ShellBuilders.Entry("CHEATC~1.JAR", "cheat client.jar", folder: false, T, version, mftEntry: 0x1_0000_0042, mftSeq: 7, size: 5000));

        Assert.Equal(ShellItemKind.File, item.Kind);
        Assert.Equal("cheat client.jar", item.Name);
        Assert.Equal("CHEATC~1.JAR", item.ShortName);
        Assert.Equal(5000u, item.Size);
        Assert.Equal(new DateTimeOffset(T), item.Modified);
        Assert.Equal(new DateTimeOffset(T.AddDays(-3)), item.Created);
        Assert.Equal(new DateTimeOffset(T), item.Accessed);
        Assert.Equal(version >= 7 ? 0x1_0000_0042UL : null, item.MftEntry);
        Assert.Equal(version >= 7 ? (ushort)7 : null, item.MftSequence);
        Assert.Null(item.Problem);
    }

    [Fact]
    public void An_id_list_becomes_a_drive_path()
    {
        var list = ShellBuilders.IdList(
            ShellBuilders.Root(new Guid("20D04FE0-3AEA-1069-A2D8-08002B30309D")),
            ShellBuilders.Volume('E'),
            ShellBuilders.Entry("CHEATS", "cheats", true, T),
            ShellBuilders.Entry("WURST~1.JAR", "wurst-client.jar", false, T));
        var items = ShellItemParser.ParseList(list, out var problem);
        Assert.Null(problem);
        Assert.Equal(@"E:\cheats\wurst-client.jar", ShellItemParser.ToPath(items));
    }

    [Fact]
    public void Known_folders_have_names_and_unknown_ones_their_guid()
    {
        Assert.Equal("Корзина", ShellItemParser.Parse(ShellBuilders.Root(new Guid("645FF040-5081-101B-9F08-00AA002F954E"))).Name);
        var unknown = Guid.NewGuid();
        Assert.Equal("{" + unknown + "}", ShellItemParser.Parse(ShellBuilders.Root(unknown)).Name);
    }

    [Fact]
    public void Impossible_dos_times_are_not_converted()
    {
        Assert.Null(ShellItemParser.DosTime([0, 0, 0, 0]));
        Assert.Null(ShellItemParser.DosTime([0xFF, 0xFF, 0xFF, 0xFF]));
    }

    [Fact]
    public void Damaged_lists_stop_with_a_reason()
    {
        var list = ShellBuilders.IdList(ShellBuilders.Volume('C'));
        BinaryPrimitives.WriteUInt16LittleEndian(list, 500);
        _ = ShellItemParser.ParseList(list, out var problem);
        Assert.NotNull(problem);
    }

    [Fact]
    public void Random_damage_never_throws_and_allocates_little()
    {
        var seed = ShellBuilders.Entry("CHEATC~1.JAR", "cheat client.jar", false, T, 9, 42, 3);
        var rng = new Random(11);
        long max = 0;
        for (var i = 0; i < 20_000; i++)
        {
            var b = (byte[])seed.Clone();
            for (var m = 0; m < 6; m++)
            {
                b[rng.Next(b.Length)] = (byte)rng.Next(256);
            }

            var before = GC.GetAllocatedBytesForCurrentThread();
            _ = ShellItemParser.Parse(b);
            max = Math.Max(max, GC.GetAllocatedBytesForCurrentThread() - before);
        }

        Assert.True(max < 64 * 1024, $"one damaged item allocated {max} bytes");
    }
}

public sealed class LnkTests
{
    [Fact]
    public void A_link_to_a_jar_on_a_usb_drive_gives_path_drive_and_arguments()
    {
        var bytes = ShellBuilders.Link(@"E:\cheats\wurst-client.jar", driveType: 2, serial: 0xA1B2C3D4, label: "KINGSTON", arguments: "-jar x");
        var l = LnkFile.Parse(bytes)!;
        Assert.Empty(l.Problems);
        Assert.Equal(@"E:\cheats\wurst-client.jar", l.TargetPath);
        Assert.Equal((2u, 0xA1B2C3D4u, "KINGSTON"), (l.DriveType!.Value, l.DriveSerial!.Value, l.VolumeLabel));
        Assert.Equal("-jar x", l.Arguments);
        Assert.Equal(4321u, l.TargetSize);
    }

    [Fact]
    public void Without_link_info_the_id_list_gives_the_path_and_the_mft_reference()
    {
        var ids = ShellBuilders.IdList(ShellBuilders.Volume('C'), ShellBuilders.Entry("GAMES", "Games", true, DateTime.UtcNow),
            ShellBuilders.Entry("CLIENT~1.JAR", "client.jar", false, DateTime.UtcNow, 9, 1234, 5));
        var bytes = ShellBuilders.Link(@"", 3, 1, "X", ids);
        var l = LnkFile.Parse(bytes)!;
        Assert.Equal(@"C:\Games\client.jar", ShellItemParser.ToPath(l.TargetIdList));
        Assert.Equal((1234UL, (ushort)5), (l.TargetItem!.MftEntry!.Value, l.TargetItem.MftSequence!.Value));
    }

    [Fact]
    public void Not_a_link_is_null_and_damage_never_throws()
    {
        Assert.Null(LnkFile.Parse(new byte[100]));
        var seed = ShellBuilders.Link(@"E:\x.jar", 2, 1, "L", ShellBuilders.IdList(ShellBuilders.Volume('E')), "args");
        var rng = new Random(9);
        long max = 0;
        for (var i = 0; i < 20_000; i++)
        {
            var b = (byte[])seed.Clone();
            for (var m = 0; m < 8; m++)
            {
                b[76 + rng.Next(b.Length - 76)] = (byte)rng.Next(256);
            }

            var before = GC.GetAllocatedBytesForCurrentThread();
            _ = LnkFile.Parse(b)?.TargetPath;
            max = Math.Max(max, GC.GetAllocatedBytesForCurrentThread() - before);
        }

        Assert.True(max < 256 * 1024, $"one damaged link allocated {max} bytes");
    }
}

/// <summary>
/// Real links and Jump Lists from Windows XP to 11 (the Lnk and JumpList libraries' test corpora at the reviewed
/// commits). Expected values are those the libraries' own tests assert.
/// </summary>
public sealed class ShellReferenceSampleTests
{
    private static string File(params string[] parts) => ShellSampleFactAttribute.File(parts);

    [ShellSampleFact]
    public void Every_link_of_the_corpus_parses_without_problems_and_with_little_memory()
    {
        var files = Directory.GetFiles(File("Lnk", "Lnk.Test", "TestFiles"), "*", SearchOption.AllDirectories);
        int parsed = 0, notLinks = 0;
        long maxAlloc = 0;
        foreach (var f in files)
        {
            var bytes = System.IO.File.ReadAllBytes(f);
            var before = GC.GetAllocatedBytesForCurrentThread();
            var l = LnkFile.Parse(bytes);
            maxAlloc = Math.Max(maxAlloc, GC.GetAllocatedBytesForCurrentThread() - before);
            if (l is null)
            {
                notLinks++;
                continue;
            }

            parsed++;
            Assert.True(l.Problems.Count == 0, $"{f}: {string.Join("; ", l.Problems)}");
        }

        Assert.True(parsed >= 1000, $"{parsed} links parsed");
        Assert.True(notLinks <= 3, $"{notLinks} files were not recognised as links");
        Assert.True(maxAlloc < 1024 * 1024, $"one link allocated {maxAlloc} bytes");
    }

    [ShellSampleFact]
    public void Windows_7_directory_link_values()
    {
        var l = LnkFile.Parse(System.IO.File.ReadAllBytes(File("Lnk", "Lnk.Test", "TestFiles", "Misc", "local.directory.seven.test")))!;
        Assert.Equal(@"..\..\Administrator", l.RelativePath);
        Assert.Equal((3u, 0x502E1A8Au, "SSD-WIN7", @"C:\Users\"), (l.DriveType!.Value, l.DriveSerial!.Value, l.VolumeLabel, l.LocalBasePath));
        Assert.Equal("netbook", l.Tracker!.MachineId);
        Assert.Equal(new Guid("4f7c66da-d320-4cc4-8d50-165dd98ebc01"), l.Tracker.VolumeDroid);
        Assert.Equal(new Guid("136502ff-8c66-11df-b6eb-001377d34a59"), l.Tracker.FileDroid);
        Assert.Equal("00:13:77:d3:4a:59", l.Tracker.MacAddress);
        Assert.Equal((2010, 7, 10, 20), (l.Tracker.ObjectIdCreated!.Value.Year, l.Tracker.ObjectIdCreated.Value.Month, l.Tracker.ObjectIdCreated.Value.Day, l.Tracker.ObjectIdCreated.Value.Hour));
    }

    [ShellSampleFact]
    public void Windows_xp_network_link_values()
    {
        var l = LnkFile.Parse(System.IO.File.ReadAllBytes(File("Lnk", "Lnk.Test", "TestFiles", "Misc", "remote.file.xp.test")))!;
        Assert.Null(l.LocalBasePath);
        Assert.Equal(@"\\ALS-FICHIERS3\QUALITÉ", l.NetName);
        Assert.Equal(@"Archives\Méthodologie WAS\Norme de développement JAVA.doc", l.CommonPathSuffix);
        Assert.Equal("als-fichiers3", l.Tracker!.MachineId);
        Assert.Equal("00:0f:1f:f7:c0:dc", l.Tracker.MacAddress);
        Assert.Equal(new DateTime(2006, 2, 8, 7, 52, 55), l.Tracker.ObjectIdCreated!.Value.UtcDateTime.AddTicks(-(l.Tracker.ObjectIdCreated.Value.UtcDateTime.Ticks % TimeSpan.TicksPerSecond)));
        Assert.Equal("Norme de développement JAVA.doc", l.TargetItem!.Name);
        Assert.Null(l.TargetItem.MftEntry);
    }

    [ShellSampleTheory]
    [InlineData("Win10", "5f7b5f1e01b83767", 0, 0, 0)]
    [InlineData("Win10", "7e4dca80246863e3", 1, 0, 3)]
    [InlineData("Win10", "f01b4d95cf55d32a", 9, 4, 3)]
    [InlineData("Win7", "1b4dd67f29cb1962", 4, 0, 1)]
    [InlineData("Win80", "f01b4d95cf55d32a", 4, 0, 1)]
    [InlineData("Win81", "f01b4d95cf55d32a", 4, 0, 1)]
    [InlineData("dtformats", "1b4dd67f29cb1962", 7, 0, 1)]
    [InlineData("dtformats", "9d1f905ce5044aee", 2, 0, 3)]
    public void Automatic_destinations_counts_and_versions(string folder, string appId, int entries, int pinned, int version)
    {
        var a = AutomaticDestinations.Parse(System.IO.File.ReadAllBytes(File("JumpList", "JumpList.Test", "TestFiles", folder, appId + ".automaticDestinations-ms")), out var problem)!;
        Assert.Null(problem);
        Assert.Empty(a.Problems);
        Assert.Equal((entries, pinned, version), (a.Entries.Count, a.Entries.Count(e => e.Pinned), a.Version));
        Assert.All(a.Entries, e => Assert.NotNull(e.Lnk));
        Assert.All(a.Entries, e => Assert.Empty(e.Lnk!.Problems));
    }

    [ShellSampleFact]
    public void Windows_10_explorer_jump_list_entry_values()
    {
        var a = AutomaticDestinations.Parse(System.IO.File.ReadAllBytes(File("JumpList", "JumpList.Test", "TestFiles", "Win10", "f01b4d95cf55d32a.automaticDestinations-ms")), out _)!;
        Assert.Equal(new[] { 7, 9, 8, 1, 2, 6, 5, 4, 3 }, a.Entries.Select(e => e.EntryNumber));
        var first = a.Entries[0];
        Assert.Equal((@"C:\Temp", "desktop-annfp9d", "00:15:5d:01:6d:02", 2, false), (first.Path, first.Hostname, first.Droids.MacAddress, first.InteractionCount!.Value, first.Pinned));
        Assert.Equal(DateTimeOffset.Parse("2015-11-24T18:39:02.4912714+00:00", System.Globalization.CultureInfo.InvariantCulture), first.Droids.ObjectIdCreated);
        Assert.Equal(DateTimeOffset.Parse("2015-11-24T20:31:34.4475253+00:00", System.Globalization.CultureInfo.InvariantCulture), DateTimeOffset.FromFileTime(first.LastModified).ToUniversalTime());
        Assert.Equal(@"C:\Temp", first.Lnk!.LocalBasePath);
        Assert.Contains(a.Entries, e => e.Pinned && e.Path == @"C:\Users\e\Desktop");
    }

    [ShellSampleFact]
    public void Custom_destinations_links()
    {
        var links = CustomDestinations.Parse(System.IO.File.ReadAllBytes(File("JumpList", "JumpList.Test", "TestFiles", "dtformats", "5afe4de1b92fc382.customDestinations-ms")));
        Assert.Equal(9, links.Count);
        Assert.All(links, l => Assert.Equal(@"C:\Windows\System32\GettingStarted.exe", l.LocalBasePath));
    }

    [ShellSampleFact]
    public void Damaged_jump_lists_never_throw()
    {
        var seed = System.IO.File.ReadAllBytes(File("JumpList", "JumpList.Test", "TestFiles", "Win10", "f01b4d95cf55d32a.automaticDestinations-ms"));
        var rng = new Random(21);
        for (var i = 0; i < 1500; i++)
        {
            var b = (byte[])seed.Clone();
            for (var m = 0; m < 20; m++)
            {
                b[rng.Next(b.Length)] = (byte)rng.Next(256);
            }

            _ = AutomaticDestinations.Parse(b, out _);
            _ = AutomaticDestinations.Parse(b[..rng.Next(b.Length)], out _);
        }
    }
}

/// <summary>Skipped without XINSKAN_SHELL_SAMPLES unless XINSKAN_REQUIRE_SAMPLES=1.</summary>
public sealed class ShellSampleFactAttribute : FactAttribute
{
    public ShellSampleFactAttribute()
    {
        if (Root is null && Environment.GetEnvironmentVariable("XINSKAN_REQUIRE_SAMPLES") != "1")
        {
            Skip = "XINSKAN_SHELL_SAMPLES is not set.";
        }
    }

    public static string? Root => Environment.GetEnvironmentVariable("XINSKAN_SHELL_SAMPLES") is { Length: > 0 } p ? p : null;

    public static string File(params string[] parts) => Path.Combine([Root ?? throw new InvalidOperationException("XINSKAN_SHELL_SAMPLES is required but not set."), .. parts]);
}

public sealed class ShellSampleTheoryAttribute : TheoryAttribute
{
    public ShellSampleTheoryAttribute()
    {
        if (ShellSampleFactAttribute.Root is null && Environment.GetEnvironmentVariable("XINSKAN_REQUIRE_SAMPLES") != "1")
        {
            Skip = "XINSKAN_SHELL_SAMPLES is not set.";
        }
    }
}
