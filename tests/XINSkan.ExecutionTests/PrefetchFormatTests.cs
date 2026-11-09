using System.Text;
using XINSkan.ExecutionFormats;

namespace XINSkan.ExecutionTests;

public sealed class PrefetchFormatTests
{
    private static readonly long Run1 = new DateTime(2026, 11, 7, 18, 30, 0, DateTimeKind.Utc).ToFileTimeUtc();
    private static readonly long Run2 = new DateTime(2026, 11, 6, 10, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();

    private static readonly PfFile[] Files =
    [
        new(@"\VOLUME{01d1b0e3a1b2c3d4-64BB3469}\WINDOWS\SYSTEM32\NTDLL.DLL", 1234, 1),
        new(@"\VOLUME{01d1b0e3a1b2c3d4-64BB3469}\PROGRAM FILES\JAVA\JRE\BIN\JAVAW.EXE", 0x1_0000_0042, 7),
        new(@"\VOLUME{01d1b0e3a1b2c3d4-64BB3469}\USERS\PLAYER\APPDATA\ROAMING\.MINECRAFT\MODS\SODIUM.JAR", 99_001, 3),
    ];

    [Theory]
    [InlineData(17)]
    [InlineData(23)]
    [InlineData(26)]
    [InlineData(30)]
    public void Every_version_layout_is_read(int version)
    {
        var pf = PrefetchFile.Parse(PrefetchBuilder.Build(version, "JAVAW.EXE", 0xB3BA7868, 42, [Run1, Run2], Files,
            directories: [@"\VOLUME{01d1b0e3a1b2c3d4-64BB3469}\USERS", @"\VOLUME{01d1b0e3a1b2c3d4-64BB3469}\USERS\PLAYER"]))!;

        Assert.Empty(pf.Problems);
        Assert.Equal(version, pf.Version);
        Assert.False(pf.WasCompressed);
        Assert.Equal("JAVAW.EXE", pf.ExecutableName);
        Assert.Equal(0xB3BA7868u, pf.Hash);
        Assert.Equal(42, pf.RunCount);
        Assert.Equal(version >= 26 ? [Run1, Run2] : new[] { Run1 }, pf.LastRunTimes);
        Assert.Equal(Files.Select(f => f.Path), pf.Files.Select(f => f.Path));
        var volume = Assert.Single(pf.Volumes);
        Assert.Equal(@"\VOLUME{01d1b0e3a1b2c3d4-64BB3469}", volume.DevicePath);
        Assert.Equal(0x64BB3469u, volume.Serial);
        Assert.Equal(2, volume.Directories.Count);
        Assert.Equal(@"\VOLUME{01d1b0e3a1b2c3d4-64BB3469}\USERS\PLAYER", volume.Directories[1]);
        Assert.Equal(((ulong)0x1_0000_0042, (ushort)7), volume.FileReferences[1]);
        if (version >= 23)
        {
            Assert.Equal(0x1_0000_0042ul, pf.Files[1].MftEntry);
            Assert.Equal((ushort)7, pf.Files[1].MftSequence);
        }
        else
        {
            Assert.Null(pf.Files[1].MftEntry); // version 17 metrics carry no reference
        }
    }

    [Fact]
    public void Run_count_moved_by_newer_windows_11_builds_is_read_from_the_new_place()
    {
        var pf = PrefetchFile.Parse(PrefetchBuilder.Build(30, "JAVAW.EXE", 1, 13, [Run1], Files, movedRunCount: true))!;
        Assert.Equal(13, pf.RunCount);
    }

    [Fact]
    public void Compressed_windows_10_file_is_decompressed_and_read()
    {
        var raw = PrefetchBuilder.Build(30, "JAVAW.EXE", 0xB3BA7868, 42, [Run1, Run2], Files);
        var pf = PrefetchFile.Parse(PrefetchBuilder.Mam(raw))!;
        Assert.True(pf.WasCompressed);
        Assert.Empty(pf.Problems);
        Assert.Equal(42, pf.RunCount);
        Assert.Equal(Files.Select(f => f.Path), pf.Files.Select(f => f.Path));
    }

    [Fact]
    public void Not_a_prefetch_file_is_null_and_unknown_versions_are_reported()
    {
        Assert.Null(PrefetchFile.Parse(Encoding.ASCII.GetBytes("hello, this is not a prefetch file at all, but it is long enough to read the header of one...")));
        var unknown = PrefetchBuilder.Build(30, "X.EXE", 1, 1, [Run1], Files);
        unknown[0] = 99;
        var pf = PrefetchFile.Parse(unknown)!;
        Assert.Equal(99, pf.Version);
        Assert.Contains(pf.Problems, p => p.Contains("99", StringComparison.Ordinal));

        var badMam = new byte[] { (byte)'M', (byte)'A', (byte)'M', 0x04, 0xFF, 0xFF, 0xFF, 0x7F, 1, 2, 3 };
        Assert.Contains(PrefetchFile.Parse(badMam)!.Problems, p => p.Contains("предела", StringComparison.Ordinal));
    }

    [Fact]
    public void Damaged_files_never_throw()
    {
        var plain = PrefetchBuilder.Build(30, "JAVAW.EXE", 1, 5, [Run1], Files, directories: [@"\X"]);
        var samples = new[] { plain, PrefetchBuilder.Build(17, "CMD.EXE", 1, 5, [Run1], Files), PrefetchBuilder.Mam(plain) };
        var random = new Random(6);
        var parsed = 0;
        foreach (var sample in samples)
        {
            for (var n = 0; n < 3000; n++)
            {
                var copy = (byte[])sample.Clone();
                for (var k = random.Next(1, 8); k > 0; k--)
                {
                    copy[random.Next(copy.Length)] = (byte)random.Next(256);
                }

                var cut = random.Next(4) == 0 ? copy[..random.Next(copy.Length)] : copy;
                if (PrefetchFile.Parse(cut) is { } pf)
                {
                    parsed++;
                    Assert.True(pf.Files.Count <= 100_000);
                }
            }
        }

        Assert.True(parsed > 1000);
    }

    [Fact]
    public void Xpress_round_trips_across_blocks_and_rejects_damage_with_one_exception_type()
    {
        var random = new Random(3);
        var data = new byte[150_000];
        for (var i = 0; i < data.Length; i++)
        {
            data[i] = i % 7 == 0 ? (byte)random.Next(256) : (byte)"minecraft"[i % 9];
        }

        var compressed = XpressEncoder.Encode(data);
        Assert.True(compressed.Length < data.Length);
        Assert.Equal(data, XpressHuffman.Decompress(compressed, data.Length));

        for (var n = 0; n < 2000; n++)
        {
            var copy = (byte[])compressed.Clone();
            copy[random.Next(copy.Length)] ^= (byte)random.Next(1, 256);
            var cut = random.Next(3) == 0 ? copy[..random.Next(copy.Length)] : copy;
            try
            {
                XpressHuffman.Decompress(cut, data.Length);
            }
            catch (InvalidDataException)
            {
            }
        }
    }
}
