using System.Text;
using XINSkan.ExecutionFormats;

namespace XINSkan.ExecutionTests;

public sealed class RegistryHiveTests
{
    private static readonly long Written = new DateTime(2026, 11, 7, 12, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();

    private static TestKey Sample(int extraKeys = 0) => new("ROOT", SubKeys:
    [
        new("Software", Written, SubKeys:
        [
            new("Lunar", Written, [TestValue.Sz("Path", @"C:\Users\player\.lunarclient"), TestValue.Dword("Runs", 7), TestValue.Qword("Big", 1L << 40)]),
            new("Кириллица", Written, [new TestValue("Имя", HiveValue.RegSz, Encoding.Unicode.GetBytes("значение\0"), AsciiName: false)], AsciiName: false),
            new("Blob", Written, [new TestValue("Data", HiveValue.RegBinary, Enumerable.Range(0, 40_000).Select(i => (byte)i).ToArray())]),
        ]),
        new("Many", Written, SubKeys: [.. Enumerable.Range(0, 7 + extraKeys).Select(i => new TestKey($"k{i}", Written + i))], List: "ri"),
        new("Short", Written, SubKeys: [new("a"), new("b")], List: "li"),
    ]);

    [Fact]
    public void Keys_values_lists_and_big_data_are_read()
    {
        var hive = RegistryHive.Open(HiveBuilder.Build(Sample()))!;
        Assert.Empty(hive.Problems);
        Assert.False(hive.WasDirty);
        Assert.Equal("ROOT", hive.Root!.Name);

        var lunar = hive.Root.Open(@"software\LUNAR")!;
        Assert.Equal(Written, lunar.LastWriteTime);
        Assert.Equal(@"C:\Users\player\.lunarclient", lunar.Value("path")!.AsString());
        Assert.Equal(7, lunar.Value("Runs")!.AsNumber());
        Assert.Equal(1L << 40, lunar.Value("Big")!.AsNumber());

        Assert.Equal("значение", hive.Root.Open(@"Software\Кириллица")!.Value("Имя")!.AsString());
        var blob = hive.Root.Open(@"Software\Blob")!.Value("Data")!.Data;
        Assert.Equal(40_000, blob.Length);
        Assert.Equal((byte)(39_999 % 256), blob[^1]);

        Assert.Equal(Enumerable.Range(0, 7).Select(i => $"k{i}"), hive.Root.SubKey("Many")!.SubKeys().Select(k => k.Name));
        Assert.Equal(new[] { "a", "b" }, hive.Root.SubKey("Short")!.SubKeys().Select(k => k.Name));
        Assert.Null(hive.Root.Open(@"Software\Missing\Key"));
    }

    [Fact]
    public void Dirty_hive_is_recovered_from_its_log_in_sequence_order()
    {
        // The file on disk is version 1 marked dirty (5/4); the log continues with versions 2 and 3.
        var stale = HiveBuilder.Build(Sample(), primarySeq: 5, secondarySeq: 4, minBins: 16384);
        var v2 = HiveBuilder.Build(Sample(extraKeys: 1), minBins: 16384);
        var v3 = HiveBuilder.Build(Sample(extraKeys: 2), minBins: 16384);

        var hive = RegistryHive.Open(stale, HiveBuilder.Log(4, v2, v3))!;
        Assert.True(hive.WasDirty);
        Assert.Equal(2, hive.LogEntriesApplied);
        Assert.False(hive.RecoveryIncomplete);
        Assert.Equal(9, hive.Root!.SubKey("Many")!.SubKeys().Count);

        // Without logs the stale version is read, and the record says recent changes may be missing.
        var alone = RegistryHive.Open(stale)!;
        Assert.True(alone.RecoveryIncomplete);
        Assert.Equal(7, alone.Root!.SubKey("Many")!.SubKeys().Count);
        Assert.Contains(alone.Problems, p => p.Contains("последние изменения", StringComparison.Ordinal));
    }

    [Fact]
    public void Log_entries_with_a_wrong_hash_or_an_older_chain_are_not_applied()
    {
        var stale = HiveBuilder.Build(Sample(), primarySeq: 5, secondarySeq: 4, minBins: 16384);
        var log = HiveBuilder.Log(4, HiveBuilder.Build(Sample(extraKeys: 1), minBins: 16384));
        log[600] ^= 0xFF; // inside the entry's pages: hash 1 no longer matches
        var hive = RegistryHive.Open(stale, log)!;
        Assert.Equal(0, hive.LogEntriesApplied);
        Assert.True(hive.RecoveryIncomplete);
        Assert.Equal(7, hive.Root!.SubKey("Many")!.SubKeys().Count);

        // A log from an earlier generation (entries older than the hive) is ignored.
        var old = RegistryHive.Open(stale, HiveBuilder.Log(1, HiveBuilder.Build(Sample(extraKeys: 2), minBins: 16384)))!;
        Assert.Equal(0, old.LogEntriesApplied);
    }

    [Fact]
    public void Not_a_hive_is_null_and_damaged_hives_never_throw()
    {
        Assert.Null(RegistryHive.Open(new byte[8192]));
        Assert.Null(RegistryHive.Open(Encoding.ASCII.GetBytes("regf")));

        var good = HiveBuilder.Build(Sample(), minBins: 16384);
        var log = HiveBuilder.Log(4, HiveBuilder.Build(Sample(extraKeys: 1), minBins: 16384));
        var random = new Random(9);
        var opened = 0;
        for (var n = 0; n < 3000; n++)
        {
            var copy = (byte[])good.Clone();
            for (var k = random.Next(1, 12); k > 0; k--)
            {
                copy[4096 + random.Next(copy.Length - 4096)] = (byte)random.Next(256);
            }

            if (n % 3 == 0)
            {
                copy[8] ^= 1; // dirty: the log is applied over the damage, or damaged too
            }

            var logCopy = (byte[])log.Clone();
            if (n % 5 == 0)
            {
                logCopy[512 + random.Next(logCopy.Length - 512)] ^= (byte)random.Next(1, 256);
            }

            var cut = n % 7 == 0 ? copy[..random.Next(4096, copy.Length)] : copy;
            if (RegistryHive.Open(cut, logCopy) is { Root: { } root })
            {
                opened++;
                Walk(root, 0);
            }
        }

        Assert.True(opened > 1000);
    }

    private static void Walk(HiveKey key, int depth)
    {
        _ = key.Values().Sum(v => v.Data.Length + (v.AsString()?.Length ?? 0));
        if (depth < 10)
        {
            foreach (var k in key.SubKeys())
            {
                Walk(k, depth + 1);
            }
        }
    }
}
