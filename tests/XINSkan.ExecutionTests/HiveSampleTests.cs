using System.IO.Compression;
using XINSkan.Analyzers.Execution;
using XINSkan.Analyzers.History;
using XINSkan.ExecutionFormats;
using XINSkan.Models;

namespace XINSkan.ExecutionTests;

/// <summary>
/// Real hives: the Amcache samples of the AmcacheParser library (DFIR Artifact Museum, MIT) with their
/// transaction logs, and hives from the Registry library's tests. Expected values are those libraries' own.
/// </summary>
public sealed class HiveSampleTests(ITestOutputHelper output)
{
    private static byte[] Museum(string relative)
    {
        var path = ExecSampleFactAttribute.File("AmcacheParser", "AmcacheParser.Test", "TestFiles", "DFIRArtifactMuseum", relative + ".gz");
        using var gz = new GZipStream(File.OpenRead(path), CompressionMode.Decompress);
        var ms = new MemoryStream();
        gz.CopyTo(ms);
        return ms.ToArray();
    }

    private static byte[] Hive(string name) => File.ReadAllBytes(ExecSampleFactAttribute.File("RegistryHives", name));

    [ExecSampleFact]
    public void Dirty_windows_10_amcache_is_recovered_from_its_logs()
    {
        var dir = "Win10/APTSimulatorVM/";
        var hive = RegistryHive.Open(Museum(dir + "Amcache.hve"), Museum(dir + "Amcache.hve.LOG1"), Museum(dir + "Amcache.hve.LOG2"))!;
        output.WriteLine($"dirty {hive.WasDirty}, applied {hive.LogEntriesApplied}, problems: {string.Join("; ", hive.Problems)}");
        Assert.True(hive.WasDirty);
        Assert.Equal(4, hive.LogEntriesApplied); // LOG1: 36, 37; LOG2: 38, 39 (its leftover entry 27 is not applied)
        Assert.False(hive.RecoveryIncomplete);
        Assert.Empty(hive.Problems);

        var root = hive.Root!;
        var files = AmcacheAnalyzer.NewFormat(root, root.Open(@"Root\InventoryApplicationFile")!);
        Assert.Equal(124, files.Count);
        Assert.Equal(90, root.Open(@"Root\InventoryApplication")!.SubKeyCount);
        Assert.Equal(12, root.Open(@"Root\InventoryDeviceContainer")!.SubKeyCount);
        Assert.Equal(189, root.Open(@"Root\InventoryDevicePnp")!.SubKeyCount);

        var file = files.Single(f => f.Path.EndsWith("onedrivestandaloneupdater.exe", StringComparison.Ordinal));
        Assert.Equal("57b7fc9bf59cf09a9c19ad0ce0a159746554d682", file.Sha1);
        Assert.Equal(3060072, file.Size);
        Assert.EndsWith("onedrivestandalo|70daea7f83b4ffcb", file.Key, StringComparison.Ordinal);
        Assert.Equal(new DateTimeOffset(2022, 3, 10, 19, 46, 36, TimeSpan.Zero).AddTicks(2565599), DateTimeOffset.FromFileTime(file.LastWrite).ToUniversalTime());
        Assert.Equal("Microsoft.WindowsCamera", root.Open(@"Root\InventoryApplication\0000041ce3ebb98d8d6fe2ef3dfc806b03f300000904")!.Value("Name")!.AsString());

        // Without the logs the hive is one entry short and says so.
        var alone = RegistryHive.Open(Museum(dir + "Amcache.hve"))!;
        Assert.True(alone.RecoveryIncomplete);
        Assert.Equal(123, alone.Root!.Open(@"Root\InventoryApplicationFile")!.SubKeyCount);
    }

    [ExecSampleFact]
    public void Old_format_amcache_of_windows_server_2012_r2()
    {
        var hive = RegistryHive.Open(Museum("Win2012R2/StolenSzechuan/Amcache.hve"))!;
        Assert.False(hive.WasDirty);
        Assert.Empty(hive.Problems);
        var files = AmcacheAnalyzer.OldFormat(hive.Root!);
        Assert.Equal(136, files.Count);
        Assert.Contains(files, f => f.Path == @"C:\Program Files\Common Files\VMware\Drivers\vss\comreg.exe");
        Assert.All(files, f => Assert.NotNull(f.Reference));
    }

    [ExecSampleFact]
    public void Registry_library_hives()
    {
        var sam = RegistryHive.Open(Hive("SAM"))!;
        Assert.Empty(sam.Problems);
        Assert.Equal("CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}", sam.Root!.Name);
        Assert.NotNull(sam.Root.Open(@"SAM\DomAins\AccoUnt"));
        Assert.Null(sam.Root.Open(@"SAM\Domains\Account\This\Does\Not\Exist"));

        // DeviceIds keeps 3 878 subkeys in an index root (ri) of several lists.
        var drivers = RegistryHive.Open(Hive("DRIVERS"))!;
        Assert.Equal(3878, drivers.Root!.Open(@"DriverDatabase\DeviceIds")!.SubKeys().Count);
        Assert.Empty(drivers.Problems);

        Assert.NotNull(RegistryHive.Open(Hive("NTUSER1.DAT"))!.Root);
        Assert.Null(RegistryHive.Open(Hive("NotAHive")));
    }

    [ExecSampleFact]
    public async Task Amcache_module_on_the_windows_10_sample()
    {
        var dir = "Win10/APTSimulatorVM/";
        const string path = @"C:\Windows\AppCompat\Programs\Amcache.hve";
        var files = new TestProtectedFiles()
            .Add(path, Museum(dir + "Amcache.hve"))
            .Add(path + ".LOG1", Museum(dir + "Amcache.hve.LOG1"))
            .Add(path + ".LOG2", Museum(dir + "Amcache.hve.LOG2"));
        var options = new HistoryOptions { Volumes = ["C:"], UsersRoot = @"C:\Users", CurrentProfile = @"C:\Users\testuser", WindowsFolder = @"C:\Windows" };
        var sink = await PrefetchAnalyzerTests.RunAsync(new AmcacheAnalyzer(options, files, new TestVolumes()));
        foreach (var e in sink.Evidence)
        {
            output.WriteLine($"{e.Target.RecordedPath} {e.Attributes.GetValueOrDefault("Amcache.Sha1")} {e.Attributes["Amcache.Why"]}");
        }

        var c = Assert.Single(sink.Coverage);
        Assert.Equal(124, c.ItemsRead);
        Assert.Equal(CollectionStatus.Collected, c.Status);
        Assert.Contains(sink.Evidence, e => e.Target.FileName == "onedrivestandaloneupdater.exe");
        Assert.All(sink.Evidence, e => Assert.Equal(EvidenceEventType.Existed, e.EventType));
    }
}
