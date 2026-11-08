using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using XINSkan.Core.Permissions;
using XINSkan.Platform.Windows;
using XINSkan.Platform.Windows.IO;

namespace XINSkan.SecurityTests.Windows;

/// <summary>
/// Measures, on a real NTFS volume, whether reading it through the platform layer changes it: content, write and
/// creation times, the change journal position, and (reported, not asserted) last-access times.
/// </summary>
public sealed class VolumeImmutabilityTests(ITestOutputHelper output)
{
    private sealed record FileState(string Sha256, DateTime CreatedUtc, DateTime WrittenUtc, DateTime AccessedUtc, FileAttributes Attributes);

    [WindowsAdminFact]
    [SupportedOSPlatform("windows")]
    public void Reading_a_volume_through_the_platform_layer_leaves_it_unchanged()
    {
        using var vhd = TestVhd.Create();
        var files = Seed(vhd.Root);

        // Let NTFS settle so lazy metadata writes from seeding do not count against the reader.
        Thread.Sleep(2000);
        var before = Snapshot(files);
        var usnBefore = QueryJournal(vhd.Letter);

        // Everything the platform layer can do today:
        foreach (var f in files)
        {
            using var s = ReadOnlyFile.OpenRead(f);
            s.CopyTo(Stream.Null);
        }

        using (var volume = VolumeReader.Open(vhd.Letter.ToString()))
        {
            var boot = new byte[512];
            Assert.Equal(512, volume.Read(0, boot));
            Assert.Equal("NTFS    ", System.Text.Encoding.ASCII.GetString(boot, 3, 8));

            var ntfs = volume.GetNtfsVolumeData();
            var mft = new byte[ntfs.BytesPerFileRecordSegment * 16];
            Assert.Equal(mft.Length, volume.Read(ntfs.MftStartLcn * ntfs.BytesPerCluster, mft));
            Assert.Equal("FILE", System.Text.Encoding.ASCII.GetString(mft, 0, 4));

            // Unaligned read through the alignment logic.
            var odd = new byte[777];
            Assert.Equal(777, volume.Read(ntfs.MftStartLcn * ntfs.BytesPerCluster + 13, odd));
            Assert.Equal(mft.AsSpan(13, 777).ToArray(), odd);
        }

        var probe = new WindowsCapabilityProbe(vhd.Letter + ":");
        foreach (var c in Enum.GetValues<Capability>())
        {
            var state = probe.Probe(c);
            output.WriteLine($"probe {c}: {state.Available} — {state.Reason}");
        }

        Thread.Sleep(2000);
        var after = Snapshot(files);
        var usnAfter = QueryJournal(vhd.Letter);

        output.WriteLine($"USN journal {usnBefore.JournalId:X}: next USN before {usnBefore.NextUsn}, after {usnAfter.NextUsn}");
        foreach (var f in files)
        {
            if (before[f].AccessedUtc != after[f].AccessedUtc)
            {
                output.WriteLine($"last-access time changed (known, documented side effect): {f} {before[f].AccessedUtc:O} -> {after[f].AccessedUtc:O}");
            }
        }

        Assert.Equal(usnBefore.JournalId, usnAfter.JournalId);
        Assert.Equal(usnBefore.NextUsn, usnAfter.NextUsn);
        foreach (var f in files)
        {
            Assert.Equal(before[f].Sha256, after[f].Sha256);
            Assert.Equal(before[f].CreatedUtc, after[f].CreatedUtc);
            Assert.Equal(before[f].WrittenUtc, after[f].WrittenUtc);
            Assert.Equal(before[f].Attributes, after[f].Attributes);
        }
    }

    [WindowsAdminFact]
    [SupportedOSPlatform("windows")]
    public void Reading_does_not_block_the_systems_own_writers()
    {
        using var vhd = TestVhd.Create();
        var path = Path.Combine(vhd.Root, "busy.log");
        File.WriteAllText(path, "start");

        using var reader = ReadOnlyFile.OpenRead(path);

        // While XIN SKAN holds the file open, another process must still be able to write, rename and delete it.
        File.AppendAllText(path, " more");
        var renamed = path + ".old";
        File.Move(path, renamed);
        File.Delete(renamed);
        Assert.False(File.Exists(renamed));
    }

    [SupportedOSPlatform("windows")]
    private static List<string> Seed(string root)
    {
        var mods = Directory.CreateDirectory(Path.Combine(root, "Users", "player", ".minecraft", "mods"));
        var files = new List<string>();
        for (var i = 0; i < 5; i++)
        {
            var f = Path.Combine(mods.FullName, $"test-mod-{i}.jar");
            File.WriteAllBytes(f, RandomNumberGenerator.GetBytes(4096 + (i * 1000)));
            files.Add(f);
        }

        var cfg = Path.Combine(root, "Users", "player", ".minecraft", "options.txt");
        File.WriteAllText(cfg, "lang:ru_ru");
        files.Add(cfg);
        return files;
    }

    private static Dictionary<string, FileState> Snapshot(IEnumerable<string> files) =>
        files.ToDictionary(f => f, f =>
        {
            // The test reads hashes with System.IO for an independent check of the product's reader.
            using var s = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var hash = Convert.ToHexString(SHA256.HashData(s));
            var info = new FileInfo(f);
            return new FileState(hash, info.CreationTimeUtc, info.LastWriteTimeUtc, info.LastAccessTimeUtc, info.Attributes);
        });

    [SupportedOSPlatform("windows")]
    private static (ulong JournalId, long NextUsn) QueryJournal(char letter)
    {
        using var volume = VolumeReader.Open(letter.ToString());
        Span<byte> data = stackalloc byte[80];
        SafeIoControl.Invoke(volume.Handle, AllowedIoControl.QueryUsnJournal, default, data);

        // USN_JOURNAL_DATA: UsnJournalID(8) FirstUsn(8) NextUsn(8) ...
        return (BinaryPrimitives.ReadUInt64LittleEndian(data), BinaryPrimitives.ReadInt64LittleEndian(data[16..]));
    }
}
