using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.Versioning;
using XINSkan.Analyzers.History;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.FileHunterTests.Support;
using XINSkan.Investigation;
using XINSkan.Models;
using XINSkan.Platform.Windows;
using XINSkan.Platform.Windows.IO;
using XINSkan.SecurityTests.Windows;

namespace XINSkan.HistoryTests.Windows;

/// <summary>
/// The MFT module on a real NTFS volume written by Windows itself: what Windows does on delete (sequence
/// number), what SetFileTime changes (only $STANDARD_INFORMATION), and that reading changes nothing.
/// </summary>
public sealed class MftOnNtfsTests(ITestOutputHelper output)
{
    [WindowsAdminFact]
    [SupportedOSPlatform("windows")]
    public async Task Deleted_and_timestomped_files_are_found_on_a_windows_volume_and_nothing_changes()
    {
        using var vhd = TestVhd.Create(256);
        var drive = vhd.Letter + ":";
        var profile = Path.Combine(vhd.Root, "Users", "player");
        var mods = Path.Combine(profile, "AppData", "Roaming", ".minecraft", "mods");
        Directory.CreateDirectory(mods);
        Directory.CreateDirectory(Path.Combine(profile, "Downloads"));

        // Timestomped: SetFileTime changes $STANDARD_INFORMATION only.
        var stomped = Path.Combine(profile, "Downloads", "stomped.jar");
        File.WriteAllBytes(stomped, Jar.FabricMod("s", "S", "1"));
        File.SetCreationTimeUtc(stomped, new DateTime(2015, 1, 1, 0, 0, 0, DateTimeKind.Utc));

        // Deleted mod with its download origin; its sequence number is read from a live handle before deletion.
        // Deleted last: Windows hands a freed record to the next new file at once (seen in the first CI run,
        // where stomped.jar took the record of the deleted mod), so nothing is created after the deletion.
        var cheat = Path.Combine(mods, "cheat-client.jar");
        File.WriteAllBytes(cheat, Jar.FabricMod("cheat", "Cheat", "1"));
        File.WriteAllText(cheat + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.org/cheat-client.jar\r\n");
        ushort liveSequence;
        ulong liveEntry;
        using (var opened = WindowsFileSource.Instance.Open(cheat))
        {
            liveSequence = opened.Identity!.MftSequence;
            liveEntry = opened.Identity.MftEntry;
        }

        File.Delete(cheat);

        // The MFT is read from the disk, not from the file system cache: flush what Windows still holds.
        Flush(vhd.Letter);
        Thread.Sleep(2000);
        var usnBefore = QueryJournal(vhd.Letter);

        var sink = new MemorySink();
        var permissions = new PermissionManager(new WindowsCapabilityProbe(drive), TimeProvider.System).Snapshot();
        var options = new HistoryOptions { Volumes = [drive], UsersRoot = Path.Combine(vhd.Root, "Users"), CurrentProfile = profile };
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System)
            .RunAsync(Ulid.NewUlid(DateTimeOffset.UtcNow), [new MftAnalyzer(options, WindowsVolumeOpener.Instance, new VolumeHistoryCache())], CancellationToken.None);

        Thread.Sleep(2000);
        var usnAfter = QueryJournal(vhd.Letter);
        foreach (var e in sink.Evidence)
        {
            output.WriteLine($"{e.EventType} {e.Target.RecordedPath} {e.Target.MftEntry}/{e.Target.MftSequence} {e.Confidence} {string.Join(",", e.Attributes.Select(a => a.Key + "=" + a.Value))}");
        }

        output.WriteLine($"USN next {usnBefore.NextUsn} -> {usnAfter.NextUsn}");
        Assert.Equal(ModuleState.Completed, Assert.Single(run.Modules).State);

        var deleted = sink.Evidence.Single(e => e.Target.FileName == "cheat-client.jar");
        Assert.Equal(EvidenceEventType.Deleted, deleted.EventType);
        Assert.Equal(cheat, deleted.Target.RecordedPath);
        Assert.Equal(liveEntry, deleted.Target.MftEntry);

        // Windows increments the sequence when it frees the record: the analyzer reports the live reference.
        Assert.Equal(liveSequence, deleted.Target.MftSequence);
        Assert.Equal((liveSequence + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), deleted.Attributes["Mft.RecordSequence"]);
        Assert.Equal("https://example.org/cheat-client.jar", deleted.Attributes["Zone.HostUrl"]);

        var stomp = sink.Evidence.Single(e => e.Target.FileName == "stomped.jar");
        Assert.Equal(Confidence.Low, stomp.Confidence);
        Assert.Contains("SI_CREATED_BEFORE_FN", stomp.Attributes["Mft.TimeAnomaly"], StringComparison.Ordinal);
        Assert.Contains("SI_CREATED_WHOLE_SECOND", stomp.Attributes["Mft.TimeAnomaly"], StringComparison.Ordinal);
        Assert.True(stomp.Timestamp!.ValueUtc > new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), "$FN.Created keeps the real creation time.");

        // Read-Only: the journal did not move.
        Assert.Equal(usnBefore, usnAfter);
    }

    [SupportedOSPlatform("windows")]
    private static void Flush(char letter)
    {
        using var p = Process.Start(new ProcessStartInfo("powershell.exe", $"-NoProfile -Command Write-VolumeCache -DriveLetter {letter}") { UseShellExecute = false })!;
        p.WaitForExit(60_000);
    }

    [SupportedOSPlatform("windows")]
    private static (ulong JournalId, long NextUsn) QueryJournal(char letter)
    {
        using var volume = VolumeReader.Open(letter.ToString());
        Span<byte> data = stackalloc byte[80];
        SafeIoControl.Invoke(volume.Handle, AllowedIoControl.QueryUsnJournal, default, data);
        return (BinaryPrimitives.ReadUInt64LittleEndian(data), BinaryPrimitives.ReadInt64LittleEndian(data[16..]));
    }
}
