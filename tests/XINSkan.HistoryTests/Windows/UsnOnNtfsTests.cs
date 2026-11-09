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

/// <summary>MFT and USN modules together on a volume whose journal Windows itself wrote.</summary>
public sealed class UsnOnNtfsTests(ITestOutputHelper output)
{
    [WindowsAdminFact]
    [SupportedOSPlatform("windows")]
    public async Task Create_rename_timestomp_and_delete_are_read_from_the_real_journal_without_changing_it()
    {
        using var vhd = TestVhd.Create(256);
        var drive = vhd.Letter + ":";
        var profile = Path.Combine(vhd.Root, "Users", "player");
        var mods = Path.Combine(profile, "AppData", "Roaming", ".minecraft", "mods");
        var desktop = Path.Combine(profile, "Desktop");
        Directory.CreateDirectory(mods);
        Directory.CreateDirectory(desktop);

        var before = DateTimeOffset.UtcNow.AddSeconds(-2);
        var cheat = Path.Combine(mods, "cheat-client.jar");
        File.WriteAllBytes(cheat, Jar.FabricMod("cheat", "Cheat", "1"));

        var hidden = Path.Combine(desktop, "client.jar");
        File.WriteAllBytes(hidden, Jar.FabricMod("c", "C", "1"));
        File.Move(hidden, Path.Combine(desktop, "homework.txt"));

        var stomped = Path.Combine(mods, "stomped.jar");
        File.WriteAllBytes(stomped, Jar.FabricMod("s", "S", "1"));
        File.SetCreationTimeUtc(stomped, new DateTime(2015, 1, 1, 0, 0, 0, DateTimeKind.Utc));

        File.Delete(cheat);
        var after = DateTimeOffset.UtcNow.AddSeconds(2);

        using (var p = Process.Start(new ProcessStartInfo("powershell.exe", $"-NoProfile -Command Write-VolumeCache -DriveLetter {vhd.Letter}") { UseShellExecute = false })!)
        {
            p.WaitForExit(60_000);
        }

        Thread.Sleep(2000);
        var usnBefore = QueryJournal(vhd.Letter);

        var sink = new MemorySink();
        var cache = new VolumeHistoryCache();
        var options = new HistoryOptions { Volumes = [drive], UsersRoot = Path.Combine(vhd.Root, "Users"), CurrentProfile = profile };
        var permissions = new PermissionManager(new WindowsCapabilityProbe(drive), TimeProvider.System).Snapshot();
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System).RunAsync(
            Ulid.NewUlid(DateTimeOffset.UtcNow),
            [new MftAnalyzer(options, WindowsVolumeOpener.Instance, cache), new UsnAnalyzer(options, WindowsUsnJournalSource.Instance, cache)],
            CancellationToken.None);

        Thread.Sleep(2000);
        var usnAfter = QueryJournal(vhd.Letter);
        var usn = sink.Evidence.Where(e => e.ModuleId == UsnAnalyzer.ModuleId).ToList();
        foreach (var e in usn)
        {
            output.WriteLine($"{e.EventType} {e.Timestamp?.ValueUtc:O} {e.Target.RecordedPath} {e.Target.MftEntry}/{e.Target.MftSequence} {e.Confidence} {string.Join(",", e.Attributes.Select(a => a.Key + "=" + a.Value))}");
        }

        foreach (var c in sink.Coverage)
        {
            output.WriteLine($"coverage {c.ModuleId} {c.Scope} {c.ItemsRead} {c.Status} {string.Join(" | ", c.Limitations.Select(l => l.Code + ": " + l.Text))}");
        }

        Assert.All(run.Modules, m => Assert.Equal(ModuleState.Completed, m.State));

        var deleted = usn.Single(e => e.EventType == EvidenceEventType.Deleted && e.Target.FileName == "cheat-client.jar");
        Assert.Equal(cheat, deleted.Target.RecordedPath);
        Assert.InRange(deleted.Timestamp!.ValueUtc, before, after);
        Assert.Contains(usn, e => e.EventType == EvidenceEventType.Created && e.Target.FileName == "cheat-client.jar");

        var rename = usn.Single(e => e.EventType == EvidenceEventType.Renamed);
        Assert.Equal("client.jar", rename.Attributes["Usn.OldName"]);
        Assert.Equal(Path.Combine(desktop, "homework.txt"), rename.Target.RecordedPath);
        Assert.Equal(Confidence.Low, rename.Confidence);

        Assert.Contains(usn, e => e.Target.FileName == "stomped.jar" && e.Attributes.ContainsKey("Usn.BasicInfoChanges"));
        Assert.DoesNotContain(usn, e => e.Target.FileName == "$UsnJrnl"); // journal created with the volume

        // Correlation on what Windows wrote: the MFT record and the journal entries of stomped.jar are one object,
        // and the two independent signs of a programmatic time change give a Medium finding.
        var correlation = new XINSkan.Correlation.CorrelationEngine(Ulid.NewUlid(DateTimeOffset.UtcNow), DateTimeOffset.UtcNow, TimeProvider.System)
            .Run(sink.Evidence.Select(XINSkan.Correlation.EvidenceFacts.From).ToList());
        foreach (var f in correlation.Findings)
        {
            output.WriteLine($"finding {f.RuleId} {f.Confidence} [{string.Join("+", f.IndependentFamilies)}] {f.Description}");
        }

        var stompedObject = correlation.Objects.Single(o => o.FileName == "stomped.jar");
        Assert.Contains("mft", stompedObject.SourceFamilies);
        Assert.Contains("usn", stompedObject.SourceFamilies);
        Assert.Contains(stompedObject.Members, m => m.Link == LinkKind.MftReference);
        var timestomp = correlation.Findings.Single(f => f.RuleId == "TIMESTOMP_CONFIRMED");
        Assert.Equal(Confidence.Medium, timestomp.Confidence);
        Assert.Equal(stompedObject.ObjectId, timestomp.ObjectId);

        // The renamed homework.txt lost ".jar", but nothing shows it ran: no "hidden by rename" finding.
        Assert.DoesNotContain(correlation.Findings, f => f.RuleId == "HIDDEN_BY_RENAME");

        // Read-Only: reading the journal does not add to it.
        Assert.Equal(usnBefore, usnAfter);
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
