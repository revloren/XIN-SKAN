using XINSkan.Correlation;
using XINSkan.Core.Paths;
using XINSkan.Models;

namespace XINSkan.CorrelationTests;

/// <summary>Builds records the way the analyzers write them, reduced to what correlation reads.</summary>
internal static class F
{
    public static readonly DateTimeOffset T0 = new(2026, 11, 8, 18, 0, 0, TimeSpan.Zero);

    public static EvidenceFacts Fact(
        EvidenceSourceKind source,
        EvidenceEventType type,
        string? path = null,
        ulong? entry = null,
        ushort? seq = null,
        DateTimeOffset? at = null,
        Confidence confidence = Confidence.Informational,
        ulong? serial = null,
        string module = "m",
        params (string Key, string Value)[] attrs) =>
        new(Ulid.NewUlid(DateTimeOffset.UtcNow), module, source, type, at, path, PathNormalizer.Normalize(EvidenceFacts.PathOnly(path)), path is null ? null : path[(path.LastIndexOf('\\') + 1)..],
            serial, entry, seq, null, confidence, attrs.ToDictionary(a => a.Key, a => a.Value, StringComparer.Ordinal));

    public static CorrelationResult Run(params EvidenceFacts[] facts) =>
        new CorrelationEngine(Ulid.NewUlid(T0), T0.AddHours(6), TimeProvider.System).Run(facts);
}

public sealed class CorrelationEngineTests
{
    private const string Mod = @"C:\Users\player\AppData\Roaming\.minecraft\mods\wurst.jar";

    [Fact]
    public void Records_of_one_file_are_linked_by_mft_reference_across_paths_and_by_path_without_reference()
    {
        var live = F.Fact(EvidenceSourceKind.FileSystem, EvidenceEventType.Existed, Mod, 500, 3, serial: 0xA1B2C3D4);
        var usnRename = F.Fact(EvidenceSourceKind.UsnJournal, EvidenceEventType.Renamed, Mod, 500, 3, F.T0, serial: 0xA1B2C3D4, attrs: ("Usn.OldPath", @"C:\Users\player\Downloads\wurst.jar"));
        var mftDeletedUnknownPath = F.Fact(EvidenceSourceKind.Mft, EvidenceEventType.Existed, @"?\mods\wurst.jar", 500, 3, serial: 0xA1B2C3D4);
        var prefetch = F.Fact(EvidenceSourceKind.Prefetch, EvidenceEventType.Loaded, Mod.ToUpperInvariant(), 500, 3, F.T0.AddMinutes(5));
        var lnkToOldPath = F.Fact(EvidenceSourceKind.Lnk, EvidenceEventType.Accessed, @"C:\Users\player\Downloads\wurst.jar", at: F.T0.AddMinutes(-10));
        var other = F.Fact(EvidenceSourceKind.FileSystem, EvidenceEventType.Existed, @"C:\Users\player\Desktop\notes.txt", 900, 1);

        var r = F.Run(live, usnRename, mftDeletedUnknownPath, prefetch, lnkToOldPath, other);

        var o = Assert.Single(r.Objects);
        Assert.Equal(5, o.Members.Count);
        Assert.Equal(LinkKind.MftReference, o.Members.Single(m => m.EvidenceId == mftDeletedUnknownPath.Id).Link); // the serial maps to C:
        Assert.Equal(LinkKind.Path, o.Members.Single(m => m.EvidenceId == lnkToOldPath.Id).Link);
        Assert.Equal(PathNormalizer.Normalize(Mod), o.NormalizedPath);
        Assert.Contains(PathNormalizer.Normalize(@"C:\Users\player\Downloads\wurst.jar"), o.OtherPaths);
        Assert.Equal(500ul, o.MftEntry);
        Assert.Equal(new[] { "files", "mft", "prefetch", "shell", "usn" }, o.SourceFamilies);
        Assert.Equal(F.T0.AddMinutes(-10), o.FirstUtc);
    }

    [Fact]
    public void A_path_used_by_two_different_files_keeps_them_apart()
    {
        var first = F.Fact(EvidenceSourceKind.UsnJournal, EvidenceEventType.Deleted, Mod, 500, 3, F.T0);
        var firstRun = F.Fact(EvidenceSourceKind.Prefetch, EvidenceEventType.Loaded, Mod, 500, 3, F.T0.AddMinutes(-30));
        var second = F.Fact(EvidenceSourceKind.FileSystem, EvidenceEventType.Existed, Mod, 777, 1);
        var secondCreated = F.Fact(EvidenceSourceKind.UsnJournal, EvidenceEventType.Created, Mod, 777, 1, F.T0.AddMinutes(1));
        var noReference = F.Fact(EvidenceSourceKind.ShellBags, EvidenceEventType.Accessed, Mod);

        var r = F.Run(first, firstRun, second, secondCreated, noReference);

        Assert.Equal(2, r.Objects.Count);
        Assert.Contains(r.Objects, o => o.MftEntry == 500 && o.Members.Count == 2);
        Assert.Contains(r.Objects, o => o.MftEntry == 777 && o.Members.Count == 2);
        Assert.DoesNotContain(r.Objects, o => o.Members.Any(m => m.EvidenceId == noReference.Id));
        Assert.Contains(r.Limitations, l => l.Code == "CORR.AMBIGUOUS_PATH");
    }

    [Fact]
    public void Timestomp_needs_both_mft_and_usn_and_is_medium()
    {
        var mft = F.Fact(EvidenceSourceKind.Mft, EvidenceEventType.Existed, Mod, 500, 3, confidence: Confidence.Low, attrs: ("Mft.TimeAnomaly", "SI_CREATED_BEFORE_FN"));
        var usn = F.Fact(EvidenceSourceKind.UsnJournal, EvidenceEventType.Modified, Mod, 500, 3, F.T0, attrs: ("Usn.BasicInfoChanges", "1"));
        var f = Assert.Single(F.Run(mft, usn).Findings);
        Assert.Equal("TIMESTOMP_CONFIRMED", f.RuleId);
        Assert.Equal(Confidence.Medium, f.Confidence);
        Assert.Equal(new[] { "mft", "usn" }, f.IndependentFamilies);
        Assert.Contains("архиватор", f.Rationale, StringComparison.Ordinal);
        Assert.NotNull(f.ObjectId);

        Assert.Empty(F.Run(mft, F.Fact(EvidenceSourceKind.UsnJournal, EvidenceEventType.Modified, Mod, 500, 3, F.T0, attrs: ("Usn.DataChanges", "1"))).Findings);
    }

    [Fact]
    public void Ran_then_deleted_is_low_and_needs_the_deletion_after_the_run()
    {
        var run = F.Fact(EvidenceSourceKind.Prefetch, EvidenceEventType.Loaded, Mod, 500, 3, F.T0);
        var bam = F.Fact(EvidenceSourceKind.Bam, EvidenceEventType.Executed, Mod, at: F.T0.AddMinutes(2));
        var deleted = F.Fact(EvidenceSourceKind.UsnJournal, EvidenceEventType.Deleted, Mod, 500, 3, F.T0.AddHours(3));
        var f = Assert.Single(F.Run(run, bam, deleted).Findings);
        Assert.Equal("RAN_THEN_DELETED", f.RuleId);
        Assert.Equal(Confidence.Low, f.Confidence); // even with three families: deleting a used program is ordinary
        Assert.Contains("меньше чем за сутки до проверки", f.Description, StringComparison.Ordinal);
        Assert.Equal(3, f.Members.Count);

        var deletedBefore = F.Fact(EvidenceSourceKind.UsnJournal, EvidenceEventType.Deleted, Mod, 500, 3, F.T0.AddDays(-1));
        Assert.Empty(F.Run(run, deletedBefore).Findings);
    }

    [Fact]
    public void Hidden_by_rename_and_defender_flagged_are_medium_with_two_families()
    {
        var rename = F.Fact(EvidenceSourceKind.UsnJournal, EvidenceEventType.Renamed, @"C:\Users\player\Downloads\notes.txt", 500, 3, F.T0, Confidence.Low, attrs: ("Usn.ExtensionChanged", ".jar → .txt"));
        var loaded = F.Fact(EvidenceSourceKind.Prefetch, EvidenceEventType.Loaded, @"C:\Users\player\Downloads\notes.txt", 500, 3, F.T0.AddMinutes(-5));
        var detection = F.Fact(EvidenceSourceKind.EventLog, EvidenceEventType.Observed, @"C:\Users\player\Downloads\notes.txt", at: F.T0.AddMinutes(1),
            attrs: [("Defender.Threat", "HackTool:Java/Wurst"), ("EventLog.Channel", "Microsoft-Windows-Windows Defender/Operational"), ("EventLog.EventId", "1116")]);

        var r = F.Run(rename, loaded, detection);
        Assert.Single(r.Objects);
        var hidden = r.Findings.Single(f => f.RuleId == "HIDDEN_BY_RENAME");
        Assert.Equal(Confidence.Medium, hidden.Confidence);
        Assert.Equal(new[] { "prefetch", "usn" }, hidden.IndependentFamilies);
        var flagged = r.Findings.Single(f => f.RuleId == "DEFENDER_FLAGGED_AND_RAN");
        Assert.Equal(Confidence.Medium, flagged.Confidence);
        Assert.Equal(new[] { "defender", "prefetch" }, flagged.IndependentFamilies);
        Assert.Contains("HackTool:Java/Wurst", flagged.Description, StringComparison.Ordinal);

        // A rename that gains an extension (finished download) is not hiding.
        var download = rename with { Id = Ulid.NewUlid(DateTimeOffset.UtcNow), Confidence = Confidence.Informational };
        Assert.DoesNotContain(F.Run(download, loaded).Findings, f => f.RuleId == "HIDDEN_BY_RENAME");
    }

    [Fact]
    public void Exclusion_of_a_folder_something_ran_from_is_medium_but_a_whole_drive_is_not_used()
    {
        (string, string)[] Exclusion() => [("EventLog.EventId", "5007"), ("Defender.Change", "added"), ("Defender.ExclusionType", "Paths"), ("EventLog.Channel", "Microsoft-Windows-Windows Defender/Operational")];
        var folder = F.Fact(EvidenceSourceKind.EventLog, EvidenceEventType.Observed, @"C:\Users\player\AppData\Roaming\.minecraft", at: F.T0, confidence: Confidence.Low, attrs: Exclusion());
        var drive = F.Fact(EvidenceSourceKind.EventLog, EvidenceEventType.Observed, @"C:\", at: F.T0, confidence: Confidence.Low, attrs: Exclusion());
        var run = F.Fact(EvidenceSourceKind.Prefetch, EvidenceEventType.Loaded, Mod, 500, 3, F.T0.AddHours(1));
        var elsewhere = F.Fact(EvidenceSourceKind.Bam, EvidenceEventType.Executed, @"D:\Tools\x.exe", at: F.T0);

        var f = Assert.Single(F.Run(folder, drive, run, elsewhere).Findings);
        Assert.Equal("EXCLUDED_AND_RAN", f.RuleId);
        Assert.Equal(Confidence.Medium, f.Confidence);
        Assert.Contains(f.Members, m => m.EvidenceId == folder.Id);
        Assert.Contains(f.Members, m => m.EvidenceId == run.Id);
        Assert.DoesNotContain(f.Members, m => m.EvidenceId == elsewhere.Id || m.EvidenceId == drive.Id);
    }

    [Fact]
    public void Concealment_cluster_needs_two_families_within_two_hours()
    {
        var cleared = F.Fact(EvidenceSourceKind.EventLog, EvidenceEventType.Observed, "System", at: F.T0, confidence: Confidence.Low,
            attrs: [("EventLog.EventId", "104"), ("EventLog.Channel", "System"), ("EventLog.ClearedChannel", "Application")]);
        var journal = F.Fact(EvidenceSourceKind.UsnJournal, EvidenceEventType.Created, @"C:\$Extend\$UsnJrnl", at: F.T0.AddMinutes(40), confidence: Confidence.Low) with { FileName = "$UsnJrnl" };
        var rtpOff = F.Fact(EvidenceSourceKind.EventLog, EvidenceEventType.Observed, "Microsoft Defender", at: F.T0.AddMinutes(41),
            attrs: [("EventLog.EventId", "5001"), ("EventLog.Channel", "Microsoft-Windows-Windows Defender/Operational")]);
        var deletion = F.Fact(EvidenceSourceKind.UsnJournal, EvidenceEventType.Deleted, Mod, 500, 3, F.T0.AddMinutes(30));

        var f = F.Run(cleared, journal, rtpOff, deletion).Findings.Single(x => x.RuleId == "CONCEALMENT_CLUSTER");
        Assert.Equal(Confidence.Medium, f.Confidence);
        Assert.Equal(new[] { "defender", "eventlog", "usn" }, f.IndependentFamilies);
        Assert.Equal("context", f.Members.Single(m => m.EvidenceId == deletion.Id).Role);
        Assert.Contains("очищен журнал «Application»", f.Description, StringComparison.Ordinal);

        // Same family only (as on the CI image: Defender exclusion and real-time protection off together), or far apart: nothing.
        var exclusion = F.Fact(EvidenceSourceKind.EventLog, EvidenceEventType.Observed, @"C:\", at: F.T0.AddSeconds(1),
            attrs: [("EventLog.EventId", "5007"), ("Defender.Change", "added"), ("Defender.ExclusionType", "Paths"), ("EventLog.Channel", "Microsoft-Windows-Windows Defender/Operational")]);
        Assert.Empty(F.Run(rtpOff, exclusion).Findings);
        Assert.Empty(F.Run(cleared, journal with { Time = F.T0.AddHours(5) }).Findings);
    }

    [Fact]
    public void Runs_from_a_detached_volume_are_linked_to_shortcuts_of_that_volume()
    {
        var run = F.Fact(EvidenceSourceKind.Prefetch, EvidenceEventType.Executed, @"\VOLUME{01d1-A1B2C3D4}\TOOLS\CLICKER.EXE", at: F.T0, attrs: ("Volume.Serial", "A1B2C3D4"));
        var lnk = F.Fact(EvidenceSourceKind.Lnk, EvidenceEventType.Accessed, @"E:\TOOLS\CLICKER.EXE", at: F.T0.AddMinutes(-1),
            attrs: [("Lnk.DriveSerial", "A1B2C3D4"), ("Lnk.VolumeLabel", "KINGSTON"), ("Lnk.DriveType", "съёмный")]);
        var f = Assert.Single(F.Run(run, lnk).Findings);
        Assert.Equal("REMOVABLE_RUN", f.RuleId);
        Assert.Equal(Confidence.Low, f.Confidence);
        Assert.Contains("KINGSTON", f.Description, StringComparison.Ordinal);
        Assert.Equal("context", f.Members.Single(m => m.EvidenceId == lnk.Id).Role);
    }

    [Fact]
    public void System_state_records_are_not_objects_and_unrelated_records_produce_nothing()
    {
        var a = F.Fact(EvidenceSourceKind.EventLog, EvidenceEventType.Observed, @"C:\", attrs: ("EventLog.EventId", "5007"));
        var b = F.Fact(EvidenceSourceKind.EventLog, EvidenceEventType.Observed, @"C:\", attrs: ("EventLog.EventId", "5007"));
        Assert.False(CorrelationEngine.IsObjectFact(a));
        var r = F.Run(a, b, F.Fact(EvidenceSourceKind.FileSystem, EvidenceEventType.Existed, Mod, 1, 1));
        Assert.Empty(r.Objects);
        Assert.Empty(r.Findings);
    }

    [Fact]
    public void Findings_without_two_families_cannot_be_medium_and_high_needs_identification()
    {
        var f = new Finding
        {
            FindingId = Ulid.NewUlid(F.T0),
            InvestigationId = Ulid.NewUlid(F.T0),
            RuleId = "X",
            Confidence = Confidence.Medium,
            Title = "t",
            Description = "d",
            Rationale = "r",
            IndependentFamilies = ["usn"],
            Members = [new FindingMember(Ulid.NewUlid(F.T0), "basis")],
        };
        Assert.Contains(f.Validate(), p => p.Contains("Medium", StringComparison.Ordinal));
        Assert.Contains((f with { Confidence = Confidence.High, IndependentFamilies = ["a", "b", "c"] }).Validate(), p => p.Contains("High", StringComparison.Ordinal));
        Assert.Empty((f with { Confidence = Confidence.High, IndependentFamilies = ["a", "b", "c"], VerifiedIdentification = true }).Validate());
        Assert.Contains((f with { Members = [new FindingMember(Ulid.NewUlid(F.T0), "context")] }).Validate(), p => p.Contains("basis", StringComparison.Ordinal));
    }

    [Fact]
    public void Two_hundred_thousand_records_are_correlated_quickly()
    {
        var facts = new List<EvidenceFacts>();
        for (var i = 0; i < 100_000; i++)
        {
            var path = $@"C:\Users\player\AppData\Local\Temp\f{i}.dll";
            facts.Add(F.Fact(EvidenceSourceKind.UsnJournal, EvidenceEventType.Deleted, path, (ulong)i, 1, F.T0.AddSeconds(i)));
            facts.Add(F.Fact(EvidenceSourceKind.FileSystem, EvidenceEventType.Existed, path));
        }

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = F.Run([.. facts]);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), $"took {sw.Elapsed}");
        Assert.Equal(100_000, r.Objects.Count);
    }
}

public sealed class LauncherRulesTests
{
    private const string Agent = @"C:\Users\player\Downloads\agent.jar";

    [Fact]
    public void An_agent_from_launcher_settings_that_was_loaded_is_medium()
    {
        var flag = F.Fact(EvidenceSourceKind.Launcher, EvidenceEventType.Observed, Agent, confidence: Confidence.Low, attrs: [("Jvm.Flag", "javaagent"), ("Jvm.Where", "профиль «PvP»")]);
        var loaded = F.Fact(EvidenceSourceKind.Prefetch, EvidenceEventType.Loaded, Agent.ToUpperInvariant(), at: F.T0);
        var f = Assert.Single(F.Run(flag, loaded).Findings);
        Assert.Equal("AGENT_CONFIRMED", f.RuleId);
        Assert.Equal(Confidence.Medium, f.Confidence);
        Assert.Equal(new[] { "launcher", "prefetch" }, f.IndependentFamilies);

        // Configured but nothing shows it ran: no finding (the Low record stays as it is).
        Assert.Empty(F.Run(flag, F.Fact(EvidenceSourceKind.FileSystem, EvidenceEventType.Existed, Agent)).Findings);
    }

    [Fact]
    public void A_modified_game_file_that_was_loaded_is_medium()
    {
        const string jar = @"C:\Users\player\AppData\Roaming\.minecraft\versions\1.8.9\1.8.9.jar";
        var mismatch = F.Fact(EvidenceSourceKind.Launcher, EvidenceEventType.Observed, jar, confidence: Confidence.Medium, attrs: [("Sha1.Actual", "ab"), ("Version.Id", "1.8.9")]);
        var loaded = F.Fact(EvidenceSourceKind.Prefetch, EvidenceEventType.Loaded, jar, at: F.T0);
        var f = Assert.Single(F.Run(mismatch, loaded).Findings);
        Assert.Equal("MODIFIED_FILE_LOADED", f.RuleId);
        Assert.Equal(Confidence.Medium, f.Confidence);
    }
}
