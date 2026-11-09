using System.Diagnostics;
using System.Runtime.Versioning;
using XINSkan.Analyzers.Execution;
using XINSkan.Analyzers.History;
using XINSkan.Core.IO;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.FileHunterTests.Support;
using XINSkan.Investigation;
using XINSkan.Models;
using XINSkan.Platform.Windows;
using XINSkan.Platform.Windows.IO;
using XINSkan.SecurityTests.Windows;

namespace XINSkan.ExecutionTests.Windows;

/// <summary>
/// Prefetch and BAM on the CI machine itself: real registry, real Prefetch folder, real volume names. What the
/// machine records depends on its configuration (servers usually keep Prefetch off), so presence is measured and
/// printed; correctness of what is read and that nothing changes are asserted.
/// </summary>
public sealed class ExecutionOnWindowsTests(ITestOutputHelper output)
{
    [WindowsAdminFact]
    [SupportedOSPlatform("windows")]
    public async Task Prefetch_and_bam_read_the_live_system_and_change_nothing()
    {
        var volumes = WindowsVolumeDirectory.Instance.Volumes();
        foreach (var v in volumes)
        {
            output.WriteLine($"volume {v.Drive} {v.DevicePath} {v.Serial:X8} removable={v.Removable}");
        }

        var system = Environment.GetFolderPath(Environment.SpecialFolder.Windows)[..2];
        var c = Assert.Single(volumes, v => v.Drive.Equals(system, StringComparison.OrdinalIgnoreCase));
        Assert.StartsWith(@"\Device\", c.DevicePath, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(c.Serial);

        // A program run from a temporary folder: a copy of where.exe under a recognisable name.
        var temp = Path.Combine(Path.GetTempPath(), "xinskan-exec-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        var probe = Path.Combine(temp, "xinskan-probe.exe");
        File.Copy(Path.Combine(Environment.SystemDirectory, "where.exe"), probe);
        using (var p = Process.Start(new ProcessStartInfo(probe, "where.exe") { UseShellExecute = false, RedirectStandardOutput = true })!)
        {
            p.WaitForExit(30_000);
        }

        await Task.Delay(15_000); // Prefetch is written about ten seconds after the start

        var registry = WindowsRegistryView.Machine;
        string[] keys = [BamAnalyzer.Roots[0], @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"];
        var before = keys.Select(registry.LastWriteTime).ToList();
        var prefetchFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        var listing = Snapshot(prefetchFolder);

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var options = new HistoryOptions
        {
            Volumes = [system],
            UsersRoot = Path.GetDirectoryName(profile)!,
            CurrentProfile = profile,
            TempFolders = [Path.GetTempPath().TrimEnd('\\')],
            WindowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        };
        var sink = new MemorySink();
        var permissions = new PermissionManager(new WindowsCapabilityProbe(system), TimeProvider.System).Snapshot();
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System).RunAsync(
            Ulid.NewUlid(DateTimeOffset.UtcNow),
            [
                new PrefetchAnalyzer(options, SystemDirectoryLister.Instance, WindowsFileSource.Instance, WindowsVolumeDirectory.Instance, registry),
                new BamAnalyzer(options, registry, WindowsVolumeDirectory.Instance),
            ],
            CancellationToken.None);

        foreach (var m in run.Modules)
        {
            output.WriteLine($"{m.ModuleId}: {m.State}, evidence {m.EvidenceCount}");
        }

        foreach (var cov in sink.Coverage)
        {
            output.WriteLine($"coverage {cov.ModuleId}: {cov.Status}, items {cov.ItemsRead}, {cov.EarliestUtc:u} .. {cov.LatestUtc:u}; {string.Join("; ", cov.Limitations.Select(l => l.Code))}");
        }

        foreach (var e in sink.Evidence.Take(60))
        {
            output.WriteLine($"{e.ModuleId} {e.EventType} {e.Confidence} {e.Timestamp?.ValueUtc:u} {e.Target.RecordedPath} {e.UserSid}");
        }

        output.WriteLine($"probe seen by Prefetch: {sink.Evidence.Any(e => e.ModuleId == "prefetch" && e.Target.FileName!.Equals("XINSKAN-PROBE.EXE", StringComparison.OrdinalIgnoreCase))}");
        output.WriteLine($"probe seen by BAM: {sink.Evidence.Any(e => e.ModuleId == "bam" && e.Target.FileName!.Equals("xinskan-probe.exe", StringComparison.OrdinalIgnoreCase))}");

        Assert.All(run.Modules, m => Assert.True(m.State is ModuleState.Completed or ModuleState.CompletedWithErrors, $"{m.ModuleId}: {m.State} {m.Reason}"));
        Assert.DoesNotContain(sink.Evidence, e => e.Confidence > Confidence.Low);
        Assert.All(sink.Evidence.Where(e => e.EventType == EvidenceEventType.Executed && e.Target.NormalizedPath is not null),
            e => Assert.Matches(@"^[A-Za-z]:\\", e.Target.RecordedPath!));

        // Read-only: the keys did not change. The Prefetch folder is written by Windows for every program that
        // starts meanwhile, so its changes are printed rather than asserted (the reader opens files read-only,
        // which the security tests enforce).
        Assert.Equal(before, keys.Select(registry.LastWriteTime).ToList());
        var after = Snapshot(prefetchFolder);
        output.WriteLine($"Prefetch folder changes during the read: {string.Join(", ", after.Except(listing).Concat(listing.Except(after)))}");
        Directory.Delete(temp, recursive: true);
    }

    [WindowsAdminFact]
    [SupportedOSPlatform("windows")]
    public async Task Locked_amcache_is_read_from_the_volume_after_the_mft_pass()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var system = windows[..2];
        var path = Path.Combine(windows, "AppCompat", "Programs", "Amcache.hve");
        try
        {
            using var direct = WindowsFileSource.Instance.Open(path);
            output.WriteLine($"Amcache.hve opened directly ({direct.Content.Length} bytes): not locked on this machine.");
        }
        catch (IOException ex)
        {
            output.WriteLine($"Amcache.hve is locked: {ex.Message}");
        }

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var options = new HistoryOptions { Volumes = [system], UsersRoot = Path.GetDirectoryName(profile)!, CurrentProfile = profile, WindowsFolder = windows };
        var cache = new VolumeHistoryCache();
        var sink = new MemorySink();
        var permissions = new PermissionManager(new WindowsCapabilityProbe(system), TimeProvider.System).Snapshot();
        var started = Stopwatch.StartNew();
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System).RunAsync(
            Ulid.NewUlid(DateTimeOffset.UtcNow),
            [
                new MftAnalyzer(options, WindowsVolumeOpener.Instance, cache),
                new AmcacheAnalyzer(options, new ProtectedFileSource(WindowsFileSource.Instance, WindowsVolumeOpener.Instance, cache), WindowsVolumeDirectory.Instance),
            ],
            CancellationToken.None);
        output.WriteLine($"took {started.Elapsed.TotalSeconds:F1} s; located: {string.Join(", ", cache.LocatedPaths())}");
        foreach (var m in run.Modules)
        {
            output.WriteLine($"{m.ModuleId}: {m.State}, evidence {m.EvidenceCount} {m.Reason}");
        }

        var coverage = sink.Coverage.Single(c => c.ModuleId == AmcacheAnalyzer.ModuleId);
        output.WriteLine($"amcache coverage: {coverage.Status}, items {coverage.ItemsRead}, {coverage.EarliestUtc:u} .. {coverage.LatestUtc:u}; {string.Join("; ", coverage.Limitations.Select(l => l.Code + ": " + l.Text))}");
        foreach (var e in sink.Evidence.Where(e => e.ModuleId == AmcacheAnalyzer.ModuleId).Take(30))
        {
            output.WriteLine($"  {e.Timestamp?.ValueUtc:u} {e.Target.RecordedPath} {e.Attributes.GetValueOrDefault("Amcache.Sha1")} via {e.Attributes["Amcache.ReadMethod"]}");
        }

        // The current user's NTUSER.DAT is loaded by Windows as well: read from the volume and recovered from its logs.
        var locked = new ProtectedFileSource(WindowsFileSource.Instance, WindowsVolumeOpener.Instance, cache);
        var me = Assert.Single(new UserHives(options, SystemDirectoryLister.Instance, locked, WindowsRegistryView.Machine).Load(otherUsersAllowed: false, includeCurrent: true));
        output.WriteLine($"user {me.User} sid {me.Sid}; problems: {string.Join("; ", me.Problems)}");
        var assist = me.View.SubKeys(UserAssistAnalyzer.Key);
        output.WriteLine($"UserAssist GUIDs in the hive file: {(assist is null ? "none" : string.Join(", ", assist))}");
        Assert.NotNull(me.View.SubKeys("Software"));
        Assert.NotNull(me.Sid);

        Assert.NotNull(cache.Located(path));
        Assert.True(coverage.Status is CollectionStatus.Collected or CollectionStatus.Partial, $"Amcache: {coverage.Status}");
        Assert.True(coverage.ItemsRead > 0, "The system's Amcache lists no files.");
        Assert.DoesNotContain(coverage.Limitations, l => l.Code is "AMCACHE.UNREADABLE" or "AMCACHE.DAMAGED");
    }

    [WindowsAdminFact]
    [SupportedOSPlatform("windows")]
    public async Task Event_logs_are_queried_and_rendered_and_a_crash_from_temp_is_found()
    {
        // Every rendered event of the System log parses.
        var source = WindowsEventLogSource.Instance;
        var sample = source.Query("System", "*", 200);
        Assert.Null(sample.Failure);
        Assert.NotEmpty(sample.Events);
        Assert.All(sample.Events, xml => Assert.NotNull(EventXml.Parse(xml)));
        Assert.NotNull(source.Oldest("System"));
        var missing = source.Query("No-Such-Channel/Operational", "*", 1);
        output.WriteLine($"missing channel: {missing.Failure}");
        Assert.True(missing.ChannelMissing, missing.Failure);

        // A program in a temporary folder that crashes: Windows writes Application Error 1000 for it.
        var temp = Path.Combine(Path.GetTempPath(), "xinskan-crash-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        var crasher = Path.Combine(temp, "xinskan-crash.exe");
        File.Copy(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"), crasher);
        using (var p = Process.Start(new ProcessStartInfo(crasher, "-NoProfile -NonInteractive -Command [Environment]::FailFast('xinskan test crash')") { UseShellExecute = false, CreateNoWindow = true })!)
        {
            p.WaitForExit(60_000);
            output.WriteLine($"crasher exit code 0x{p.ExitCode:X8}");
        }

        await Task.Delay(5000);
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var options = new HistoryOptions
        {
            Volumes = [Environment.GetFolderPath(Environment.SpecialFolder.Windows)[..2]],
            UsersRoot = Path.GetDirectoryName(profile)!,
            CurrentProfile = profile,
            TempFolders = [Path.GetTempPath().TrimEnd('\\')],
        };
        var sink = new MemorySink();
        var permissions = new PermissionManager(new WindowsCapabilityProbe(options.Volumes[0]), TimeProvider.System).Snapshot();
        var run = await new InvestigationRunner(sink, permissions, TimeProvider.System).RunAsync(
            Ulid.NewUlid(DateTimeOffset.UtcNow), [new EventLogAnalyzer(options, source, WindowsVolumeDirectory.Instance)], CancellationToken.None);

        foreach (var c in sink.Coverage)
        {
            output.WriteLine($"{c.Scope}: {c.Status}, events {c.ItemsRead}, oldest {c.EarliestUtc:u}; {string.Join("; ", c.Limitations.Select(l => l.Code))}");
        }

        foreach (var e in sink.Evidence.Take(40))
        {
            output.WriteLine($"{e.Attributes["EventLog.Channel"]} {e.Attributes["EventLog.EventId"]} {e.EventType} {e.Confidence} {e.Timestamp?.ValueUtc:u} {e.Target.RecordedPath} | {e.Description}");
        }

        Assert.Equal(ModuleState.Completed, Assert.Single(run.Modules).State);
        Assert.Equal(CollectionStatus.Collected, sink.Coverage.Single(c => c.Scope == "System").Status);
        output.WriteLine($"crash found: {sink.Evidence.Any(e => e.Target.FileName?.Equals("xinskan-crash.exe", StringComparison.OrdinalIgnoreCase) == true)}");
        Directory.Delete(temp, recursive: true);
    }

    private static List<string> Snapshot(string folder) =>
        Directory.Exists(folder)
            ? Directory.EnumerateFiles(folder)
                .Where(f => !Path.GetFileName(f).StartsWith("XINSKAN-PROBE", StringComparison.OrdinalIgnoreCase))
                .Select(f => $"{Path.GetFileName(f)}|{File.GetLastWriteTimeUtc(f).Ticks}|{new FileInfo(f).Length}")
                .Order(StringComparer.Ordinal).ToList()
            : [];
}
