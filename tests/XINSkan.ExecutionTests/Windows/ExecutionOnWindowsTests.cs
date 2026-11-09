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

        var registry = WindowsMachineRegistry.Instance;
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
        Assert.Empty(sink.Evidence.Where(e => e.Confidence > Confidence.Low));
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

    private static List<string> Snapshot(string folder) =>
        Directory.Exists(folder)
            ? Directory.EnumerateFiles(folder)
                .Where(f => !Path.GetFileName(f).StartsWith("XINSKAN-PROBE", StringComparison.OrdinalIgnoreCase))
                .Select(f => $"{Path.GetFileName(f)}|{File.GetLastWriteTimeUtc(f).Ticks}|{new FileInfo(f).Length}")
                .Order(StringComparer.Ordinal).ToList()
            : [];
}
