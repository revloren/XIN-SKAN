using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using XINSkan.Analyzers.FileHunter;
using XINSkan.Analyzers.FileHunter.Content;
using XINSkan.Core.IO;
using XINSkan.Core.Paths;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.FileHunterTests.Support;
using XINSkan.Models;

namespace XINSkan.FileHunterTests;

public sealed class FileHunterScenarioTests(ITestOutputHelper output) : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 9, 0, 0, 0, TimeSpan.Zero);
    private readonly PlayerProfile _p = new();
    private readonly TestFileSource _files = new();

    public void Dispose() => _p.Dispose();

    private FileHunterOptions Options() => new()
    {
        UsersRoot = _p.Users,
        CurrentProfile = _p.Player,
        TempFolders = [_p.WindowsTemp],
    };

    private async Task<(MemorySink Sink, InvestigationRunResult Result)> Run(
        FileHunterOptions? options = null,
        IDirectoryLister? lister = null,
        Capability[]? capabilities = null,
        CancellationToken ct = default)
    {
        var sink = new MemorySink();
        var permissions = new PermissionManager(new FixedProbe(capabilities ?? []), TimeProvider.System).Snapshot();
        var analyzer = new FileHunterAnalyzer(options ?? Options(), lister ?? SystemDirectoryLister.Instance, _files, NoSignatureVerifier.Instance);
        var result = await new InvestigationRunner(sink, permissions, TimeProvider.System).RunAsync(Ulid.NewUlid(T0), [analyzer], ct);
        return (sink, result);
    }

    private static Evidence Find(MemorySink s, string path) =>
        s.Evidence.Single(e => e.Target.NormalizedPath == PathNormalizer.Normalize(path));

    [Fact]
    public async Task Records_exactly_the_relevant_files_and_minecraft_folders()
    {
        var (sink, result) = await Run();

        Assert.Equal(ModuleState.Completed, result.Modules[0].State);
        var recorded = sink.Evidence.Select(e => e.Target.NormalizedPath!).ToHashSet(StringComparer.Ordinal);
        var expected = _p.ExpectedFiles.Concat(_p.ExpectedDirectories).Select(x => PathNormalizer.Normalize(x)!).ToHashSet(StringComparer.Ordinal);

        Assert.Empty(expected.Except(recorded));
        Assert.Empty(recorded.Except(expected));
        Assert.All(sink.Evidence, e =>
        {
            Assert.Empty(e.Validate());
            Assert.Equal(Confidence.Informational, e.Confidence);
            Assert.Equal(EvidenceEventType.Existed, e.EventType);
            Assert.Contains(e.Limitations, l => l.Code == "FS.SI_TIMES");
        });
    }

    [Fact]
    public async Task Ordinary_files_outside_drop_locations_are_not_even_opened()
    {
        var opened = new List<string>();
        _files.Fail = path =>
        {
            lock (opened)
            {
                opened.Add(path);
            }

            return null;
        };

        await Run();

        Assert.DoesNotContain(opened, p => p.EndsWith("big.png", StringComparison.Ordinal));
        Assert.DoesNotContain(opened, p => p.EndsWith("readme.txt", StringComparison.Ordinal));
        Assert.DoesNotContain(opened, p => p.EndsWith("cache.dat", StringComparison.Ordinal));
        Assert.Contains(opened, p => p.EndsWith("photo.png", StringComparison.Ordinal)); // drop location: content is checked
    }

    [Fact]
    public async Task Hashes_are_the_sha256_of_the_file_bytes()
    {
        var (sink, _) = await Run();
        foreach (var path in _p.ExpectedFiles)
        {
            var e = Find(sink, path);
            Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))), e.ObjectSha256!.Value.Hex);
            Assert.Equal(new FileInfo(path).Length, e.Target.Size);
        }
    }

    [Fact]
    public async Task Mod_metadata_and_class_packages_are_extracted()
    {
        var (sink, _) = await Run();

        var fabric = Find(sink, Path.Combine(_p.MinecraftDir, "mods", "test-client.jar"));
        Assert.Equal("fabric", fabric.Attributes["Mod.Loader"]);
        Assert.Equal("testclient", fabric.Attributes["Mod.Id"]);
        Assert.Equal("Test Client", fabric.Attributes["Mod.Name"]);
        Assert.Equal("1.0.0", fabric.Attributes["Mod.Version"]);
        Assert.Equal("3", fabric.Attributes["Archive.Classes"]);
        Assert.StartsWith("net.example.testclient", fabric.Attributes["Jar.TopPackages"], StringComparison.Ordinal);
        Assert.Contains("мод Fabric «Test Client» версии 1.0.0", fabric.Description, StringComparison.Ordinal);
        Assert.Equal("MinecraftTree", fabric.Attributes["Selection"]);

        var forge = Find(sink, Path.Combine(_p.MinecraftDir, "mods", "forge-mod.jar"));
        Assert.Equal("forge", forge.Attributes["Mod.Loader"]);
        Assert.Equal("examplemod", forge.Attributes["Mod.Id"]);
        Assert.Equal("Example Mod", forge.Attributes["Mod.Name"]);
        Assert.Equal("2.3", forge.Attributes["Mod.Version"]);
    }

    [Fact]
    public async Task Java_agent_manifest_is_flagged_and_continuation_lines_are_joined()
    {
        var (sink, _) = await Run();
        var agent = Find(sink, Path.Combine(_p.MinecraftDir, "mods", "agent.jar"));
        Assert.Equal("org.example.agent.Agent", agent.Attributes["Manifest.Premain-Class"]);
        Assert.Equal("org.example.agent.Agent", agent.Attributes["Manifest.Agent-Class"]);
        Assert.Contains("Java-агент", agent.Description, StringComparison.Ordinal);
        Assert.DoesNotContain(agent.Attributes.Keys, k => k == "Manifest.Sealed"); // per-entry section is not mixed in
    }

    [Fact]
    public async Task Renamed_archive_is_recognised_by_content()
    {
        var (sink, _) = await Run();
        var renamed = Find(sink, _p.P("Downloads", "renamed.txt"));
        Assert.Equal("Zip", renamed.Attributes["Content"]);
        Assert.Equal("true", renamed.Attributes["ExtensionMismatch"]);
        Assert.Equal("DropLocationContent", renamed.Attributes["Selection"]);
        Assert.Contains("не соответствует расширению «.txt»", renamed.Description, StringComparison.Ordinal);

        var payload = Find(sink, _p.P("AppData", "Local", "Temp", "payload.tmp"));
        Assert.Equal("PortableExecutable", payload.Attributes["Content"]);
        Assert.Equal("true", payload.Attributes["ExtensionMismatch"]);
    }

    [Fact]
    public async Task Executable_version_resource_reveals_its_original_name()
    {
        var (sink, _) = await Run();
        var tool = Find(sink, _p.P("Downloads", "tool.exe"));
        Assert.Equal("System.Private.CoreLib.dll", tool.Attributes["Pe.OriginalFilename"]);
        Assert.Equal("Microsoft Corporation", tool.Attributes["Pe.CompanyName"]);
        Assert.Equal("DLL", tool.Attributes["Pe.Kind"]);
        Assert.Equal("true", tool.Attributes["Pe.DotNet"]);
        Assert.Contains("исходное имя по ресурсу версии — System.Private.CoreLib.dll", tool.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Damaged_archive_is_recorded_as_partial_and_the_module_continues()
    {
        var (sink, result) = await Run();
        var broken = Find(sink, Path.Combine(_p.MinecraftDir, "mods", "broken.jar"));
        Assert.Equal(CollectionStatus.Partial, broken.CollectionStatus);
        Assert.Contains(broken.Limitations, l => l.Code == "ARCHIVE.PARTIAL");
        Assert.NotNull(broken.ObjectSha256);
        Assert.Equal(ModuleState.Completed, result.Modules[0].State);
    }

    [Fact]
    public async Task Links_are_not_followed_and_this_is_stated_in_coverage()
    {
        var (sink, _) = await Run();
        var profile = sink.Coverage.Single(c => c.Scope == _p.Player);
        Assert.Equal(CollectionStatus.Partial, profile.Status);
        Assert.Contains(profile.Limitations, l => l.Code == "FS.LINKS");
        Assert.DoesNotContain(sink.Evidence, e => e.Target.RecordedPath!.Contains(Path.Combine("Games", "loop"), StringComparison.Ordinal));
    }

    [Fact]
    public async Task Other_profiles_need_the_capability_and_system_profiles_are_skipped()
    {
        var other = Path.Combine(_p.Users, "other", "Downloads", "other.jar");
        var (without, _) = await Run();
        Assert.DoesNotContain(without.Evidence, e => e.Target.RecordedPath == other);
        Assert.Contains(without.Coverage.Single(c => c.Scope.StartsWith("Область поиска", StringComparison.Ordinal)).Limitations,
            l => l.Text.Contains(Path.Combine(_p.Users, "other"), StringComparison.Ordinal));

        var (with, _) = await Run(capabilities: [Capability.OtherUserProfiles]);
        Assert.Contains(with.Evidence, e => e.Target.RecordedPath == other);
        Assert.DoesNotContain(with.Evidence, e => e.Target.RecordedPath!.Contains(Path.Combine("Public", "Desktop"), StringComparison.Ordinal));
    }

    [Fact]
    public async Task Unreadable_folders_are_counted_reported_and_capped()
    {
        var denied = Path.Combine(_p.Player, "AppData", "Local");
        var lister = new FaultyLister(d => d.StartsWith(denied, StringComparison.Ordinal) || d.EndsWith("Pictures", StringComparison.Ordinal)
            ? new UnauthorizedAccessException("denied in test") : null);

        var (sink, result) = await Run(options: Options() with { MaxReportedErrors = 1 }, lister: lister);

        Assert.Equal(ModuleState.CompletedWithErrors, result.Modules[0].State);
        Assert.Equal(2, sink.Errors.Count); // one detailed error + one summary of the rest
        Assert.Contains(sink.Errors, e => e.Message.Contains("Ещё 1", StringComparison.Ordinal));
        var profile = sink.Coverage.Single(c => c.Scope == _p.Player);
        Assert.Contains(profile.Limitations, l => l.Code == "FS.INACCESSIBLE" && l.Text.StartsWith("2 ", StringComparison.Ordinal));
        Assert.DoesNotContain(sink.Evidence, e => e.Target.RecordedPath == _p.P("AppData", "Local", "Temp", "payload.tmp"));
    }

    [Fact]
    public async Task Locked_or_denied_files_are_recorded_with_metadata_only()
    {
        var jar = Path.Combine(_p.MinecraftDir, "mods", "forge-mod.jar");
        _files.Fail = path => path == jar ? new UnauthorizedAccessException("denied in test") : null;

        var (sink, result) = await Run();
        var e = Find(sink, jar);
        Assert.Equal(CollectionStatus.Partial, e.CollectionStatus);
        Assert.Null(e.ObjectSha256);
        Assert.Contains(e.Limitations, l => l.Code == "CONTENT.ACCESS_DENIED");
        Assert.Equal(ModuleState.Completed, result.Modules[0].State);
    }

    [Fact]
    public async Task Files_above_the_hash_limit_are_recorded_without_hash()
    {
        var (sink, _) = await Run(options: Options() with { MaxHashBytes = 100 });
        var e = Find(sink, Path.Combine(_p.MinecraftDir, "mods", "test-client.jar"));
        Assert.Null(e.ObjectSha256);
        Assert.Equal(CollectionStatus.Partial, e.CollectionStatus);
        Assert.Contains(e.Limitations, l => l.Code == "HASH.SIZE_LIMIT");
        Assert.Equal("fabric", e.Attributes["Mod.Loader"]); // metadata is still read
    }

    [Fact]
    public async Task Download_origin_is_read_from_zone_identifier()
    {
        var jar = Path.Combine(_p.MinecraftDir, "mods", "test-client.jar");
        _files.Streams[(jar, "Zone.Identifier")] = Encoding.UTF8.GetBytes("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.org/page\r\nHostUrl=https://example.org/test-client.jar\r\n");

        var (sink, _) = await Run();
        var e = Find(sink, jar);
        Assert.Equal("3", e.Attributes["Zone.Id"]);
        Assert.Equal("https://example.org/test-client.jar", e.Attributes["Zone.HostUrl"]);
        Assert.Equal("https://example.org/page", e.Attributes["Zone.ReferrerUrl"]);
    }

    [Fact]
    public async Task Cancellation_stops_promptly_and_keeps_what_was_recorded()
    {
        using var cts = new CancellationTokenSource();
        var seen = 0;
        _files.Fail = _ =>
        {
            if (Interlocked.Increment(ref seen) == 3)
            {
                cts.Cancel();
            }

            return null;
        };

        var sw = Stopwatch.StartNew();
        var (_, result) = await Run(ct: cts.Token);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(30));
        Assert.True(result.Cancelled);
        Assert.Equal(ModuleState.Cancelled, result.Modules[0].State);
    }

    [Fact]
    public async Task An_unexpected_failure_while_processing_stops_the_walker_instead_of_hanging()
    {
        _files.Fail = _ => new InvalidOperationException("unexpected bug in a file source");

        var run = Run();
        var finished = await Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds(30)));
        Assert.Same(run, finished);
        var (_, result) = await run;
        Assert.Equal(ModuleState.Failed, result.Modules[0].State);
        Assert.Contains(result.Modules[0].Errors, e => e.Message.Contains("unexpected bug", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Large_tree_is_walked_within_budget()
    {
        var bulk = _p.P("AppData", "Local", "BigApp");
        for (var d = 0; d < 200; d++)
        {
            var dir = Path.Combine(bulk, $"d{d}");
            Directory.CreateDirectory(dir);
            for (var f = 0; f < 100; f++)
            {
                File.WriteAllBytes(Path.Combine(dir, $"f{f}.cache"), [1, 2, 3]);
            }
        }

        var sw = Stopwatch.StartNew();
        var (sink, result) = await Run();
        sw.Stop();

        var items = sink.Coverage.Single(c => c.Scope == _p.Player).ItemsRead;
        output.WriteLine($"Walked {items} entries in {sw.Elapsed.TotalSeconds:F2} s");
        Assert.Equal(ModuleState.Completed, result.Modules[0].State);
        Assert.True(items > 20_000);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(60), $"Took {sw.Elapsed}.");
        Assert.DoesNotContain(sink.Evidence, e => e.Target.RecordedPath!.StartsWith(bulk, StringComparison.Ordinal));
    }
}
