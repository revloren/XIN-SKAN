using XINSkan.Analyzers.Minecraft;
using XINSkan.Core.IO;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.FileHunterTests.Support;
using XINSkan.Models;

namespace XINSkan.MinecraftTests;

/// <summary>Skipped without XINSKAN_MC_SAMPLES unless XINSKAN_REQUIRE_SAMPLES=1.</summary>
public sealed class McSampleFactAttribute : FactAttribute
{
    public McSampleFactAttribute()
    {
        if (Root is null && Environment.GetEnvironmentVariable("XINSKAN_REQUIRE_SAMPLES") != "1")
        {
            Skip = "XINSKAN_MC_SAMPLES is not set.";
        }
    }

    public static string? Root => Environment.GetEnvironmentVariable("XINSKAN_MC_SAMPLES") is { Length: > 0 } p ? p : null;
}

/// <summary>
/// A real version from Mojang (CI downloads the 1.20.1 version file, checks it against the version manifest's
/// SHA-1, then the client JAR and the first libraries): the parser reads the real format, every downloaded file
/// matches, and a one-byte change to the client is found and rated Medium.
/// </summary>
public sealed class RealVersionTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _copy = Path.Combine(Path.GetTempPath(), "xinskan-mc-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_copy))
        {
            Directory.Delete(_copy, recursive: true);
        }
    }

    private static string Source => McSampleFactAttribute.Root ?? throw new InvalidOperationException("XINSKAN_MC_SAMPLES is required but not set.");

    [McSampleFact]
    public void Mojang_files_match_their_version_file()
    {
        var root = Path.Combine(Source, ".minecraft");
        var integrity = new VersionIntegrity(new Reader(SystemDirectoryLister.Instance, new TestFileSource()), long.MaxValue);
        var r = Assert.Single(integrity.CheckAll(root));
        output.WriteLine($"{r.Id}: main {r.MainClass}, client {r.Client?.Status} {r.Client?.ActualSha1}, libraries {r.Libraries.Count}: " +
                         string.Join(", ", r.Libraries.GroupBy(l => l.Status).Select(g => $"{g.Key} {g.Count()}")));
        Assert.Equal("1.20.1", r.Id);
        Assert.True(r.MainClassKnown);
        Assert.True(r.ClientFromMojang);
        Assert.Equal(HashStatus.Match, r.Client!.Status);
        Assert.True(r.Libraries.Count > 30, $"only {r.Libraries.Count} libraries read from the real version file");
        Assert.True(r.Libraries.Count(l => l.Status == HashStatus.Match) >= 5);
        Assert.DoesNotContain(r.Libraries, l => l.Status == HashStatus.Mismatch);
        Assert.Empty(r.JvmFlags); // the real file has -Djava.library.path and similar, nothing that loads code
    }

    [McSampleFact]
    public async Task One_changed_byte_in_the_client_is_found_and_rated_medium()
    {
        var profile = Path.Combine(_copy, "Users", "player");
        var target = Path.Combine(profile, "AppData", "Roaming", ".minecraft");
        foreach (var file in Directory.EnumerateFiles(Path.Combine(Source, ".minecraft"), "*", SearchOption.AllDirectories))
        {
            var to = Path.Combine(target, Path.GetRelativePath(Path.Combine(Source, ".minecraft"), file));
            Directory.CreateDirectory(Path.GetDirectoryName(to)!);
            File.Copy(file, to);
        }

        var jar = Path.Combine(target, "versions", "1.20.1", "1.20.1.jar");
        var bytes = File.ReadAllBytes(jar);
        bytes[bytes.Length / 2] ^= 0x01;
        File.WriteAllBytes(jar, bytes);

        var sink = new MemorySink();
        var permissions = new PermissionManager(new FixedProbe(), TimeProvider.System).Snapshot();
        await new InvestigationRunner(sink, permissions, TimeProvider.System).RunAsync(Ulid.NewUlid(DateTimeOffset.UtcNow),
            [new MinecraftIntegrityAnalyzer(new MinecraftOptions { UsersRoot = Path.Combine(_copy, "Users"), CurrentProfile = profile }, SystemDirectoryLister.Instance, new TestFileSource())],
            CancellationToken.None);

        var changed = sink.Evidence.Single(e => e.Target.FileName == "1.20.1.jar");
        output.WriteLine(changed.Description);
        Assert.Equal(Confidence.Medium, changed.Confidence);
        Assert.StartsWith("https://piston-data.mojang.com/", changed.Attributes["Download.Url"], StringComparison.Ordinal);
    }
}
