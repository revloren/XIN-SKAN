using XINSkan.Analyzers.FileHunter;
using XINSkan.Core.IO;
using XINSkan.Core.Paths;
using XINSkan.Core.Pipeline;
using XINSkan.FileHunterTests.Support;
using XINSkan.Investigation;
using XINSkan.Models;
using XINSkan.Security;
using XINSkan.Storage;

namespace XINSkan.InvestigationTests;

/// <summary>The same run with the real SQLite store: what File Hunter found is what the database holds.</summary>
public sealed class InvestigationWithSqliteTests : IDisposable
{
    private readonly PlayerProfile _p = new();
    private readonly string _out = Path.Combine(Path.GetTempPath(), "xinskan-out-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        _p.Dispose();
        if (Directory.Exists(_out))
        {
            foreach (var f in Directory.EnumerateFiles(_out, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(f, FileAttributes.Normal);
            }

            Directory.Delete(_out, recursive: true);
        }
    }

    [Fact]
    public async Task Records_found_by_file_hunter_are_stored_and_the_folder_verifies()
    {
        var platform = new PlatformServices(SystemDirectoryLister.Instance, new TestFileSource(), NoSignatureVerifier.Instance, new FixedProbe(), "read");
        var service = new InvestigationService(platform, (o, i) => InvestigationStore.Create(o, i, TimeProvider.System), TimeProvider.System, "test-1.0");

        var outcome = await service.RunAsync(
            new InvestigationRequest
            {
                OutputRoot = _out,
                FileHunter = new FileHunterOptions { UsersRoot = _p.Users, CurrentProfile = _p.Player, TempFolders = [_p.WindowsTemp] },
                Operator = "Модератор",
            },
            null,
            CancellationToken.None);

        Assert.Empty(outcome.SelfCheck);
        Assert.True(File.Exists(Path.Combine(outcome.Folder, InvestigationStore.DatabaseFileName)));

        using var reader = InvestigationReader.Open(Path.Combine(outcome.Folder, InvestigationStore.DatabaseFileName));
        Assert.Equal(outcome.EvidenceWritten, reader.CountEvidence());
        Assert.Equal(outcome.InvestigationId, reader.ReadInfo().InvestigationId);
        Assert.Equal("Модератор", reader.ReadInfo().Operator);

        var stored = reader.ReadEvidence().ToList();
        var module = reader.ReadModuleResults().Single(m => m.ModuleId == FileHunterAnalyzer.ModuleId);
        Assert.Equal(FileHunterAnalyzer.ModuleId, module.ModuleId);
        Assert.Equal(ModuleState.Completed, module.State);
        Assert.Equal(outcome.EvidenceWritten, reader.ReadModuleResults().Sum(m => m.EvidenceCount));
        Assert.Equal(stored.Count(e => e.ModuleId == FileHunterAnalyzer.ModuleId), module.EvidenceCount);
        Assert.NotEmpty(reader.ReadCoverage());

        var mod = stored.Single(e => e.Target.NormalizedPath == PathNormalizer.Normalize(Path.Combine(_p.MinecraftDir, "mods", "test-client.jar")));
        Assert.Equal("testclient", mod.Attributes["Mod.Id"]);
        Assert.NotNull(mod.ObjectSha256);
        Assert.All(stored.Where(e => e.ModuleId == FileHunterAnalyzer.ModuleId), e => Assert.Equal(Confidence.Informational, e.Confidence));

        // Reading the closed investigation did not change it.
        Assert.Empty(IntegrityManifest.Verify(outcome.Folder));
    }
}
