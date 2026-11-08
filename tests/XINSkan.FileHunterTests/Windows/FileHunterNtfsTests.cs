using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using XINSkan.Analyzers.FileHunter;
using XINSkan.Core.IO;
using XINSkan.Core.Paths;
using XINSkan.Core.Permissions;
using XINSkan.Core.Pipeline;
using XINSkan.FileHunterTests.Support;
using XINSkan.Models;
using XINSkan.Platform.Windows;
using XINSkan.Platform.Windows.IO;
using XINSkan.SecurityTests.Windows;

namespace XINSkan.FileHunterTests.Windows;

/// <summary>
/// File Hunter with the real Windows implementations on a throw-away NTFS volume: identities, alternate streams,
/// long paths, signatures, and proof that a full run leaves the volume unchanged.
/// </summary>
public sealed class FileHunterNtfsTests(ITestOutputHelper output)
{
    [WindowsAdminFact]
    [SupportedOSPlatform("windows")]
    public async Task Full_run_on_ntfs_records_identity_origin_signatures_and_changes_nothing()
    {
        using var vhd = TestVhd.Create(512);
        using var p = new PlayerProfile(withOtherProfile: true, baseDirectory: vhd.Root);

        // Real alternate stream with a download origin.
        var jar = Path.Combine(p.MinecraftDir, "mods", "test-client.jar");
        File.WriteAllText(jar + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.org/test-client.jar\r\n");

        // Path beyond MAX_PATH.
        var deep = p.P("Documents");
        while (deep.Length < 300)
        {
            deep = Path.Combine(deep, "very-long-folder-name-for-path-testing");
        }

        Directory.CreateDirectory(deep);
        var longJar = Path.Combine(deep, "long.jar");
        File.WriteAllBytes(longJar, Jar.FabricMod("long", "Long", "1"));

        // Signatures: a Microsoft-signed executable, a tampered copy, and an unsigned build output.
        var signedSource = FindDotnetExe();
        var signed = p.P("Downloads", "signed.exe");
        var tampered = p.P("Downloads", "tampered.exe");
        var unsigned = p.P("Downloads", "unsigned.exe");
        File.Copy(signedSource, signed);
        var bytes = File.ReadAllBytes(signedSource);
        bytes[bytes.Length / 2] ^= 0xFF;
        File.WriteAllBytes(tampered, bytes);
        File.Copy(typeof(FileHunterNtfsTests).Assembly.Location, unsigned);

        var tool = p.P("Downloads", "tool.exe");
        File.SetAttributes(tool, File.GetAttributes(tool) | FileAttributes.Hidden);

        Thread.Sleep(2000);
        var usnBefore = QueryJournal(vhd.Letter);
        var timesBefore = p.ExpectedFiles.ToDictionary(f => f, f => (File.GetLastWriteTimeUtc(f), File.GetCreationTimeUtc(f)));

        var sink = new MemorySink();
        var analyzer = new FileHunterAnalyzer(
            new FileHunterOptions { UsersRoot = p.Users, CurrentProfile = p.Player, TempFolders = [p.WindowsTemp] },
            SystemDirectoryLister.Instance,
            WindowsFileSource.Instance,
            AuthenticodeVerifier.Instance);
        var permissions = new PermissionManager(new WindowsCapabilityProbe(vhd.Letter + ":"), TimeProvider.System).Snapshot();
        var result = await new InvestigationRunner(sink, permissions, TimeProvider.System).RunAsync(Ulid.NewUlid(DateTimeOffset.UtcNow), [analyzer], CancellationToken.None);

        Thread.Sleep(2000);
        var usnAfter = QueryJournal(vhd.Letter);
        output.WriteLine($"Module: {result.Modules[0].State}, evidence {sink.Evidence.Count}; USN next {usnBefore.NextUsn} -> {usnAfter.NextUsn}");
        foreach (var err in sink.Errors)
        {
            output.WriteLine("error: " + err.Message);
        }

        Evidence Find(string path) => sink.Evidence.Single(e => e.Target.NormalizedPath == PathNormalizer.Normalize(path));

        Assert.Equal(ModuleState.Completed, result.Modules[0].State);

        // Identity from the open handle: the key that links live files to MFT and USN records.
        foreach (var f in p.ExpectedFiles)
        {
            var e = Find(f);
            Assert.NotNull(e.Target.MftEntry);
            Assert.True(e.Target.MftSequence > 0, f);
            Assert.NotNull(e.Target.VolumeSerial);
        }

        var z = Find(jar);
        Assert.Equal("https://example.org/test-client.jar", z.Attributes["Zone.HostUrl"]);
        Assert.Equal("3", z.Attributes["Zone.Id"]);

        var l = Find(longJar);
        Assert.NotNull(l.ObjectSha256);
        Assert.Equal("long", l.Attributes["Mod.Id"]);

        Assert.Equal(nameof(SignatureStatus.Valid), Find(signed).Attributes["Signature"]);
        Assert.Equal(nameof(SignatureStatus.Tampered), Find(tampered).Attributes["Signature"]);
        Assert.Equal(nameof(SignatureStatus.NotSigned), Find(unsigned).Attributes["Signature"]);
        Assert.Contains("Hidden", Find(tool).Attributes["FileAttributes"], StringComparison.Ordinal);

        // Read-Only: the analyzer's full run leaves the volume's journal and files unchanged.
        Assert.Equal(usnBefore.JournalId, usnAfter.JournalId);
        Assert.Equal(usnBefore.NextUsn, usnAfter.NextUsn);
        foreach (var (f, t) in timesBefore)
        {
            Assert.Equal(t, (File.GetLastWriteTimeUtc(f), File.GetCreationTimeUtc(f)));
        }
    }

    private static string FindDotnetExe()
    {
        var dir = new DirectoryInfo(RuntimeEnvironment.GetRuntimeDirectory());
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "dotnet.exe")))
        {
            dir = dir.Parent;
        }

        return dir is null ? throw new FileNotFoundException("dotnet.exe not found above the runtime directory.") : Path.Combine(dir.FullName, "dotnet.exe");
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
