using XINSkan.ExecutionFormats;

namespace XINSkan.ExecutionTests;

/// <summary>Skipped without XINSKAN_EXEC_SAMPLES unless XINSKAN_REQUIRE_SAMPLES=1.</summary>
public sealed class ExecSampleFactAttribute : FactAttribute
{
    public ExecSampleFactAttribute()
    {
        if (Root is null && Environment.GetEnvironmentVariable("XINSKAN_REQUIRE_SAMPLES") != "1")
        {
            Skip = "XINSKAN_EXEC_SAMPLES is not set.";
        }
    }

    public static string? Root => Environment.GetEnvironmentVariable("XINSKAN_EXEC_SAMPLES") is { Length: > 0 } p ? p : null;

    public static string File(params string[] parts) => Path.Combine([Root ?? throw new InvalidOperationException("XINSKAN_EXEC_SAMPLES is required but not set."), .. parts]);
}

/// <summary>
/// Real Prefetch files from Windows XP to 10 (the corpus of the Prefetch library, fetched by CI at a pinned
/// commit). Expected values are the ones that library's own tests assert.
/// </summary>
public sealed class PrefetchSampleTests(ITestOutputHelper output)
{
    private static PrefetchFile Load(params string[] parts) => PrefetchFile.Parse(File.ReadAllBytes(ExecSampleFactAttribute.File(["Prefetch", "Prefetch.Test", "TestFiles", .. parts])))!;

    private static DateTimeOffset At(int y, int mo, int d, int h, int mi, int s, double fraction = 0) =>
        new DateTimeOffset(y, mo, d, h, mi, s, TimeSpan.FromHours(-7)).AddTicks((long)Math.Round(fraction * TimeSpan.TicksPerSecond)).ToUniversalTime();

    private static DateTimeOffset LastRun(PrefetchFile pf) => DateTimeOffset.FromFileTime(pf.LastRunTimes[0]).ToUniversalTime();

    [ExecSampleFact]
    public void Every_file_of_the_corpus_parses_without_problems()
    {
        var root = ExecSampleFactAttribute.File("Prefetch", "Prefetch.Test", "TestFiles");
        var files = Directory.EnumerateFiles(root, "*.pf", SearchOption.AllDirectories).ToList();
        var problems = new List<string>();
        foreach (var f in files)
        {
            var pf = PrefetchFile.Parse(File.ReadAllBytes(f));
            if (pf is null || pf.Version == 0 || pf.Problems.Count > 0)
            {
                problems.Add($"{Path.GetRelativePath(root, f)}: {(pf is null ? "null" : string.Join("; ", pf.Problems))}");
            }
        }

        output.WriteLine($"{files.Count} files, {problems.Count} with problems");
        foreach (var p in problems)
        {
            output.WriteLine(p);
        }

        Assert.True(files.Count >= 50, $"Only {files.Count} files found under {root}.");
        Assert.DoesNotContain(problems, p => !p.Contains("Bad", StringComparison.OrdinalIgnoreCase));
    }

    [ExecSampleFact]
    public void Version_17_windows_2003()
    {
        var pf = Load("Win2k3", "CMD.EXE-087B4001.pf");
        Assert.Equal(17, pf.Version);
        Assert.Equal(0x087B4001u, pf.Hash);
        Assert.Equal(3, pf.RunCount);
        Assert.Equal(At(2016, 1, 15, 16, 1, 40, 0.875), LastRun(pf));
        var v = Assert.Single(pf.Volumes);
        Assert.Equal(@"\DEVICE\HARDDISKVOLUME1", v.DevicePath);
        Assert.Equal(0x64BB3469u, v.Serial);
        Assert.Equal(16, pf.Files.Count);
    }

    [ExecSampleFact]
    public void Version_17_windows_xp()
    {
        var pf = Load("XPPro", "CALC.EXE-02CD573A.pf");
        Assert.Equal(3, pf.RunCount);
        Assert.Equal(At(2016, 1, 13, 15, 5, 51, 0.28125), LastRun(pf));
    }

    [ExecSampleFact]
    public void Version_23_vista()
    {
        var pf = Load("Vista", "EXPLORER.EXE-7A3328DA.pf");
        Assert.Equal(23, pf.Version);
        Assert.Equal(1, pf.RunCount);
        Assert.Equal(At(2016, 1, 16, 13, 2, 0, 0.8326765), LastRun(pf));
        Assert.Equal(0xE8EAB8B5u, Assert.Single(pf.Volumes).Serial);
        Assert.Equal(66, pf.Files.Count);
    }

    [ExecSampleFact]
    public void Version_26_windows_2012_r2()
    {
        var pf = Load("Win2012R2", "NOTEPAD.EXE-D8414F97.pf");
        Assert.Equal(26, pf.Version);
        Assert.Equal(2, pf.RunCount);
        Assert.Equal(At(2016, 1, 16, 14, 40, 31, 0.2944718), LastRun(pf));
        var v = Assert.Single(pf.Volumes);
        Assert.Equal(@"\DEVICE\HARDDISKVOLUME2", v.DevicePath);
        Assert.Equal(0x7450B65Fu, v.Serial);
        Assert.Equal(26, pf.Files.Count);
    }

    [ExecSampleFact]
    public void Version_30_windows_10_compressed()
    {
        var pf = Load("Win10", "DEVENV.EXE-854D7862.pf");
        Assert.Equal(30, pf.Version);
        Assert.True(pf.WasCompressed);
        Assert.Equal(54, pf.RunCount);
        Assert.Equal(403, pf.Files.Count);
        Assert.Equal(At(2016, 1, 13, 9, 50, 34, 0.6578416), LastRun(pf));

        var dcode = Load("Win10", "DCODEDCODEDCODEDCODEDCODEDCOD-E65B9FE8.pf");
        Assert.Equal(2, dcode.RunCount);
        Assert.Equal(2, dcode.Volumes.Count);
        Assert.Equal(57, dcode.Files.Count);
    }
}
