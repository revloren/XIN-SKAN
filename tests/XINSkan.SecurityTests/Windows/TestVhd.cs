using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace XINSkan.SecurityTests.Windows;

/// <summary>Runs only on Windows with administrator rights (CI windows runners qualify).</summary>
public sealed class WindowsAdminFactAttribute : FactAttribute
{
    public WindowsAdminFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Requires Windows.";
        }
        else if (!IsAdmin())
        {
            Skip = "Requires administrator rights.";
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsAdmin()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }
}

/// <summary>
/// A throw-away NTFS volume backed by a VHD file in the temp folder. Integration tests investigate this volume,
/// never the runner's real disks. Created and removed with diskpart.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class TestVhd : IDisposable
{
    private readonly string _vhdPath;

    private TestVhd(string vhdPath, char letter)
    {
        _vhdPath = vhdPath;
        Letter = letter;
    }

    public char Letter { get; }

    public string Root => $@"{Letter}:\";

    public static TestVhd Create(int sizeMb = 256)
    {
        var used = DriveInfo.GetDrives().Select(d => char.ToUpperInvariant(d.Name[0])).ToHashSet();
        var letter = "XWVUTSRQPONMLKJ".First(c => !used.Contains(c));
        var path = Path.Combine(Path.GetTempPath(), $"xinskan-{Guid.NewGuid():N}.vhdx");

        RunDiskpart(
            $"create vdisk file=\"{path}\" maximum={sizeMb} type=expandable",
            $"select vdisk file=\"{path}\"",
            "attach vdisk",
            "create partition primary",
            "format fs=ntfs quick label=XINTEST",
            $"assign letter={letter}");

        for (var i = 0; i < 50 && !Directory.Exists($@"{letter}:\"); i++)
        {
            Thread.Sleep(200);
        }

        if (!Directory.Exists($@"{letter}:\"))
        {
            throw new InvalidOperationException($"Test volume {letter}: did not appear.");
        }

        // A freshly formatted data volume may not have a change journal yet; the fixture creates one (32 MiB, the
        // Windows default) so the test can measure whether reading adds records.
        Run("fsutil.exe", $"usn createjournal m=33554432 a=8388608 {letter}:");
        return new TestVhd(path, letter);
    }

    public void Dispose()
    {
        try
        {
            RunDiskpart($"select vdisk file=\"{_vhdPath}\"", "detach vdisk");
        }
        finally
        {
            if (File.Exists(_vhdPath))
            {
                File.Delete(_vhdPath);
            }
        }
    }

    private static void RunDiskpart(params string[] commands)
    {
        var script = Path.Combine(Path.GetTempPath(), $"xinskan-diskpart-{Guid.NewGuid():N}.txt");
        File.WriteAllLines(script, commands);
        try
        {
            Run("diskpart.exe", $"/s \"{script}\"");
        }
        finally
        {
            File.Delete(script);
        }
    }

    private static void Run(string exe, string arguments)
    {
        using var p = Process.Start(new ProcessStartInfo(exe, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        })!;
        var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        if (!p.WaitForExit(120_000))
        {
            p.Kill(entireProcessTree: true);
            throw new TimeoutException($"{exe} did not finish in 2 minutes.");
        }

        if (p.ExitCode != 0)
        {
            throw new InvalidOperationException($"{exe} {arguments} failed ({p.ExitCode}): {output}");
        }
    }
}
