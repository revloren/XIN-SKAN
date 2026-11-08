using Microsoft.Win32;

namespace XINSkan.NegativeBuild;

/// <summary>Each line below must be reported as RS0030 by the banned-API analyzer.</summary>
public static class ForbiddenCalls
{
    public static void DeleteEvidence(string path) => System.IO.File.Delete(path);

    public static void RemoveFolder(string path) => System.IO.Directory.Delete(path, recursive: true);

    public static void RunCleaner() => System.Diagnostics.Process.Start("cleaner.exe");

    public static void OpenRegistryForWriting(RegistryKey key) => key.OpenSubKey("Software", writable: true)?.Dispose();
}
