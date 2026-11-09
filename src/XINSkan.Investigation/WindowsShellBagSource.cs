using System.Runtime.Versioning;
using Microsoft.Win32;
using XINSkan.Analyzers.History;
using XINSkan.Platform.Windows.Registry;

namespace XINSkan.Investigation;

/// <summary>ShellBags of the user running XIN SKAN, read from HKEY_CURRENT_USER (read only).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsShellBagSource : IShellBagSource
{
    public static readonly WindowsShellBagSource Instance = new();

    public IReadOnlyList<(string Name, byte[] Data)>? Values(string key) =>
        RegistryReader.ReadValues(RegistryHive.CurrentUser, key)?
            .Where(v => v.Value is byte[])
            .Select(v => (v.Name, (byte[])v.Value!))
            .ToList();

    public IReadOnlyList<string>? SubKeys(string key) => RegistryReader.ReadSubKeyNames(RegistryHive.CurrentUser, key);

    public long? LastWriteTime(string key) => RegistryReader.ReadLastWriteTime(RegistryHive.CurrentUser, key);
}

/// <summary>Used where no registry exists (tests, other platforms).</summary>
public sealed class NoShellBags : IShellBagSource
{
    public static readonly NoShellBags Instance = new();

    public IReadOnlyList<(string Name, byte[] Data)>? Values(string key) => null;

    public IReadOnlyList<string>? SubKeys(string key) => null;

    public long? LastWriteTime(string key) => null;
}
