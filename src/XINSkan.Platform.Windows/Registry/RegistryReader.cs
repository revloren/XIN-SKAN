using System.Runtime.Versioning;
using Microsoft.Win32;

namespace XINSkan.Platform.Windows.Registry;

/// <summary>A registry value copied out of the hive, so no open key handle leaves this layer.</summary>
public sealed record RegistryValueSnapshot(string Name, RegistryValueKind Kind, object? Value);

/// <summary>
/// Reads registry keys of the live system. Every key is opened with the single-argument OpenSubKey, which is
/// read-only; the writable overloads are banned in BannedSymbols.txt and absent from this type.
/// </summary>
[SupportedOSPlatform("windows")]
public static class RegistryReader
{
    /// <returns>Values of the key, or null when the key does not exist.</returns>
    public static IReadOnlyList<RegistryValueSnapshot>? ReadValues(RegistryHive hive, string subKey)
    {
        using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
        using var key = root.OpenSubKey(subKey);
        if (key is null)
        {
            return null;
        }

        var values = new List<RegistryValueSnapshot>();
        foreach (var name in key.GetValueNames())
        {
            values.Add(new RegistryValueSnapshot(
                name,
                key.GetValueKind(name),
                key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames)));
        }

        return values;
    }

    /// <returns>Names of the subkeys, or null when the key does not exist.</returns>
    public static IReadOnlyList<string>? ReadSubKeyNames(RegistryHive hive, string subKey)
    {
        using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
        using var key = root.OpenSubKey(subKey);
        return key?.GetSubKeyNames();
    }

    /// <summary>
    /// Last write time of a key (UTC FILETIME), or null when the key does not exist. Windows updates it when a
    /// value or subkey of the key changes; for ShellBags this is close to the last time a folder's view was saved.
    /// </summary>
    public static unsafe long? ReadLastWriteTime(RegistryHive hive, string subKey)
    {
        using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
        using var key = root.OpenSubKey(subKey);
        if (key is null)
        {
            return null;
        }

        long time;
        var rc = Native.NativeMethods.RegQueryInfoKey(key.Handle, null, null, IntPtr.Zero, null, null, null, null, null, null, null, &time);
        return rc == 0 ? time : null;
    }

    public static bool KeyExists(RegistryHive hive, string subKey)
    {
        using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
        using var key = root.OpenSubKey(subKey);
        return key is not null;
    }
}
