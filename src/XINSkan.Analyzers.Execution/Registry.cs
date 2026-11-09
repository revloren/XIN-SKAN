namespace XINSkan.Analyzers.Execution;

/// <summary>A registry value copied out of the hive: byte[] for binary, int/long for numbers, string otherwise.</summary>
public sealed record RegistryEntry(string Name, object? Value);

/// <summary>
/// Read-only view of one registry root (HKEY_LOCAL_MACHINE of the live system on Windows; a dictionary in tests).
/// Keys are relative to the root.
/// </summary>
public interface IRegistryView
{
    /// <summary>Values of a key, or null when it does not exist or cannot be opened.</summary>
    IReadOnlyList<RegistryEntry>? Values(string key);

    IReadOnlyList<string>? SubKeys(string key);

    /// <summary>Last write time (FILETIME, UTC), or null.</summary>
    long? LastWriteTime(string key);
}

/// <summary>Used where no registry exists (tests, other platforms).</summary>
public sealed class NoRegistry : IRegistryView
{
    public static readonly NoRegistry Instance = new();

    public IReadOnlyList<RegistryEntry>? Values(string key) => null;

    public IReadOnlyList<string>? SubKeys(string key) => null;

    public long? LastWriteTime(string key) => null;
}

internal static class RegistryExtensions
{
    public static object? Value(this IRegistryView registry, string key, string name) =>
        registry.Values(key)?.FirstOrDefault(v => string.Equals(v.Name, name, StringComparison.OrdinalIgnoreCase))?.Value;

    public static int? Int(this IRegistryView registry, string key, string name) =>
        registry.Value(key, name) switch
        {
            int i => i,
            long l when l is >= int.MinValue and <= int.MaxValue => (int)l,
            byte[] { Length: >= 4 } b => BitConverter.ToInt32(b),
            _ => null,
        };

    /// <summary>User profile folder of a SID, from ProfileList.</summary>
    public static string? ProfileOf(this IRegistryView registry, string sid) =>
        registry.Value(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid, "ProfileImagePath") as string;
}
