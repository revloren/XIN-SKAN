using XINSkan.Analyzers.FileHunter.Scanning;
using XINSkan.Analyzers.History;
using XINSkan.Core.IO;
using XINSkan.ExecutionFormats;

namespace XINSkan.Analyzers.Execution;

/// <summary>
/// A user's registry built from the hive files: keys are relative to HKEY_CURRENT_USER, and
/// "Software\Classes\…" goes to UsrClass.dat as Windows maps it.
/// </summary>
public sealed class HiveRegistryView(HiveKey? ntuser, HiveKey? usrClass) : IRegistryView
{
    private const string Classes = @"Software\Classes";

    public IReadOnlyList<RegistryEntry>? Values(string key) => Open(key)?.Values().Select(v => new RegistryEntry(v.Name, Convert(v))).ToList();

    public IReadOnlyList<string>? SubKeys(string key) => Open(key)?.SubKeys().Select(k => k.Name).ToList();

    public long? LastWriteTime(string key) => Open(key)?.LastWriteTime;

    private HiveKey? Open(string key)
    {
        if (usrClass is not null && key.StartsWith(Classes, StringComparison.OrdinalIgnoreCase) && (key.Length == Classes.Length || key[Classes.Length] == '\\'))
        {
            return usrClass.Open(key[Classes.Length..]);
        }

        return ntuser?.Open(key);
    }

    private static object? Convert(HiveValue v) => v.Type switch
    {
        HiveValue.RegDword when v.Data.Length >= 4 => (int)(v.AsNumber() ?? 0),
        HiveValue.RegQword when v.Data.Length >= 8 => v.AsNumber(),
        HiveValue.RegSz or HiveValue.RegExpandSz => v.AsString(),
        _ => v.Data,
    };
}

/// <summary>ShellBags of a registry view (binary values only).</summary>
public sealed class RegistryShellBags(IRegistryView view) : IShellBagSource
{
    public IReadOnlyList<(string Name, byte[] Data)>? Values(string key) =>
        view.Values(key)?.Where(v => v.Value is byte[]).Select(v => (v.Name, (byte[])v.Value!)).ToList();

    public IReadOnlyList<string>? SubKeys(string key) => view.SubKeys(key);

    public long? LastWriteTime(string key) => view.LastWriteTime(key);
}

/// <summary>A user's registry read from NTUSER.DAT and UsrClass.dat.</summary>
public sealed record UserRegistry(string User, string Profile, string? Sid, IRegistryView View, IReadOnlyList<string> Problems);

/// <summary>
/// Reads the registry files of every profile (the current one, and others only with permission), once per
/// investigation; hives Windows has loaded are read from the volume (<see cref="IProtectedFileSource"/>).
/// </summary>
public sealed class UserHives(HistoryOptions options, IDirectoryLister lister, IProtectedFileSource files, IRegistryView machine)
{
    private const long MaxHive = 512L * 1024 * 1024;
    private readonly Dictionary<string, UserRegistry> _loaded = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<UserRegistry> Load(bool otherUsersAllowed, bool includeCurrent)
    {
        var result = new List<UserRegistry>();
        IReadOnlyList<FsEntry> entries;
        try
        {
            entries = lister.List(options.UsersRoot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return result;
        }

        foreach (var e in entries.Where(e => e.IsDirectory && !e.IsReparsePoint && !ScopeBuilder.IsSystemProfile(e.Name)).OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
        {
            var current = string.Equals(e.FullPath.TrimEnd('\\', '/'), options.CurrentProfile.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase);
            if ((current && !includeCurrent) || (!current && !otherUsersAllowed))
            {
                continue;
            }

            if (!_loaded.TryGetValue(e.FullPath, out var user))
            {
                _loaded[e.FullPath] = user = Read(e.Name, e.FullPath);
            }

            result.Add(user);
        }

        return result;
    }

    private UserRegistry Read(string name, string profile)
    {
        var problems = new List<string>();
        var ntuser = Hive(ProgramRelevance.Join(profile, "NTUSER.DAT"), problems);
        var classes = Hive(ProgramRelevance.Join(profile, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"), problems);
        return new UserRegistry(name, profile, Sid(profile), new HiveRegistryView(ntuser?.Root, classes?.Root), problems);
    }

    private RegistryHive? Hive(string path, List<string> problems)
    {
        var file = files.Read(path, MaxHive);
        if (file is null)
        {
            problems.Add($"{ProgramRelevance.FileName(path)} нет.");
            return null;
        }

        if (file.Data.Length == 0)
        {
            problems.Add($"{ProgramRelevance.FileName(path)} не прочитан: {string.Join(" ", file.Problems)}");
            return null;
        }

        var logs = new[] { path + ".LOG1", path + ".LOG2" }.Select(l => files.Read(l, MaxHive)).Where(l => l is { Data.Length: > 0 }).Select(l => l!.Data).ToArray();
        var hive = RegistryHive.Open(file.Data, logs);
        if (hive?.Root is null)
        {
            problems.Add($"{ProgramRelevance.FileName(path)} повреждён.");
            return null;
        }

        problems.AddRange(file.Problems.Select(p => $"{ProgramRelevance.FileName(path)}: {p}"));
        if (hive.RecoveryIncomplete)
        {
            problems.Add($"{ProgramRelevance.FileName(path)}: последние изменения могут отсутствовать (журналы применены не полностью).");
        }

        return hive;
    }

    private string? Sid(string profile)
    {
        const string list = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
        foreach (var sid in machine.SubKeys(list) ?? [])
        {
            if (machine.ProfileOf(sid) is { } p && string.Equals(p.TrimEnd('\\'), profile.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
            {
                return sid;
            }
        }

        return null;
    }
}

/// <summary>Other users' ShellBags for <see cref="ShellBagsAnalyzer"/>.</summary>
public sealed class OtherUserShellBags(UserHives hives) : IOtherUserShellBags
{
    public IReadOnlyList<UserShellBags> Load(bool otherUsersAllowed) =>
        hives.Load(otherUsersAllowed, includeCurrent: false)
            .Select(u => new UserShellBags(u.User, u.Sid, new RegistryShellBags(u.View), $"USER({u.User})", u.Problems))
            .ToList();
}
