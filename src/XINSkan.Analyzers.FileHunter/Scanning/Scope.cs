using XINSkan.Core.IO;
using XINSkan.Core.Paths;

namespace XINSkan.Analyzers.FileHunter.Scanning;

public enum RootKind
{
    /// <summary>A user profile, scanned whole: Minecraft folders, Downloads, Desktop, Documents, AppData and any custom folder.</summary>
    Profile,

    /// <summary>A system temporary folder.</summary>
    Temp,

    /// <summary>A folder or drive added by the operator.</summary>
    Extra,
}

public sealed record ScopeRoot(string Path, RootKind Kind, string? ProfileName);

/// <summary>What will be scanned, and what deliberately will not be (each exclusion has a reason).</summary>
public sealed record ScanScope(IReadOnlyList<ScopeRoot> Roots, IReadOnlyList<string> Excluded);

/// <summary>
/// Builds the scan scope. Whole user profiles are scanned rather than a list of known Minecraft folders, so a
/// client kept in a custom folder is still found.
/// </summary>
public static class ScopeBuilder
{
    private static readonly HashSet<string> SystemProfiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "Default", "Default User", "All Users", "Public", "defaultuser0", "WDAGUtilityAccount",
    };

    /// <summary>Profiles of Windows itself (templates, shared), not of a person.</summary>
    public static bool IsSystemProfile(string name) => SystemProfiles.Contains(name);

    /// <param name="usersRoot">The profiles folder, normally C:\Users.</param>
    /// <param name="currentProfile">Profile of the account running XIN SKAN.</param>
    /// <param name="canReadOtherProfiles">Whether other profiles are readable (Capability.OtherUserProfiles).</param>
    /// <param name="tempFolders">System temporary folders (C:\Windows\Temp).</param>
    /// <param name="extraRoots">Folders or drives added by the operator.</param>
    public static ScanScope Build(
        IDirectoryLister lister,
        string usersRoot,
        string currentProfile,
        bool canReadOtherProfiles,
        IEnumerable<string> tempFolders,
        IEnumerable<string> extraRoots)
    {
        ArgumentNullException.ThrowIfNull(lister);
        ArgumentNullException.ThrowIfNull(tempFolders);
        ArgumentNullException.ThrowIfNull(extraRoots);

        var roots = new List<ScopeRoot>();
        var excluded = new List<string>();

        IReadOnlyList<FsEntry> profiles = [];
        try
        {
            profiles = lister.List(usersRoot).Where(e => e.IsDirectory).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            excluded.Add($"{usersRoot}: список профилей не прочитан ({ex.Message}); проверяется только текущий профиль.");
        }

        var current = PathNormalizer.Normalize(currentProfile);
        var addedCurrent = false;
        foreach (var p in profiles.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase))
        {
            if (SystemProfiles.Contains(p.Name))
            {
                continue;
            }

            if (p.IsReparsePoint)
            {
                excluded.Add($"{p.FullPath}: ссылка на другое место, не пройдена.");
                continue;
            }

            var isCurrent = string.Equals(PathNormalizer.Normalize(p.FullPath), current, StringComparison.Ordinal);
            if (!isCurrent && !canReadOtherProfiles)
            {
                excluded.Add($"{p.FullPath}: профили других пользователей недоступны без прав администратора.");
                continue;
            }

            roots.Add(new ScopeRoot(p.FullPath, RootKind.Profile, p.Name));
            addedCurrent |= isCurrent;
        }

        if (!addedCurrent && lister.DirectoryExists(currentProfile))
        {
            roots.Add(new ScopeRoot(currentProfile, RootKind.Profile, System.IO.Path.GetFileName(currentProfile.TrimEnd('\\', '/'))));
        }

        foreach (var t in tempFolders.Where(lister.DirectoryExists))
        {
            roots.Add(new ScopeRoot(t, RootKind.Temp, null));
        }

        foreach (var x in extraRoots.Where(r => !string.IsNullOrWhiteSpace(r)))
        {
            if (lister.DirectoryExists(x))
            {
                roots.Add(new ScopeRoot(x, RootKind.Extra, null));
            }
            else
            {
                excluded.Add($"{x}: папка не существует.");
            }
        }

        return new ScanScope(RemoveNested(roots), excluded);
    }

    /// <summary>A root inside another root would be scanned twice; keep only the outer one.</summary>
    private static List<ScopeRoot> RemoveNested(List<ScopeRoot> roots)
    {
        var result = new List<ScopeRoot>();
        foreach (var r in roots)
        {
            if (roots.Any(o => !ReferenceEquals(o, r) && PathNormalizer.IsUnder(r.Path, o.Path)
                               && !string.Equals(PathNormalizer.Normalize(o.Path), PathNormalizer.Normalize(r.Path), StringComparison.Ordinal)))
            {
                continue;
            }

            if (result.Any(o => string.Equals(PathNormalizer.Normalize(o.Path), PathNormalizer.Normalize(r.Path), StringComparison.Ordinal)))
            {
                continue;
            }

            result.Add(r);
        }

        return result;
    }
}
