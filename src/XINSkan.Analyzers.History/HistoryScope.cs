using XINSkan.Analyzers.FileHunter.Scanning;
using XINSkan.Core.Paths;

namespace XINSkan.Analyzers.History;

/// <summary>Where a path lies for the purposes of a check, decided from the path alone (no folder listing).</summary>
public sealed record ScopeMatch(bool InScope, bool InMinecraftTree, bool InDropLocation, string? MinecraftRoot, string? Profile);

/// <summary>
/// The same area File Hunter covers — user profiles (others only when readable), system temporary folders,
/// operator folders — plus any Minecraft folder on the volume, applied to paths rebuilt from history sources.
/// </summary>
public sealed class HistoryScope
{
    private readonly string _users;
    private readonly string _currentProfile;
    private readonly bool _otherProfiles;
    private readonly List<string> _temp;
    private readonly List<string> _extra;

    public HistoryScope(string usersRoot, string currentProfile, bool canReadOtherProfiles, IEnumerable<string> tempFolders, IEnumerable<string> extraRoots)
    {
        _users = Norm(usersRoot);
        _currentProfile = Norm(currentProfile);
        _otherProfiles = canReadOtherProfiles;
        _temp = tempFolders.Select(Norm).Where(p => p.Length > 0).ToList();
        _extra = extraRoots.Select(Norm).Where(p => p.Length > 0).ToList();
    }

    /// <summary>Paths in profiles of other users that were left out because they are not readable.</summary>
    public long ExcludedOtherProfiles { get; private set; }

    public ScopeMatch Match(string path)
    {
        var n = Norm(path);
        var mc = MinecraftRoot(path);
        string? profile = null;
        var inScope = false;
        var drop = false;

        if (Under(n, _users) && n.Length > _users.Length + 1)
        {
            var rest = n[(_users.Length + 1)..];
            var slash = rest.IndexOf('\\', StringComparison.Ordinal);
            var name = slash < 0 ? rest : rest[..slash];
            var profileRoot = _users + "\\" + name;
            if (!ScopeBuilder.IsSystemProfile(name))
            {
                var current = profileRoot == _currentProfile;
                if (current || _otherProfiles)
                {
                    inScope = slash >= 0;
                    profile = OriginalSegment(path, _users.Split('\\').Length) ?? name;
                    drop = slash >= 0 && IsDrop(n, profileRoot);
                }
                else if (slash >= 0)
                {
                    ExcludedOtherProfiles++;
                }
            }
        }

        if (!inScope && _temp.Any(t => Under(n, t)))
        {
            inScope = true;
            drop = true;
        }

        if (!inScope && _extra.Any(x => Under(n, x)))
        {
            inScope = true;
        }

        return new ScopeMatch(inScope || mc is not null, mc is not null, drop, mc, profile);
    }

    /// <summary>The path segment at <paramref name="index"/> as written (the normalised form is upper case).</summary>
    private static string? OriginalSegment(string path, int index)
    {
        var parts = path.Replace('/', '\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
        return index < parts.Length ? parts[index] : null;
    }

    /// <summary>The ".minecraft" folder the path is in, if any (anywhere on the volume).</summary>
    public static string? MinecraftRoot(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        var i = path.IndexOf("\\.minecraft", StringComparison.OrdinalIgnoreCase);
        while (i >= 0)
        {
            var end = i + "\\.minecraft".Length;
            if (end == path.Length || path[end] == '\\')
            {
                return path[..end];
            }

            i = path.IndexOf("\\.minecraft", end, StringComparison.OrdinalIgnoreCase);
        }

        return null;
    }

    private static bool IsDrop(string n, string profileRoot)
    {
        var rel = n[(profileRoot.Length + 1)..];
        var lastSlash = rel.LastIndexOf('\\');
        if (lastSlash < 0)
        {
            return true; // directly in the profile folder
        }

        var folder = rel[..lastSlash];
        return Relevance.DropFoldersInProfile.Any(d =>
            folder.Equals(d, StringComparison.OrdinalIgnoreCase) || folder.StartsWith(d.ToUpperInvariant() + "\\", StringComparison.OrdinalIgnoreCase));
    }

    private static bool Under(string n, string folder) =>
        folder.Length > 0 && (n == folder || n.StartsWith(folder + "\\", StringComparison.Ordinal));

    private static string Norm(string path) => (PathNormalizer.Normalize(path) ?? string.Empty).TrimEnd('\\');
}
