using XINSkan.Core.IO;

namespace XINSkan.Analyzers.FileHunter.Scanning;

/// <summary>Why a file or folder becomes evidence. Recorded in the evidence so the selection is explainable.</summary>
public enum Selection
{
    /// <summary>Inside a Minecraft folder: every file and folder is recorded.</summary>
    MinecraftTree,

    /// <summary>An archive or executable by its extension, anywhere in scope.</summary>
    ExecutableOrArchive,

    /// <summary>In a place where downloads and dropped files land; recorded only if its content is an archive or executable.</summary>
    DropLocationContent,
}

/// <summary>
/// Decides which entries are worth recording. Recording everything would bury the few relevant files under
/// hundreds of thousands of browser caches and icons; recording only by extension would miss a renamed JAR.
/// </summary>
public static class Relevance
{
    private static readonly HashSet<string> ExecutableOrArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jar", ".zip", ".exe", ".dll", ".mrpack",
    };

    /// <summary>Folders, relative to a profile, where downloaded or dropped files usually land.</summary>
    private static readonly string[] ProfileDropFolders =
    [
        "Downloads", "Desktop", "Documents", @"AppData\Local\Temp", "OneDrive\\Desktop", "OneDrive\\Documents",
    ];

    /// <summary>Minecraft game directory: named .minecraft, or holding options.txt next to mods/versions/saves.</summary>
    public static bool IsMinecraftRoot(string directoryName, IReadOnlyList<FsEntry> children)
    {
        ArgumentNullException.ThrowIfNull(children);
        if (directoryName.Equals(".minecraft", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var hasOptions = children.Any(c => !c.IsDirectory && c.Name.Equals("options.txt", StringComparison.OrdinalIgnoreCase));
        var hasGameFolder = children.Any(c => c.IsDirectory && (c.Name.Equals("mods", StringComparison.OrdinalIgnoreCase)
                                                                || c.Name.Equals("versions", StringComparison.OrdinalIgnoreCase)
                                                                || c.Name.Equals("saves", StringComparison.OrdinalIgnoreCase)));
        return hasOptions && hasGameFolder;
    }

    public static bool IsExecutableOrArchiveByName(string name) =>
        ExecutableOrArchiveExtensions.Contains(Path.GetExtension(name));

    /// <summary>Whether <paramref name="directory"/> is a drop location under <paramref name="root"/>.</summary>
    public static bool IsDropLocation(ScopeRoot root, string directory)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (root.Kind == RootKind.Temp)
        {
            return true;
        }

        if (root.Kind != RootKind.Profile)
        {
            return false;
        }

        var rel = Path.GetRelativePath(root.Path, directory).Replace('/', '\\');
        if (rel == ".")
        {
            // Files lying directly in the profile folder.
            return true;
        }

        foreach (var d in ProfileDropFolders)
        {
            if (rel.Equals(d, StringComparison.OrdinalIgnoreCase) || rel.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
