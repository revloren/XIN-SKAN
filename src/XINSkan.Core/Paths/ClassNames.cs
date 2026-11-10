using System.Text;

namespace XINSkan.Core.Paths;

/// <summary>
/// Reduces a Java class entry ("net/wurstclient/hacks/KillauraHack.class") to the key its feature is looked up by
/// ("killaura"). Shared by the archive reader (which keeps only classes whose key is in the feature catalog) and the
/// signature matcher, so both read class names the same way.
/// </summary>
public static class ClassNames
{
    private static readonly string[] Suffixes = ["Module", "Hack", "Feature", "Cheat", "Mod"];

    /// <summary>Packages of the JDK, Kotlin, Minecraft and common libraries: their class names say nothing about a client.</summary>
    private static readonly string[] LibraryPrefixes =
    [
        "java/", "javax/", "jdk/", "sun/", "com/sun/", "kotlin/", "kotlinx/", "scala/", "groovy/",
        "net/minecraft/", "com/mojang/", "net/minecraftforge/", "net/neoforged/", "net/fabricmc/", "org/quiltmc/",
        "org/apache/", "com/google/", "io/netty/", "it/unimi/", "org/lwjgl/", "org/slf4j/", "org/objectweb/",
        "org/spongepowered/", "com/fasterxml/", "org/jetbrains/", "org/intellij/", "okhttp3/", "okio/",
    ];

    /// <summary>
    /// The lookup key of a class entry, or null for inner and synthetic classes, package/module descriptors and
    /// library packages. Prefix "Module" and suffixes "Module", "Hack", "Feature", "Cheat", "Mod" are dropped
    /// (LiquidBounce ModuleKillAura, Wurst KillauraHack, SalHack KillAuraModule → "killaura").
    /// </summary>
    public static string? FeatureKey(string entryPath)
    {
        ArgumentNullException.ThrowIfNull(entryPath);
        var path = entryPath.Replace('\\', '/');
        if (!path.EndsWith(".class", StringComparison.OrdinalIgnoreCase) || IsLibrary(path))
        {
            return null;
        }

        var slash = path.LastIndexOf('/');
        var simple = path[(slash + 1)..^".class".Length];
        if (simple.Length == 0 || simple.Contains('$', StringComparison.Ordinal) || simple is "package-info" or "module-info")
        {
            return null;
        }

        if (simple.Length > "Module".Length + 1 && simple.StartsWith("Module", StringComparison.Ordinal) && char.IsUpper(simple["Module".Length]))
        {
            simple = simple["Module".Length..];
        }

        foreach (var s in Suffixes)
        {
            if (simple.Length >= s.Length + 3 && simple.EndsWith(s, StringComparison.Ordinal))
            {
                simple = simple[..^s.Length];
                break;
            }
        }

        var key = Key(simple);
        return key.Length is >= 3 and <= 40 ? key : null;
    }

    /// <summary>Lower case letters and digits only: "Kill-Aura" and "KillAura" have the same key.</summary>
    public static string Key(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        var sb = new StringBuilder(name.Length);
        foreach (var c in name)
        {
            if (char.IsAsciiLetterOrDigit(c))
            {
                sb.Append(char.ToLowerInvariant(c));
            }
        }

        return sb.ToString();
    }

    /// <summary>Package path segments of a class entry, lower case ("net/wurstclient/hacks/X.class" → net, wurstclient, hacks).</summary>
    public static IReadOnlyList<string> PackageSegments(string entryPath)
    {
        ArgumentNullException.ThrowIfNull(entryPath);
        var path = entryPath.Replace('\\', '/');
        var slash = path.LastIndexOf('/');
        return slash <= 0 ? [] : path[..slash].ToLowerInvariant().Split('/', StringSplitOptions.RemoveEmptyEntries);
    }

    private static bool IsLibrary(string path)
    {
        foreach (var p in LibraryPrefixes)
        {
            if (path.StartsWith(p, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
