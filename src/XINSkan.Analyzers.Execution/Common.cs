using System.Globalization;
using System.Text.RegularExpressions;
using XINSkan.Analyzers.History;

namespace XINSkan.Analyzers.Execution;

/// <summary>A volume of the investigated system as artifacts name it.</summary>
public sealed record KnownVolume(string Drive, string? DevicePath, uint? Serial, bool Removable);

/// <summary>Where the investigated system's volumes are, for translating device paths in artifacts.</summary>
public interface IVolumeDirectory
{
    IReadOnlyList<KnownVolume> Volumes();
}

/// <summary>Translates artifact paths (\VOLUME{time-serial}\…, \Device\HarddiskVolumeN\…) to drive paths.</summary>
public sealed partial class VolumeResolver(IReadOnlyList<KnownVolume> volumes)
{
    [GeneratedRegex(@"^\\VOLUME\{[0-9A-Fa-f]{16}-([0-9A-Fa-f]{8})\}(\\.*)?$")]
    private static partial Regex VolumeGuid();

    [GeneratedRegex(@"^(\\Device\\HarddiskVolume\d+|\\Device\\HarddiskVolumeShadowCopy\d+)(\\.*)?$", RegexOptions.IgnoreCase)]
    private static partial Regex DevicePath();

    /// <summary>The drive path, or the original when the volume is not mounted now (for example a USB stick).</summary>
    public (string Path, bool Resolved, string? Serial) Resolve(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        // A drive path, or an absolute path of the platform's own file system (tests run on Linux).
        if ((path.Length >= 2 && path[1] == ':') || path.StartsWith('/'))
        {
            return (path, true, null);
        }

        if (VolumeGuid().Match(path) is { Success: true } g)
        {
            var serialText = g.Groups[1].Value.ToUpperInvariant();
            var serial = uint.Parse(serialText, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            var v = volumes.FirstOrDefault(x => x.Serial == serial);
            return v is null ? (path, false, serialText) : (v.Drive + g.Groups[2].Value, true, serialText);
        }

        if (DevicePath().Match(path) is { Success: true } d)
        {
            var v = volumes.FirstOrDefault(x => string.Equals(x.DevicePath, d.Groups[1].Value, StringComparison.OrdinalIgnoreCase));
            return v is null ? (path, false, null) : (v.Drive + d.Groups[2].Value, true, null);
        }

        return (path, false, null);
    }

    public bool IsRemovable(string drivePath) =>
        volumes.Any(v => v.Removable && drivePath.StartsWith(v.Drive, StringComparison.OrdinalIgnoreCase));
}

/// <summary>Which programs are worth recording as executed.</summary>
internal static class ProgramRelevance
{
    /// <summary>The Java runtime and Minecraft launchers (cheat names belong to the verified database, stage 9).</summary>
    private static readonly HashSet<string> KnownNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "java.exe", "javaw.exe", "minecraft.exe", "minecraftlauncher.exe", "minecraft.windows.exe", "tlauncher.exe",
        "lunar client.exe", "lunarclient.exe", "badlion client.exe", "prismlauncher.exe", "multimc.exe", "atlauncher.exe",
        "curseforge.exe", "feather launcher.exe", "modrinth app.exe", "polymc.exe", "gdlauncher.exe", "sklauncher.exe",
    };

    public static bool IsKnown(string name) => KnownNames.Contains(name);

    public static bool IsJava(string name) => name.Equals("java.exe", StringComparison.OrdinalIgnoreCase) || name.Equals("javaw.exe", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// A program is recorded when it is the JVM or a launcher, lives in a Minecraft folder, a download location or a
    /// temporary folder, sits on a removable or no-longer-mounted volume, or anywhere in a user profile.
    /// </summary>
    public static string? Why(string fileName, string path, bool resolved, bool removable, HistoryScope scope)
    {
        if (KnownNames.Contains(fileName))
        {
            return "известная программа (Java или лаунчер Minecraft)";
        }

        if (!resolved)
        {
            // Only a real volume path can point to an unmounted volume; "Registry", "MemCompression" and other
            // pseudo-process names, or "unknown", are not paths.
            return path.StartsWith('\\') && path.IndexOf('\\', 1) > 0 ? "программа на томе, который сейчас не подключён" : null;
        }

        if (removable)
        {
            return "программа на съёмном диске";
        }

        var m = scope.Match(path);
        if (m.InMinecraftTree)
        {
            return "программа в папке Minecraft";
        }

        if (m.InDropLocation)
        {
            return "программа в загрузках, на рабочем столе, в документах или во временной папке";
        }

        return m.InScope ? "программа в профиле пользователя" : null;
    }

    /// <summary>Joins Windows paths with backslashes on any platform (tests run on Linux with Windows paths).</summary>
    public static string Join(string root, params string[] parts) =>
        root.Contains('\\', StringComparison.Ordinal) || (root.Length >= 2 && root[1] == ':')
            ? string.Join('\\', [root.TrimEnd('\\'), .. parts])
            : Path.Combine([root, .. parts]);

    public static string FileName(string path)
    {
        var t = path.TrimEnd('\\', '/');
        var i = t.LastIndexOfAny(['\\', '/']);
        return i < 0 ? t : t[(i + 1)..];
    }
}
