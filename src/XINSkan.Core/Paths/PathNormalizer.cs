using System.Text;

namespace XINSkan.Core.Paths;

/// <summary>
/// Maps volume names that artifacts use (\Device\HarddiskVolume3, \VOLUME{01d5...-c4b2a1f0}, Volume{GUID})
/// to drive letters of the investigated system. Built from the live system by the platform layer.
/// </summary>
public sealed class VolumeMap
{
    private readonly Dictionary<string, string> _map = new(StringComparer.OrdinalIgnoreCase);

    /// <param name="volumeName">The prefix as artifacts write it, without a trailing backslash.</param>
    /// <param name="driveLetter">For example "C:".</param>
    public void Add(string volumeName, string driveLetter)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(volumeName);
        if (driveLetter is not { Length: 2 } || !char.IsAsciiLetter(driveLetter[0]) || driveLetter[1] != ':')
        {
            throw new ArgumentException("Drive letter must look like 'C:'.", nameof(driveLetter));
        }

        _map[volumeName.TrimEnd('\\')] = char.ToUpperInvariant(driveLetter[0]) + ":";
    }

    internal bool TryMap(string path, out string mapped)
    {
        foreach (var (prefix, drive) in _map)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                && (path.Length == prefix.Length || path[prefix.Length] == '\\'))
            {
                mapped = drive + (path.Length == prefix.Length ? "\\" : path[prefix.Length..]);
                return true;
            }
        }

        mapped = path;
        return false;
    }
}

/// <summary>
/// Produces the comparison form of a Windows path: no namespace prefixes, backslashes only, no duplicate or
/// trailing separators, "." and ".." resolved lexically, upper case (NTFS lookups are case-insensitive).
/// The form is for matching only; reports always show the path as the artifact recorded it.
/// </summary>
/// <remarks>
/// Lexical normalisation cannot resolve 8.3 short names, junctions or environment variables
/// (%USERPROFILE% in LNK files). Such paths stay distinct and correlation treats them as different strings.
/// </remarks>
public static class PathNormalizer
{
    public static string? Normalize(string? path, VolumeMap? volumes = null)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var p = path.Trim().Replace('/', '\\');

        // Namespace prefixes: \\?\UNC\server\share, \\?\C:\, \??\C:\, \\.\C:\
        if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            p = @"\\" + p[8..];
        }
        else if (p.StartsWith(@"\\?\", StringComparison.Ordinal) || p.StartsWith(@"\??\", StringComparison.Ordinal)
                 || p.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            p = p[4..];
        }

        if (volumes is not null)
        {
            volumes.TryMap(p, out p);
        }

        var unc = p.StartsWith(@"\\", StringComparison.Ordinal);
        var body = unc ? p[2..] : p;

        var parts = new List<string>();
        foreach (var raw in body.Split('\\'))
        {
            if (raw.Length == 0 || raw == ".")
            {
                continue;
            }

            if (raw == "..")
            {
                // Never climb above the root (drive, UNC server/share or device).
                var floor = unc ? 2 : 1;
                if (parts.Count > floor)
                {
                    parts.RemoveAt(parts.Count - 1);
                }

                continue;
            }

            // Windows ignores trailing dots and spaces in path components.
            var trimmed = raw.TrimEnd('.', ' ');
            parts.Add(trimmed.Length == 0 ? raw : trimmed);
        }

        if (parts.Count == 0)
        {
            return unc ? @"\\" : null;
        }

        var sb = new StringBuilder(p.Length);
        if (unc)
        {
            sb.Append(@"\\");
        }
        else if (body.StartsWith('\\'))
        {
            sb.Append('\\');
        }

        sb.AppendJoin('\\', parts);

        // A bare drive is the root of that drive.
        if (!unc && parts.Count == 1 && parts[0].Length == 2 && parts[0][1] == ':')
        {
            sb.Append('\\');
        }

        return sb.ToString().ToUpperInvariant();
    }

    /// <summary>File name (last component) in comparison form.</summary>
    public static string? FileName(string? path)
    {
        var n = Normalize(path);
        if (n is null)
        {
            return null;
        }

        var trimmed = n.TrimEnd('\\');
        var i = trimmed.LastIndexOf('\\');
        var name = i < 0 ? trimmed : trimmed[(i + 1)..];
        return name.Length == 0 || name.EndsWith(':') ? null : name;
    }

    /// <summary>True when <paramref name="path"/> is <paramref name="folder"/> or lies beneath it.</summary>
    public static bool IsUnder(string? path, string? folder)
    {
        var p = Normalize(path);
        var f = Normalize(folder);
        if (p is null || f is null)
        {
            return false;
        }

        f = f.TrimEnd('\\');
        return p.Equals(f, StringComparison.Ordinal) || p.StartsWith(f + "\\", StringComparison.Ordinal);
    }
}
