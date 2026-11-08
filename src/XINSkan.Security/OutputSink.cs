namespace XINSkan.Security;

/// <summary>
/// The only component of XIN SKAN that creates files. It writes inside one investigation folder, never opens an
/// existing file for writing, never deletes, and refuses paths that escape the folder. Earlier investigations
/// are therefore never overwritten: each one gets a new folder, and a second write to the same name fails.
/// </summary>
public sealed class OutputSink
{
    private readonly List<string> _created = [];
    private readonly Lock _gate = new();

    private OutputSink(string root) => Root = root;

    /// <summary>Absolute path of the investigation folder.</summary>
    public string Root { get; }

    /// <summary>Files created so far, relative to <see cref="Root"/>, in creation order.</summary>
    public IReadOnlyList<string> CreatedFiles
    {
        get
        {
            lock (_gate)
            {
                return [.. _created];
            }
        }
    }

    /// <summary>Creates a new, empty investigation folder. Fails if the folder already exists.</summary>
    public static OutputSink CreateInvestigationFolder(string baseDirectory, string folderName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);
        ValidateRelative(folderName);
        if (folderName.Contains('\\', StringComparison.Ordinal) || folderName.Contains('/', StringComparison.Ordinal))
        {
            throw new ArgumentException("The investigation folder name must be a single path component.", nameof(folderName));
        }

        var root = Path.GetFullPath(Path.Combine(baseDirectory, folderName));
        if (Directory.Exists(root) || File.Exists(root))
        {
            throw new IOException($"'{root}' already exists. Earlier investigations are never reused or overwritten.");
        }

        Directory.CreateDirectory(root);
        return new OutputSink(root);
    }

    /// <summary>Opens a new file for writing. Throws <see cref="IOException"/> if the file already exists.</summary>
    public Stream CreateNew(string relativePath)
    {
        var full = Resolve(relativePath);
        var dir = Path.GetDirectoryName(full)!;
        if (!Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var stream = new FileStream(full, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        lock (_gate)
        {
            _created.Add(Path.GetRelativePath(Root, full));
        }

        return stream;
    }

    /// <summary>
    /// Claims a new, empty file for a component that must open the file itself (the SQLite database).
    /// The claim is atomic (CreateNew), so an existing file is never taken over.
    /// </summary>
    /// <returns>Absolute path of the claimed file.</returns>
    public string ReserveNewFile(string relativePath)
    {
        using (CreateNew(relativePath))
        {
        }

        return Resolve(relativePath);
    }

    public void WriteNew(string relativePath, ReadOnlySpan<byte> content)
    {
        using var s = CreateNew(relativePath);
        s.Write(content);
    }

    /// <summary>Marks a finished file read-only. A convenience against accidental edits, not tamper protection.</summary>
    public void Seal(string relativePath)
    {
        var full = Resolve(relativePath);
        File.SetAttributes(full, File.GetAttributes(full) | FileAttributes.ReadOnly);
    }

    /// <summary>Opens a file this sink created, for reading (used to hash it).</summary>
    public Stream OpenOwnForRead(string relativePath)
    {
        var full = Resolve(relativePath);
        lock (_gate)
        {
            if (!_created.Contains(Path.GetRelativePath(Root, full), StringComparer.Ordinal))
            {
                throw new InvalidOperationException($"'{relativePath}' was not created by this investigation.");
            }
        }

        return new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read);
    }

    private string Resolve(string relativePath)
    {
        ValidateRelative(relativePath);
        var full = Path.GetFullPath(Path.Combine(Root, relativePath));
        var rootWithSep = Root.EndsWith(Path.DirectorySeparatorChar) ? Root : Root + Path.DirectorySeparatorChar;
        if (!full.StartsWith(rootWithSep, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException($"'{relativePath}' resolves outside the investigation folder.");
        }

        return full;
    }

    private static void ValidateRelative(string relativePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        if (Path.IsPathRooted(relativePath) || relativePath.Contains(':', StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException($"'{relativePath}' must be relative, without drive letters or alternate streams.");
        }

        foreach (var part in relativePath.Split(['\\', '/']))
        {
            if (part is ".." or ".")
            {
                throw new UnauthorizedAccessException($"'{relativePath}' must not contain '.' or '..' segments.");
            }
        }

        if (relativePath.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
        {
            throw new ArgumentException($"'{relativePath}' contains invalid characters.", nameof(relativePath));
        }
    }
}

/// <summary>Result of checking where the output folder lies relative to the investigated volumes.</summary>
public sealed record OutputLocationAssessment(bool OnInvestigatedVolume, string Message);

/// <summary>
/// Warns when results would be written to a volume under investigation: new files there can occupy clusters
/// that still hold the content of deleted files and add records to its change journal.
/// </summary>
public static class OutputLocationPolicy
{
    public static OutputLocationAssessment Assess(string outputDirectory, IEnumerable<string> investigatedRoots)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        ArgumentNullException.ThrowIfNull(investigatedRoots);
        var outRoot = Path.GetPathRoot(Path.GetFullPath(outputDirectory)) ?? string.Empty;
        foreach (var r in investigatedRoots)
        {
            var root = Path.GetPathRoot(Path.GetFullPath(r)) ?? string.Empty;
            if (string.Equals(root.TrimEnd('\\', '/'), outRoot.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
            {
                return new OutputLocationAssessment(true,
                    $"Results will be written to {outRoot}, which is being investigated. New files there may overwrite clusters that still hold deleted content and will appear in its change journal. Use an external drive if possible.");
            }
        }

        return new OutputLocationAssessment(false, $"Results will be written to {outRoot}, which is not being investigated.");
    }
}
