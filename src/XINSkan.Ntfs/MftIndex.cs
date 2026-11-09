namespace XINSkan.Ntfs;

/// <summary>How much of a reconstructed path can be trusted.</summary>
[Flags]
public enum PathQuality
{
    /// <summary>Every folder up to the root is a live record whose sequence matches the reference.</summary>
    Complete = 0,

    /// <summary>A folder on the path is itself deleted; its name and place come from its unused record.</summary>
    DeletedAncestor = 1,

    /// <summary>
    /// A folder's record now belongs to another object (sequence differs): the part of the path above it is
    /// unknown and shown as "?".
    /// </summary>
    ReusedAncestor = 2,

    /// <summary>A folder record is missing, unreadable or loops back on itself; the path is cut there.</summary>
    Broken = 4,
}

/// <summary>A path rebuilt from parent references in $FILE_NAME, with an honest statement of its quality.</summary>
public readonly record struct ResolvedPath(string Path, PathQuality Quality);

/// <summary>
/// Compact map of the MFT for rebuilding paths: per entry its sequence, flags and parent; names only for
/// folders. About 13 bytes per entry plus folder names, so a 3-million-entry MFT needs ~40 MB, not gigabytes.
/// </summary>
public sealed class MftIndex
{
    public const ulong RootEntry = 5;
    private const int MaxDepth = 255;

    private const byte HasRecord = 1;
    private const byte InUse = 2;
    private const byte Directory = 4;
    private const byte HasName = 8;

    private readonly ushort[] _sequence;
    private readonly byte[] _flags;
    private readonly uint[] _parent;
    private readonly ushort[] _parentSequence;
    private readonly Dictionary<uint, string> _folderNames = [];
    private readonly Dictionary<uint, string> _cache = [];
    private readonly string _volumePrefix;

    /// <param name="capacity">Number of MFT entries.</param>
    /// <param name="volumePrefix">Prefix of every path, for example "C:".</param>
    public MftIndex(long capacity, string volumePrefix)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(capacity);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(capacity, uint.MaxValue);
        _sequence = new ushort[capacity];
        _flags = new byte[capacity];
        _parent = new uint[capacity];
        _parentSequence = new ushort[capacity];
        _volumePrefix = volumePrefix ?? string.Empty;
    }

    public long Capacity => _flags.Length;

    public int FolderCount => _folderNames.Count;

    /// <summary>Adds a parsed record. Extension records contribute a name only if the base record has none.</summary>
    public void Add(MftRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (record.State != MftRecordState.Parsed)
        {
            return;
        }

        if (record.IsExtension)
        {
            var b = record.BaseRecord.Entry;
            if (b < (ulong)_flags.Length && (_flags[b] & HasName) == 0 && record.PrimaryName is { } extName)
            {
                // The base record may be read later; its own name (if any) then replaces this one.
                SetName((uint)b, extName, (_flags[b] & Directory) != 0);
            }

            return;
        }

        if (record.Entry >= (ulong)_flags.Length)
        {
            return;
        }

        var e = (uint)record.Entry;
        _sequence[e] = record.Sequence;
        _flags[e] = (byte)(HasRecord | (record.InUse ? InUse : 0) | (record.IsDirectory ? Directory : 0) | (_flags[e] & HasName));
        if (record.PrimaryName is { } name)
        {
            SetName(e, name, record.IsDirectory);
        }
    }

    private void SetName(uint e, FileNameAttribute name, bool isDirectory)
    {
        _parent[e] = name.Parent.Entry <= uint.MaxValue ? (uint)name.Parent.Entry : uint.MaxValue;
        _parentSequence[e] = name.Parent.Sequence;
        _flags[e] |= HasName;
        if (isDirectory || (_flags[e] & HasRecord) == 0)
        {
            _folderNames[e] = name.Name;
        }
    }

    /// <summary>Whether a reference still points to the object it was made for.</summary>
    public ReferenceState Check(FileReference reference)
    {
        if (reference.Entry >= (ulong)_flags.Length || (_flags[reference.Entry] & HasRecord) == 0)
        {
            return ReferenceState.Missing;
        }

        var f = _flags[reference.Entry];
        var seq = _sequence[reference.Entry];
        if ((f & InUse) != 0)
        {
            return seq == reference.Sequence ? ReferenceState.Live : ReferenceState.Reused;
        }

        // NTFS increments the sequence number when it frees a record, so a deleted object's last reference
        // carries the previous value (0 is skipped on wrap-around).
        return seq == reference.Sequence || seq == Next(reference.Sequence) ? ReferenceState.Deleted : ReferenceState.Reused;
    }

    /// <summary>Path of a file whose $FILE_NAME says it lives in <paramref name="parent"/>.</summary>
    public ResolvedPath Resolve(FileReference parent, string name)
    {
        var folder = ResolveFolder(parent, 0, out var quality);
        return new ResolvedPath(folder + "\\" + name, quality);
    }

    /// <summary>Path of a folder (without trailing separator); the volume root is the bare prefix.</summary>
    public ResolvedPath ResolveFolderPath(FileReference folder)
    {
        var path = ResolveFolder(folder, 0, out var quality);
        return new ResolvedPath(path, quality);
    }

    private string ResolveFolder(FileReference reference, int depth, out PathQuality quality)
    {
        quality = PathQuality.Complete;
        if (reference.Entry == RootEntry)
        {
            return _volumePrefix;
        }

        if (depth >= MaxDepth)
        {
            quality = PathQuality.Broken;
            return _volumePrefix + "\\?";
        }

        var state = Check(reference);
        var e = (uint)Math.Min(reference.Entry, uint.MaxValue);
        switch (state)
        {
            case ReferenceState.Missing:
                quality = PathQuality.Broken;
                return _volumePrefix + "\\?";
            case ReferenceState.Reused:
                quality = PathQuality.ReusedAncestor;
                return _volumePrefix + "\\?";
            case ReferenceState.Live when _cache.TryGetValue(e, out var cached):
                return cached;
        }

        if (!_folderNames.TryGetValue(e, out var name))
        {
            quality = PathQuality.Broken;
            return _volumePrefix + "\\?";
        }

        var parent = new FileReference(_parent[e], _parentSequence[e]);
        if (parent.Entry == reference.Entry)
        {
            quality = PathQuality.Broken;
            return _volumePrefix + "\\?\\" + name;
        }

        var above = ResolveFolder(parent, depth + 1, out var aboveQuality);
        quality = aboveQuality | (state == ReferenceState.Deleted ? PathQuality.DeletedAncestor : PathQuality.Complete);
        var path = above + "\\" + name;
        if (quality == PathQuality.Complete)
        {
            _cache[e] = path;
        }

        return path;
    }

    private static ushort Next(ushort sequence) => sequence == ushort.MaxValue ? (ushort)1 : (ushort)(sequence + 1);
}

public enum ReferenceState
{
    /// <summary>The entry is in use by the referenced object.</summary>
    Live,

    /// <summary>The entry is free and was last used by the referenced object.</summary>
    Deleted,

    /// <summary>The entry now belongs to (or was last used by) a different object.</summary>
    Reused,

    /// <summary>No record for the entry was read.</summary>
    Missing,
}
