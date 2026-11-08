namespace XINSkan.SecurityTests.Infrastructure;

/// <summary>Parsed BannedSymbols.txt (copied next to the test assembly).</summary>
internal sealed class BannedList
{
    private BannedList(IReadOnlyList<(string Id, string Reason)> entries)
    {
        Entries = entries;
        Members = entries.Where(e => e.Id.StartsWith("M:", StringComparison.Ordinal)).Select(e => e.Id).ToHashSet(StringComparer.Ordinal);
        Types = entries.Where(e => e.Id.StartsWith("T:", StringComparison.Ordinal)).Select(e => e.Id).ToHashSet(StringComparer.Ordinal);
    }

    public IReadOnlyList<(string Id, string Reason)> Entries { get; }

    public HashSet<string> Members { get; }

    public HashSet<string> Types { get; }

    public static BannedList Load()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "BannedSymbols.txt");
        if (!System.IO.File.Exists(path))
        {
            // Offline runner: walk up to the repository root.
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !System.IO.File.Exists(Path.Combine(dir.FullName, "BannedSymbols.txt")))
            {
                dir = dir.Parent;
            }

            path = dir is null ? path : Path.Combine(dir.FullName, "BannedSymbols.txt");
        }

        var entries = new List<(string, string)>();
        foreach (var raw in System.IO.File.ReadAllLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var semi = line.IndexOf(';', StringComparison.Ordinal);
            entries.Add(semi < 0 ? (line, string.Empty) : (line[..semi].Trim(), line[(semi + 1)..].Trim()));
        }

        return new BannedList(entries);
    }

    public bool IsBanned(IlCall call) => Members.Contains(call.CalleeDocId) || Types.Contains(call.CalleeTypeDocId);
}
