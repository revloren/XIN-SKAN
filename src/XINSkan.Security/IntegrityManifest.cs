using System.Security.Cryptography;
using System.Text.Json;
using XINSkan.Models;

namespace XINSkan.Security;

public sealed record ManifestEntry(string Path, long Size, string Sha256);

public sealed record IntegrityProblem(string Path, string Problem);

/// <summary>
/// SHA-256 of every file an investigation produced, written as a new manifest file when the investigation is
/// closed. Verification reports missing, changed and unexpected files.
/// </summary>
public static class IntegrityManifest
{
    public const string DefaultName = "manifest.sha256.json";

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <returns>Hash of the manifest itself, to be shown to the operator and printed in reports.</returns>
    public static Sha256Hash Write(OutputSink sink, TimeProvider time, string manifestName = DefaultName)
    {
        ArgumentNullException.ThrowIfNull(sink);
        ArgumentNullException.ThrowIfNull(time);

        var entries = new List<ManifestEntry>();
        foreach (var rel in sink.CreatedFiles)
        {
            using var s = sink.OpenOwnForRead(rel);
            var hash = SHA256.HashData(s);
            entries.Add(new ManifestEntry(rel.Replace('\\', '/'), s.Length, Convert.ToHexStringLower(hash)));
        }

        var json = JsonSerializer.SerializeToUtf8Bytes(new
        {
            createdUtc = time.GetUtcNow().UtcDateTime,
            files = entries,
        }, JsonOptions);

        sink.WriteNew(manifestName, json);
        return Sha256Hash.FromBytes(SHA256.HashData(json));
    }

    public static IReadOnlyList<IntegrityProblem> Verify(string investigationRoot, string manifestName = DefaultName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(investigationRoot);
        var manifestPath = Path.Combine(investigationRoot, manifestName);
        var problems = new List<IntegrityProblem>();
        if (!File.Exists(manifestPath))
        {
            return [new IntegrityProblem(manifestName, "The manifest is missing.")];
        }

        using var doc = JsonDocument.Parse(File.ReadAllBytes(manifestPath));
        var listed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { manifestName };
        foreach (var f in doc.RootElement.GetProperty("files").EnumerateArray())
        {
            var rel = f.GetProperty("path").GetString()!;
            listed.Add(rel.Replace('/', Path.DirectorySeparatorChar));
            var full = Path.Combine(investigationRoot, rel.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(full))
            {
                problems.Add(new IntegrityProblem(rel, "Listed in the manifest but missing."));
                continue;
            }

            using var s = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read);
            var actual = Convert.ToHexStringLower(SHA256.HashData(s));
            if (!string.Equals(actual, f.GetProperty("sha256").GetString(), StringComparison.Ordinal))
            {
                problems.Add(new IntegrityProblem(rel, "Content differs from the manifest."));
            }
        }

        foreach (var file in Directory.EnumerateFiles(investigationRoot, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(investigationRoot, file);
            if (!listed.Contains(rel))
            {
                problems.Add(new IntegrityProblem(rel.Replace('\\', '/'), "Not listed in the manifest (added after the investigation closed?)."));
            }
        }

        return problems;
    }
}
