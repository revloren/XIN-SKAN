using System.Globalization;
using System.Text;
using XINSkan.Correlation;
using XINSkan.Models;

namespace XINSkan.Signatures;

/// <summary>
/// Matches records against the database by four independent mechanisms: exact hash, component identifiers from the
/// project's own source, names, and ambiguous names in a Minecraft context. Each match states what matched and
/// how; no mechanism alone is a verdict.
/// </summary>
public sealed class Matcher
{
    private readonly SignatureDatabase _db;
    private readonly Dictionary<string, ClientEntry> _byId;
    private readonly Dictionary<string, HashEntry> _hashes;
    private readonly List<(string Normalized, string Variant, ClientEntry Client, bool Ambiguous, bool ExactFile)> _names = [];

    public Matcher(SignatureDatabase db)
    {
        ArgumentNullException.ThrowIfNull(db);
        _db = db;
        _byId = db.Clients.ToDictionary(c => c.Id, StringComparer.Ordinal);
        _hashes = db.Hashes.ToDictionary(h => h.Sha256, StringComparer.OrdinalIgnoreCase);
        foreach (var c in db.Clients)
        {
            foreach (var v in c.Variants)
            {
                var exactFile = v.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || v.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) || v.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
                var n = Normalize(v);
                if (n.Length > 0)
                {
                    // Very short spellings mean nothing without context, whatever the list says.
                    _names.Add((n, v, c, c.AmbiguousVariants.Contains(v) || (n.Length < 4 && !exactFile), exactFile));
                }
            }
        }
    }

    private static readonly string[] Extensions = [".jar", ".dll", ".exe"];

    private static readonly string[] ModIdKeys = ["Mod.Id", "Mod2.Id", "Mod3.Id", "Mod4.Id", "Mod5.Id"];

    private static readonly string[] NameKeys = ["Mod.Name", "Pe.ProductName", "Pe.OriginalFilename", "Pe.InternalName", "Pe.FileDescription", "Version.Id", "Instance.Name"];

    /// <summary>Lower case, without spaces, hyphens, underscores, dots and a .jar/.dll/.exe ending.</summary>
    public static string Normalize(string s)
    {
        ArgumentNullException.ThrowIfNull(s);
        var t = s.Trim().ToLowerInvariant();
        foreach (var ext in Extensions)
        {
            if (t.EndsWith(ext, StringComparison.Ordinal))
            {
                t = t[..^ext.Length];
            }
        }

        var sb = new StringBuilder(t.Length);
        foreach (var ch in t)
        {
            if (char.IsLetterOrDigit(ch))
            {
                sb.Append(ch);
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Everything a name can be read as: whole stem, words split at separators and at case changes, and runs of up
    /// to three neighbouring words ("Wurst-Client-7.40" → wurst, client, wurstclient, …).
    /// </summary>
    public static HashSet<string> Phrases(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        var stem = name;
        var dot = stem.LastIndexOf('.');
        if (dot > 0 && stem.Length - dot <= 5)
        {
            stem = stem[..dot];
        }

        var words = new List<string>();
        var current = new StringBuilder();
        void Flush()
        {
            if (current.Length > 0)
            {
                words.Add(current.ToString().ToLowerInvariant());
                current.Clear();
            }
        }

        for (var i = 0; i < stem.Length; i++)
        {
            var c = stem[i];
            if (!char.IsLetterOrDigit(c))
            {
                Flush();
                continue;
            }

            // Case change: "LiquidBounce" → Liquid | Bounce; "NightDLC" keeps "DLC" together.
            if (i > 0 && char.IsUpper(c) && char.IsLower(stem[i - 1]))
            {
                Flush();
            }

            current.Append(c);
        }

        Flush();
        var phrases = new HashSet<string>(StringComparer.Ordinal) { Normalize(stem) };
        for (var i = 0; i < words.Count; i++)
        {
            var sb = new StringBuilder();
            for (var j = i; j < Math.Min(words.Count, i + 3); j++)
            {
                sb.Append(words[j]);
                phrases.Add(sb.ToString());
            }
        }

        phrases.Remove(string.Empty);
        return phrases;
    }

    public IReadOnlyList<SignatureMatch> Match(IEnumerable<EvidenceFacts> facts)
    {
        ArgumentNullException.ThrowIfNull(facts);
        var matches = new List<SignatureMatch>();
        foreach (var f in facts)
        {
            var found = new Dictionary<string, SignatureMatch>(StringComparer.Ordinal);
            void Add(SignatureMatch m)
            {
                // One match per entry and record: the strongest kind wins.
                if (!found.TryGetValue(m.ClientId, out var old) || Rank(m.Kind) > Rank(old.Kind))
                {
                    found[m.ClientId] = m;
                }
            }

            if (f.Sha256 is { } sha && _hashes.TryGetValue(sha.Hex, out var hash) && _byId.TryGetValue(hash.ClientId, out var hc))
            {
                Add(Make(f, hc, SignatureMatchKind.ExactHashMatch, sha.Hex,
                    $"SHA-256 файла совпадает с {hash.FileName}{(hash.Version is null ? string.Empty : " " + hash.Version)} ({hash.Source.Url}, проверено {hash.Source.Checked})."));
            }

            foreach (var (client, what, detail) in Components(f))
            {
                Add(Make(f, client, client.Status == "verified" ? SignatureMatchKind.VerifiedComponentMatch : SignatureMatchKind.PossibleMatch, what, detail));
            }

            var context = InMinecraftContext(f);
            foreach (var (text, field) in Names(f))
            {
                var phrases = Phrases(text);
                foreach (var (normalized, variant, client, ambiguous, exactFile) in _names)
                {
                    var hit = exactFile ? string.Equals(LastSegment(text), variant, StringComparison.OrdinalIgnoreCase) : phrases.Contains(normalized);
                    if (!hit || (ambiguous && !context))
                    {
                        continue;
                    }

                    Add(Make(f, client, ambiguous ? SignatureMatchKind.PossibleMatch : SignatureMatchKind.NameMatch, variant,
                        $"{field} «{text}» содержит написание «{variant}»" + (ambiguous ? " — общеупотребительное слово, учтено только потому, что объект связан с Minecraft." : ".")));
                }
            }

            matches.AddRange(found.Values);
        }

        return matches;
    }

    private static int Rank(SignatureMatchKind k) => k switch
    {
        SignatureMatchKind.ExactHashMatch => 5,
        SignatureMatchKind.VerifiedComponentMatch => 4,
        SignatureMatchKind.MultipleFeatureMatch => 3,
        SignatureMatchKind.NameMatch => 2,
        SignatureMatchKind.PossibleMatch => 1,
        _ => 0,
    };

    private IEnumerable<(ClientEntry Client, string What, string Detail)> Components(EvidenceFacts f)
    {
        var modIds = new List<(string Id, string Field)>();
        foreach (var key in ModIdKeys)
        {
            if (f.Attr(key) is { } id)
            {
                modIds.Add((id, "идентификатор мода в описании JAR"));
            }
        }

        foreach (var item in Split(f.Attr("Jar.NestedMods")))
        {
            var colon = item.IndexOf(':', StringComparison.Ordinal);
            modIds.Add((colon < 0 ? item : item[(colon + 1)..], "вложенный мод"));
        }

        foreach (var item in Split(f.Attr("Game.Mods")).Concat(Split(f.Attr("Game.NestedMods"))))
        {
            var at = item.IndexOf('@', StringComparison.Ordinal);
            modIds.Add((at < 0 ? item : item[..at], "мод в логе Minecraft"));
        }

        var packages = Split(f.Attr("Jar.TopPackages")).ToList();
        var classes = new[] { f.Attr("Manifest.Main-Class"), f.Attr("Manifest.Premain-Class"), f.Attr("Manifest.Agent-Class") }.Where(c => c is not null).Select(c => c!).ToList();
        foreach (var c in _db.Clients.Where(c => c.Identifiers.ModIds.Count + c.Identifiers.Packages.Count + c.Identifiers.Entrypoints.Count > 0))
        {
            foreach (var (id, field) in modIds)
            {
                if (c.Identifiers.ModIds.Contains(id, StringComparer.Ordinal))
                {
                    yield return (c, id, $"{field}: «{id}» — идентификатор {c.Name} по его исходному коду ({Cite(c)}).");
                }
            }

            foreach (var p in packages)
            {
                if (c.Identifiers.Packages.FirstOrDefault(cp => p == cp || p.StartsWith(cp + ".", StringComparison.Ordinal)) is { } own)
                {
                    yield return (c, p, $"классы пакета {p} — пакет {own} проекта {c.Name} ({Cite(c)}).");
                }
            }

            foreach (var cls in classes)
            {
                if (c.Identifiers.Entrypoints.Contains(cls, StringComparer.Ordinal) || c.Identifiers.Packages.Any(cp => cls.StartsWith(cp + ".", StringComparison.Ordinal)))
                {
                    yield return (c, cls, $"класс запуска {cls} принадлежит {c.Name} ({Cite(c)}).");
                }
            }
        }
    }

    private static string Cite(ClientEntry c) =>
        c.Sources.LastOrDefault(s => s.Url is not null) is { } s ? $"{s.Url}{(s.Commit is null ? string.Empty : " @" + s.Commit[..Math.Min(12, s.Commit.Length)])}, {s.Checked}" : "источник не указан";

    private static IEnumerable<(string Text, string Field)> Names(EvidenceFacts f)
    {
        if (f.FileName is { Length: > 0 } name)
        {
            yield return (name, "Имя файла");
        }
        else if (f.RecordedPath is { Length: > 0 } path)
        {
            yield return (LastSegment(path), "Имя в пути");
        }

        foreach (var key in NameKeys)
        {
            if (f.Attr(key) is { } v)
            {
                yield return (v, key);
            }
        }
    }

    private static bool InMinecraftContext(EvidenceFacts f) =>
        f.Attr("MinecraftRoot") is not null || f.Source is EvidenceSourceKind.MinecraftLog or EvidenceSourceKind.Launcher
        || (f.RecordedPath ?? string.Empty).Contains(".minecraft", StringComparison.OrdinalIgnoreCase)
        || (f.RecordedPath ?? string.Empty).Contains("\\mods\\", StringComparison.OrdinalIgnoreCase)
        || f.Attr("Mod.Id") is not null;

    private static string[] Split(string? list) =>
        string.IsNullOrWhiteSpace(list) ? [] : list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static string LastSegment(string path)
    {
        var t = path.TrimEnd('\\', '/');
        var i = t.LastIndexOfAny(['\\', '/']);
        return i < 0 ? t : t[(i + 1)..];
    }

    private static SignatureMatch Make(EvidenceFacts f, ClientEntry c, SignatureMatchKind kind, string matched, string detail) =>
        new(f.Id, c.Id, c.Name, c.Kind, c.Status, kind, matched, detail.ToString(CultureInfo.InvariantCulture));
}
