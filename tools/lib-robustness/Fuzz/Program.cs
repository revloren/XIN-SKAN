// Robustness harness for third-party artifact parsers (MFT, USN, Prefetch, LNK, Jump Lists).
// Feeds valid samples and deterministic corruptions (truncation, byte flips, oversized
// length fields, zeroed regions) and classifies how each parser reacts.
// Usage: Fuzz <kind> <sampleDir> <casesPerSample> <reportFile> [seed]
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

static class Program
{
    static readonly Dictionary<string, int> Outcomes = new();
    static readonly List<string> Severe = new();
    static int cases;
    static string progressFile;

    static int Main(string[] args)
    {
        var kind = args[0];
        var dir = args[1];
        var perSample = int.Parse(args[2]);
        var report = args[3];
        progressFile = report + ".current";
        var seed = args.Length > 4 ? int.Parse(args[4]) : 1;
        System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);

        var samples = Samples(kind, dir);
        var sw = Stopwatch.StartNew();
        foreach (var (name, bytes) in samples)
        {
            // 1. the untouched sample must parse
            Run(kind, name + "#orig", bytes, expectOk: true);
            // 2. truncations
            foreach (var len in Truncations(bytes.Length)) Run(kind, $"{name}#trunc{len}", bytes.AsSpan(0, len).ToArray(), false);
            // 3. random corruptions, deterministic per sample
            var rnd = new Random(StableHash(name) ^ seed);
            for (var i = 0; i < perSample; i++)
            {
                var m = (byte[])bytes.Clone();
                var mode = i % 4;
                if (mode == 0) { for (var k = 0; k < 1 + rnd.Next(16); k++) m[rnd.Next(m.Length)] = (byte)rnd.Next(256); }
                else if (mode == 1 && m.Length >= 8)
                {   // oversized length/count fields at aligned offsets (in the header region more often)
                    var limit = Math.Min(m.Length - 4, rnd.Next(2) == 0 ? 512 : m.Length - 4);
                    var off = rnd.Next(Math.Max(1, limit / 4)) * 4;
                    uint[] evil = { 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0x00010000, 0x0FFFFFFF, 0 };
                    BitConverter.GetBytes(evil[rnd.Next(evil.Length)]).CopyTo(m, off);
                }
                else if (mode == 2) { var off = rnd.Next(m.Length); var len = Math.Min(m.Length - off, 1 + rnd.Next(256)); Array.Clear(m, off, len); }
                else { var off = rnd.Next(m.Length); var len = Math.Min(m.Length - off, 1 + rnd.Next(64)); for (var k = 0; k < len; k++) m[off + k] = 0xFF; }
                Run(kind, $"{name}#mut{i}", m, false);
            }
        }
        sw.Stop();
        var lines = new List<string> { $"seed={seed} kind={kind} samples={samples.Count} cases={cases} seconds={sw.Elapsed.TotalSeconds:F1}" };
        lines.AddRange(Outcomes.OrderByDescending(o => o.Value).Select(o => $"  {o.Key}: {o.Value}"));
        lines.Add($"severe={Severe.Count}");
        lines.AddRange(Severe.Take(40).Select(s => "  ! " + s));
        File.WriteAllLines(report, lines);
        File.Delete(progressFile);
        Console.WriteLine(string.Join(Environment.NewLine, lines));
        return 0;
    }

    // string.GetHashCode is randomised per process; FNV-1a keeps runs reproducible
    static int StableHash(string s) { unchecked { var h = (int)2166136261; foreach (var c in s) h = (h ^ c) * 16777619; return h; } }

    static IEnumerable<int> Truncations(int n)
    {
        var set = new SortedSet<int> { 0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 100, 128, 255, 256, 511, 512, 1023, 1024 };
        for (var i = 1; i < 20; i++) set.Add(n * i / 20);
        set.Add(n - 1);
        return set.Where(x => x >= 0 && x < n);
    }

    static void Run(string kind, string id, byte[] data, bool expectOk)
    {
        cases++;
        File.WriteAllText(progressFile, id);
        var before = GC.GetTotalAllocatedBytes(true);
        var clock = Stopwatch.StartNew();
        var t = Task.Run(() => Parse(kind, data));
        string outcome;
        if (!((IAsyncResult)t).AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(10)))
        {
            outcome = "TIMEOUT(>10s)";
            Severe.Add($"{id}: timeout — possible infinite loop");
            Bump(outcome);
            // cannot abort a thread in .NET; write what we have and exit
            File.WriteAllLines(progressFile + ".timeout", new[] { id });
            Console.WriteLine("TIMEOUT at " + id);
            Environment.Exit(3);
            return;
        }
        var alloc = GC.GetTotalAllocatedBytes(true) - before;
        var ms = clock.ElapsedMilliseconds;
        if (ms > 1000) Severe.Add($"{id}: took {ms} ms for {data.Length} input bytes");
        if (t.IsFaulted)
        {
            var e = t.Exception!.GetBaseException();
            var type = e.GetType().Name;
            outcome = "EXC:" + type;
            if (e is OutOfMemoryException || e is InsufficientExecutionStackException) Severe.Add($"{id}: {type} at {TopFrame(e)}");
            if (expectOk) Severe.Add($"{id}: valid sample rejected: {type}: {e.Message}");
        }
        else
        {
            outcome = "OK:" + t.Result;
        }
        if (alloc > 512L * 1024 * 1024) Severe.Add($"{id}: allocated {alloc / (1024 * 1024)} MB in {ms} ms for {data.Length} input bytes");
        Bump(outcome);
    }

    static string TopFrame(Exception e) => string.Join(" <- ", (e.StackTrace ?? "").Split('\n').Select(l => l.Trim()).Where(l => l.StartsWith("at ") && !l.Contains("System.")).Take(3));

    static void Bump(string k) { Outcomes.TryGetValue(k, out var v); Outcomes[k] = v + 1; }

    // Returns a short tag describing plausibility of a "successful" parse.
    static string Parse(string kind, byte[] data)
    {
        switch (kind)
        {
            case "prefetch":
            {
                var pf = Prefetch.PrefetchFile.Open(new MemoryStream(data), "x.pf");
                var bad = pf.LastRunTimes.Any(d => d.Year < 2000 || d.Year > 2100) || pf.RunCount < 0;
                return bad ? "implausible-values" : "plausible";
            }
            case "lnk":
            {
                var l = new Lnk.LnkFile(data, "x.lnk");
                return l.Header == null ? "no-header" : "parsed";
            }
            case "autodest":
            {
                var a = new JumpList.Automatic.AutomaticDestination(data, "x.automaticDestinations-ms");
                return a.DestListEntries.Count > 100000 ? "implausible-values" : "parsed";
            }
            case "customdest":
            {
                var c = new JumpList.Custom.CustomDestination(data, "x.customDestinations-ms");
                return "parsed";
            }
            case "mftrecord":
            {
                var f = new MFT.FileRecord(data, 0, false);
                return f.IsBad ? "flagged-bad" : (f.ParseErrors.Count > 0 ? "parsed-with-errors" : "parsed");
            }
            case "mftfile":
            {
                var m = new MFT.Mft(new MemoryStream(data), false);
                return m.ParseErrors.Count > 0 ? "parsed-with-errors" : "parsed";
            }
            case "usn":
            {
                var u = new Usn.Usn(new MemoryStream(data), 0);
                return "parsed";
            }
            default: throw new ArgumentException(kind);
        }
    }

    static List<(string, byte[])> Samples(string kind, string dir)
    {
        var list = new List<(string, byte[])>();
        if (kind == "mftrecord")
        {
            // first 200 records of each $MFT as individual 1 KB records
            foreach (var f in Directory.GetFiles(dir, "$MFT", SearchOption.AllDirectories))
            {
                var b = File.ReadAllBytes(f);
                var n = Math.Min(200, b.Length / 1024);
                for (var i = 0; i < n; i += 10) list.Add((Path.GetFileName(Path.GetDirectoryName(f)) + $"/rec{i}", b.AsSpan(i * 1024, 1024).ToArray()));
            }
            return list;
        }
        if (kind == "mftfile")
        {
            foreach (var f in Directory.GetFiles(dir, "$MFT", SearchOption.AllDirectories))
            {
                var b = File.ReadAllBytes(f);
                list.Add((Path.GetFileName(Path.GetDirectoryName(f)), b.AsSpan(0, Math.Min(b.Length, 256 * 1024)).ToArray()));
            }
            return list;
        }
        var pattern = kind switch { "prefetch" => "*.pf", "lnk" => "*.lnk", "autodest" => "*.automaticDestinations-ms", "customdest" => "*.customDestinations-ms", "usn" => "*", _ => "*" };
        var files = Directory.GetFiles(dir, pattern, SearchOption.AllDirectories).Where(f => !f.Contains("/Bad/")).OrderBy(x => x).ToList();
        if (kind == "lnk") files = files.Where((_, i) => i % 12 == 0).ToList();
        foreach (var f in files)
        {
            var b = File.ReadAllBytes(f);
            if (kind == "usn")
            {
                var start = 0;
                while (start < b.Length && b[start] == 0) start++;
                start -= start % 8;
                b = b.AsSpan(start, Math.Min(b.Length - start, 64 * 1024)).ToArray();
            }
            list.Add((Path.GetRelativePath(dir, f), b));
        }
        return list;
    }
}
