using System.Text;
using XINSkan.Security;

namespace XINSkan.SecurityTests;

internal sealed class FixedTime(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;
}

public sealed class OutputSinkTests : IDisposable
{
    private readonly string _base = Path.Combine(Path.GetTempPath(), "xinskan-out-" + Guid.NewGuid().ToString("N"));

    public OutputSinkTests() => Directory.CreateDirectory(_base);

    public void Dispose()
    {
        foreach (var f in Directory.EnumerateFiles(_base, "*", SearchOption.AllDirectories))
        {
            System.IO.File.SetAttributes(f, FileAttributes.Normal);
        }

        Directory.Delete(_base, recursive: true);
    }

    [Fact]
    public void Investigation_folder_is_new_and_cannot_be_reused()
    {
        var sink = OutputSink.CreateInvestigationFolder(_base, "inv-01");
        Assert.True(Directory.Exists(sink.Root));
        Assert.Throws<IOException>(() => OutputSink.CreateInvestigationFolder(_base, "inv-01"));
    }

    [Fact]
    public void Existing_file_is_never_overwritten()
    {
        var sink = OutputSink.CreateInvestigationFolder(_base, "inv-02");
        sink.WriteNew("report.json", "first"u8);
        Assert.Throws<IOException>(() => sink.WriteNew("report.json", "second"u8));
        Assert.Equal("first", System.IO.File.ReadAllText(Path.Combine(sink.Root, "report.json")));
    }

    [Theory]
    [InlineData(@"..\escape.txt")]
    [InlineData("../escape.txt")]
    [InlineData(@"sub\..\..\escape.txt")]
    [InlineData(@"C:\Windows\escape.txt")]
    [InlineData("/etc/escape.txt")]
    [InlineData("report.json:hidden")]
    [InlineData(@".\report.json")]
    public void Paths_outside_the_folder_or_alternate_streams_are_refused(string path)
    {
        var sink = OutputSink.CreateInvestigationFolder(_base, "inv-03-" + Guid.NewGuid().ToString("N")[..6]);
        Assert.ThrowsAny<UnauthorizedAccessException>(() => sink.CreateNew(path).Dispose());
        Assert.Empty(sink.CreatedFiles);
    }

    [Theory]
    [InlineData("..")]
    [InlineData("a/b")]
    [InlineData(@"a\b")]
    public void Folder_name_must_be_a_single_component(string name)
    {
        Assert.ThrowsAny<Exception>(() => OutputSink.CreateInvestigationFolder(_base, name));
    }

    [Fact]
    public void Nested_files_are_created_and_tracked_in_order()
    {
        var sink = OutputSink.CreateInvestigationFolder(_base, "inv-04");
        sink.WriteNew("a.txt", "a"u8);
        sink.WriteNew(Path.Combine("reports", "expert.json"), "{}"u8);
        Assert.Equal(new[] { "a.txt", Path.Combine("reports", "expert.json") }, sink.CreatedFiles);
    }

    [Fact]
    public void Only_own_files_can_be_reopened()
    {
        var sink = OutputSink.CreateInvestigationFolder(_base, "inv-05");
        System.IO.File.WriteAllText(Path.Combine(sink.Root, "foreign.txt"), "x");
        Assert.Throws<InvalidOperationException>(() => sink.OpenOwnForRead("foreign.txt"));
    }

    [Fact]
    public void Sealed_file_is_read_only()
    {
        var sink = OutputSink.CreateInvestigationFolder(_base, "inv-06");
        sink.WriteNew("final.json", "{}"u8);
        sink.Seal("final.json");
        Assert.True(System.IO.File.GetAttributes(Path.Combine(sink.Root, "final.json")).HasFlag(FileAttributes.ReadOnly));
    }

    [Fact]
    public void Output_on_an_investigated_volume_is_flagged()
    {
        var root = Path.GetPathRoot(_base)!;
        Assert.True(OutputLocationPolicy.Assess(_base, [root]).OnInvestigatedVolume);
        Assert.False(OutputLocationPolicy.Assess(_base, []).OnInvestigatedVolume);
        if (OperatingSystem.IsWindows())
        {
            Assert.False(OutputLocationPolicy.Assess(@"E:\cases", [@"C:\"]).OnInvestigatedVolume);
            Assert.True(OutputLocationPolicy.Assess(@"c:\cases", [@"C:\"]).OnInvestigatedVolume);
        }
    }
}

public sealed class AuditLoggerTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 8, 12, 0, 0, TimeSpan.Zero);

    private static byte[] WriteLog(int entries)
    {
        using var ms = new MemoryStream();
        var time = new FixedTime(T0);
        var log = new AuditLogger(ms, time);
        for (var i = 0; i < entries; i++)
        {
            log.Record("open", $@"C:\Users\p\.minecraft\mods\m{i}.jar", "GENERIC_READ, share RWD", "ok", i % 2 == 0 ? null : "детали \"в кавычках\"");
            time.Now = time.Now.AddSeconds(1);
        }

        return ms.ToArray();
    }

    private static AuditVerification Verify(byte[] log) => AuditLogger.Verify(new MemoryStream(log));

    private static string[] Lines(byte[] log) => Encoding.UTF8.GetString(log).Split('\n', StringSplitOptions.RemoveEmptyEntries);

    private static byte[] Join(IEnumerable<string> lines) => Encoding.UTF8.GetBytes(string.Join('\n', lines) + "\n");

    [Fact]
    public void Untouched_log_verifies()
    {
        var v = Verify(WriteLog(5));
        Assert.True(v.Intact, v.Problem);
        Assert.Equal(5, v.Entries);
    }

    [Fact]
    public void Empty_log_verifies()
    {
        Assert.True(Verify([]).Intact);
    }

    [Fact]
    public void Edited_entry_is_detected()
    {
        var lines = Lines(WriteLog(5));
        lines[2] = lines[2].Replace("m2.jar", "m9.jar", StringComparison.Ordinal);
        var v = Verify(Join(lines));
        Assert.False(v.Intact);
        Assert.Equal(3, v.FirstBrokenSequence);
    }

    [Fact]
    public void Removed_entry_is_detected()
    {
        var lines = Lines(WriteLog(5)).ToList();
        lines.RemoveAt(1);
        var v = Verify(Join(lines));
        Assert.False(v.Intact);
        Assert.Equal(2, v.FirstBrokenSequence);
    }

    [Fact]
    public void Reordered_entries_are_detected()
    {
        var lines = Lines(WriteLog(5));
        (lines[1], lines[2]) = (lines[2], lines[1]);
        Assert.False(Verify(Join(lines)).Intact);
    }

    [Fact]
    public void Truncated_tail_is_not_detected_without_an_external_anchor()
    {
        // Documented limit: dropping the last entries leaves a valid shorter chain. The manifest hash closes this gap.
        var lines = Lines(WriteLog(5)).Take(3);
        var v = Verify(Join(lines));
        Assert.True(v.Intact);
        Assert.Equal(3, v.Entries);
    }

    [Fact]
    public void Garbage_line_is_detected()
    {
        var lines = Lines(WriteLog(2)).Append("not json").ToArray();
        var v = Verify(Join(lines));
        Assert.False(v.Intact);
        Assert.Equal(3, v.FirstBrokenSequence);
    }

    [Fact]
    public void Read_only_stream_is_refused()
    {
        using var ro = new MemoryStream(new byte[10], writable: false);
        Assert.Throws<ArgumentException>(() => new AuditLogger(ro, TimeProvider.System));
    }
}

public sealed class IntegrityManifestTests : IDisposable
{
    private readonly string _base = Path.Combine(Path.GetTempPath(), "xinskan-man-" + Guid.NewGuid().ToString("N"));
    private readonly FixedTime _time = new(new DateTimeOffset(2026, 11, 8, 12, 0, 0, TimeSpan.Zero));

    public IntegrityManifestTests() => Directory.CreateDirectory(_base);

    public void Dispose() => Directory.Delete(_base, recursive: true);

    private OutputSink Sink(string name)
    {
        var sink = OutputSink.CreateInvestigationFolder(_base, name);
        sink.WriteNew("evidence.db", "database bytes"u8);
        sink.WriteNew(Path.Combine("reports", "admin.html"), "<html></html>"u8);
        IntegrityManifest.Write(sink, _time);
        return sink;
    }

    [Fact]
    public void Fresh_investigation_verifies()
    {
        Assert.Empty(IntegrityManifest.Verify(Sink("a").Root));
    }

    [Fact]
    public void Changed_file_is_reported()
    {
        var sink = Sink("b");
        System.IO.File.WriteAllText(Path.Combine(sink.Root, "evidence.db"), "tampered");
        Assert.Contains(IntegrityManifest.Verify(sink.Root), p => p.Path == "evidence.db" && p.Problem.Contains("differs", StringComparison.Ordinal));
    }

    [Fact]
    public void Missing_and_added_files_are_reported()
    {
        var sink = Sink("c");
        System.IO.File.Delete(Path.Combine(sink.Root, "reports", "admin.html"));
        System.IO.File.WriteAllText(Path.Combine(sink.Root, "extra.txt"), "x");
        var problems = IntegrityManifest.Verify(sink.Root);
        Assert.Contains(problems, p => p.Path == "reports/admin.html" && p.Problem.Contains("missing", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.Path == "extra.txt");
    }

    [Fact]
    public void Manifest_cannot_be_written_twice()
    {
        var sink = Sink("d");
        Assert.Throws<IOException>(() => IntegrityManifest.Write(sink, _time));
    }
}
