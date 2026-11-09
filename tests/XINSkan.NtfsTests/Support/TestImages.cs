using System.IO.Compression;
using System.Reflection;
using XINSkan.Ntfs;

namespace XINSkan.NtfsTests.Support;

/// <summary>NTFS images built by TestData/*.sh and embedded gzipped.</summary>
internal static class TestImages
{
    private static readonly Lazy<byte[]> PlayerBytes = new(() => Load("player.img.gz"));

    /// <summary>A fresh, independent copy of the player image (tests may corrupt it).</summary>
    public static MemoryStream Player() => new(PlayerBytes.Value, writable: false);

    public static byte[] PlayerCopy() => (byte[])PlayerBytes.Value.Clone();

    private static byte[] Load(string name)
    {
        var asm = typeof(TestImages).Assembly;
        using var s = asm.GetManifestResourceStream(name)
                      ?? asm.GetManifestResourceStream(asm.GetManifestResourceNames().Single(n => n.EndsWith(name, StringComparison.Ordinal)));
        using var gz = new GZipStream(s!, CompressionMode.Decompress);
        using var ms = new MemoryStream();
        gz.CopyTo(ms);
        return ms.ToArray();
    }
}

/// <summary>The player image parsed once: every record, and the path index.</summary>
internal sealed class PlayerVolume
{
    public static readonly Lazy<PlayerVolume> Instance = new(() => new PlayerVolume());

    private PlayerVolume()
    {
        Reader = MftReader.Open(new StreamVolume(TestImages.Player()));
        Index = new MftIndex(Reader.RecordCount, "C:");
        foreach (var raw in Reader.ReadRecords())
        {
            var r = MftRecord.Parse(raw.Bytes.Span, raw.Entry);
            Records.Add(r);
            Index.Add(r);
        }
    }

    public MftReader Reader { get; }

    public MftIndex Index { get; }

    public List<MftRecord> Records { get; } = [];

    public string PathOf(MftRecord r) => Index.Resolve(r.PrimaryName!.Parent, r.PrimaryName.Name).Path;

    public MftRecord Live(string path) => Records.Single(r => r.State == MftRecordState.Parsed && r.InUse && !r.IsExtension
                                                              && r.PrimaryName is not null && PathOf(r) == path);
}

/// <summary>
/// Tests on third-party reference samples (the MFT library's test files at a pinned commit; CI clones them).
/// Skipped when XINSKAN_NTFS_SAMPLES is not set, unless XINSKAN_REQUIRE_SAMPLES=1 — then they must run.
/// </summary>
public sealed class SampleFactAttribute : FactAttribute
{
    public SampleFactAttribute()
    {
        if (SampleRoot is null && Environment.GetEnvironmentVariable("XINSKAN_REQUIRE_SAMPLES") != "1")
        {
            Skip = "XINSKAN_NTFS_SAMPLES is not set.";
        }
    }

    public static string? SampleRoot => Environment.GetEnvironmentVariable("XINSKAN_NTFS_SAMPLES") is { Length: > 0 } p ? p : null;

    public static string File(params string[] parts) =>
        Path.Combine([SampleRoot ?? throw new InvalidOperationException("XINSKAN_NTFS_SAMPLES is required but not set."), .. parts]);
}

/// <summary>Builds FILE records byte by byte, for cases no real volume produces on demand.</summary>
internal sealed class RecordBuilder
{
    private readonly List<byte[]> _attributes = [];

    public ushort Sequence { get; set; } = 1;

    public ushort Flags { get; set; } = 1;

    public ulong BaseRecord { get; set; }

    public RecordBuilder Resident(uint type, byte[] value, string name = "")
    {
        var nameBytes = System.Text.Encoding.Unicode.GetBytes(name);
        var valueOffset = Align(24 + nameBytes.Length);
        var length = Align(valueOffset + value.Length);
        var a = new byte[length];
        BitConverter.TryWriteBytes(a.AsSpan(0), type);
        BitConverter.TryWriteBytes(a.AsSpan(4), (uint)length);
        a[8] = 0;
        a[9] = (byte)name.Length;
        BitConverter.TryWriteBytes(a.AsSpan(10), (ushort)24);
        BitConverter.TryWriteBytes(a.AsSpan(16), (uint)value.Length);
        BitConverter.TryWriteBytes(a.AsSpan(20), (ushort)valueOffset);
        nameBytes.CopyTo(a, 24);
        value.CopyTo(a, valueOffset);
        _attributes.Add(a);
        return this;
    }

    public RecordBuilder NonResidentData(long size, byte[] runs, string name = "", long startVcn = 0)
    {
        var nameBytes = System.Text.Encoding.Unicode.GetBytes(name);
        var runsOffset = Align(64 + nameBytes.Length);
        var length = Align(runsOffset + runs.Length + 1);
        var a = new byte[length];
        BitConverter.TryWriteBytes(a.AsSpan(0), MftRecord.TypeData);
        BitConverter.TryWriteBytes(a.AsSpan(4), (uint)length);
        a[8] = 1;
        a[9] = (byte)name.Length;
        BitConverter.TryWriteBytes(a.AsSpan(10), (ushort)64);
        BitConverter.TryWriteBytes(a.AsSpan(16), startVcn);
        BitConverter.TryWriteBytes(a.AsSpan(32), (ushort)runsOffset);
        BitConverter.TryWriteBytes(a.AsSpan(40), (size + 4095) / 4096 * 4096);
        BitConverter.TryWriteBytes(a.AsSpan(48), size);
        BitConverter.TryWriteBytes(a.AsSpan(56), size);
        nameBytes.CopyTo(a, 64);
        runs.CopyTo(a, runsOffset);
        _attributes.Add(a);
        return this;
    }

    public RecordBuilder Raw(byte[] attribute)
    {
        _attributes.Add(attribute);
        return this;
    }

    public static byte[] StandardInformation(long created, long modified, long mftModified, long accessed)
    {
        var v = new byte[72];
        BitConverter.TryWriteBytes(v.AsSpan(0), created);
        BitConverter.TryWriteBytes(v.AsSpan(8), modified);
        BitConverter.TryWriteBytes(v.AsSpan(16), mftModified);
        BitConverter.TryWriteBytes(v.AsSpan(24), accessed);
        BitConverter.TryWriteBytes(v.AsSpan(32), 0x20u);
        return v;
    }

    public static byte[] FileName(ulong parentEntry, ushort parentSeq, string name, long time, FileNameNamespace ns = FileNameNamespace.Win32)
    {
        var v = new byte[66 + (name.Length * 2)];
        BitConverter.TryWriteBytes(v.AsSpan(0), parentEntry | ((ulong)parentSeq << 48));
        for (var i = 0; i < 4; i++)
        {
            BitConverter.TryWriteBytes(v.AsSpan(8 + (i * 8)), time);
        }

        v[64] = (byte)name.Length;
        v[65] = (byte)ns;
        System.Text.Encoding.Unicode.GetBytes(name).CopyTo(v, 66);
        return v;
    }

    /// <summary>A 1024-byte record with a valid update sequence (two 512-byte strides).</summary>
    public byte[] Build(uint entry)
    {
        var r = new byte[1024];
        "FILE"u8.CopyTo(r);
        BitConverter.TryWriteBytes(r.AsSpan(4), (ushort)48);
        BitConverter.TryWriteBytes(r.AsSpan(6), (ushort)3);
        BitConverter.TryWriteBytes(r.AsSpan(16), Sequence);
        BitConverter.TryWriteBytes(r.AsSpan(18), (ushort)1);
        BitConverter.TryWriteBytes(r.AsSpan(20), (ushort)56);
        BitConverter.TryWriteBytes(r.AsSpan(22), Flags);
        BitConverter.TryWriteBytes(r.AsSpan(28), 1024u);
        BitConverter.TryWriteBytes(r.AsSpan(32), BaseRecord);
        BitConverter.TryWriteBytes(r.AsSpan(44), entry);
        var o = 56;
        foreach (var a in _attributes)
        {
            a.CopyTo(r, o);
            o += a.Length;
        }

        BitConverter.TryWriteBytes(r.AsSpan(o), 0xFFFF_FFFFu);
        BitConverter.TryWriteBytes(r.AsSpan(24), (uint)(o + 8));

        // Update sequence: check value 0x0007; original tails saved in the array.
        BitConverter.TryWriteBytes(r.AsSpan(48), (ushort)7);
        for (var i = 1; i <= 2; i++)
        {
            var tail = (i * 512) - 2;
            r.AsSpan(tail, 2).CopyTo(r.AsSpan(48 + (i * 2)));
            BitConverter.TryWriteBytes(r.AsSpan(tail), (ushort)7);
        }

        return r;
    }

    private static int Align(int v) => (v + 7) & ~7;
}
