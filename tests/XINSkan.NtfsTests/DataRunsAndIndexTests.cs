using XINSkan.Ntfs;
using XINSkan.NtfsTests.Support;

namespace XINSkan.NtfsTests;

public sealed class DataRunsTests
{
    [Fact]
    public void Runs_with_relative_and_negative_offsets_and_sparse_parts_are_decoded()
    {
        // 0x21: 1-byte length 0x18, 2-byte offset 0x5634 → LCN 0x5634
        // 0x01: sparse, length 8
        // 0x11: length 0x10, offset -0x10 (0xF0) → 0x5624
        // 0x31: length 1, 3-byte offset 0x010000 → 0x015624
        byte[] b = [0x21, 0x18, 0x34, 0x56, 0x01, 0x08, 0x11, 0x10, 0xF0, 0x31, 0x01, 0x00, 0x00, 0x01, 0x00];
        var runs = DataRuns.Decode(b, out var problem);

        Assert.Null(problem);
        Assert.Equal(new[] { new DataRun(0x5634, 0x18), new DataRun(null, 8), new DataRun(0x5624, 0x10), new DataRun(0x15624, 1) }, runs);
    }

    [Fact]
    public void A_one_byte_length_with_the_top_bit_set_is_a_length_not_a_negative_number()
    {
        var runs = DataRuns.Decode([0x11, 0x80, 0x10, 0x00], out var problem);
        Assert.Null(problem);
        Assert.Equal(new DataRun(0x10, 0x80), Assert.Single(runs));
    }

    [Theory]
    [InlineData(new byte[] { 0x19, 0x01 })]              // 9-byte length field
    [InlineData(new byte[] { 0x21, 0x01 })]              // header promises more bytes than exist
    [InlineData(new byte[] { 0x11, 0x00, 0x05, 0x00 })]  // zero length
    [InlineData(new byte[] { 0x11, 0x05, 0xF0, 0x00 })]  // starts before the volume
    [InlineData(new byte[] { 0x11, 0x05, 0x10 })]        // no terminator
    public void Damaged_runs_stop_with_a_reason(byte[] b)
    {
        _ = DataRuns.Decode(b, out var problem);
        Assert.NotNull(problem);
    }
}

public sealed class MftIndexTests
{
    private const long T = 133_485_408_000_000_000;

    private static MftRecord Dir(uint entry, uint parent, string name, ushort seq = 1, ushort parentSeq = 1, bool inUse = true) =>
        MftRecord.Parse(new RecordBuilder { Sequence = seq, Flags = (ushort)((inUse ? 1 : 0) | 2) }
            .Resident(MftRecord.TypeFileName, RecordBuilder.FileName(parent, parentSeq, name, T)).Build(entry), entry);

    [Fact]
    public void A_folder_that_contains_itself_does_not_loop()
    {
        var index = new MftIndex(100, "C:");
        index.Add(Dir(40, 41, "a"));
        index.Add(Dir(41, 40, "b"));

        var p = index.Resolve(new FileReference(40, 1), "x.jar");
        Assert.True(p.Quality.HasFlag(PathQuality.Broken));
        Assert.EndsWith(@"\a\x.jar", p.Path, StringComparison.Ordinal);
    }

    [Fact]
    public void A_missing_parent_cuts_the_path_and_says_so()
    {
        var index = new MftIndex(100, "C:");
        index.Add(Dir(40, 90, "orphan"));
        var p = index.Resolve(new FileReference(40, 1), "x.jar");
        Assert.Equal(@"C:\?\orphan\x.jar", p.Path);
        Assert.Equal(PathQuality.Broken, p.Quality);
    }

    [Fact]
    public void References_beyond_the_table_are_missing_not_a_crash()
    {
        var index = new MftIndex(10, "C:");
        Assert.Equal(ReferenceState.Missing, index.Check(new FileReference(1UL << 40, 1)));
        Assert.Equal(PathQuality.Broken, index.Resolve(new FileReference(1UL << 40, 1), "x").Quality);
    }

    [Fact]
    public void Deep_paths_are_rebuilt_and_cached_consistently()
    {
        var index = new MftIndex(400, "C:");
        index.Add(Dir(6, 5, "d0", parentSeq: 5));
        for (uint i = 7; i < 306; i++)
        {
            index.Add(Dir(i, i - 1, "d" + (i - 6)));
        }

        var shallow = index.Resolve(new FileReference(50, 1), "f");
        Assert.Equal(PathQuality.Complete, shallow.Quality);
        Assert.StartsWith(@"C:\d0\d1\d2\", shallow.Path, StringComparison.Ordinal);
        Assert.Equal(shallow, index.Resolve(new FileReference(50, 1), "f"));

        // Deeper than any real path (NTFS allows ~32 000 characters): cut, not overflowed.
        Assert.True(index.Resolve(new FileReference(305, 1), "f").Quality.HasFlag(PathQuality.Broken));
    }

    [Fact]
    public void A_name_held_only_in_an_extension_record_is_used()
    {
        var index = new MftIndex(100, "C:");
        index.Add(Dir(6, 5, "Games", parentSeq: 5));
        var ext = MftRecord.Parse(new RecordBuilder { BaseRecord = 30 | (1UL << 48) }
            .Resident(MftRecord.TypeFileName, RecordBuilder.FileName(6, 1, "Impact", T)).Build(70), 70);
        index.Add(ext);
        index.Add(MftRecord.Parse(new RecordBuilder { Flags = 3 }.Build(30), 30)); // base with no name of its own

        Assert.Equal(@"C:\Games\Impact\x.jar", index.Resolve(new FileReference(30, 1), "x.jar").Path);
    }
}
