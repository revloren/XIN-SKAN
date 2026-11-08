using XINSkan.Platform.Windows.IO;

namespace XINSkan.SecurityTests;

public class IoControlAllowListTests
{
    [Fact]
    public void Allow_list_contains_exactly_the_reviewed_query_and_read_codes()
    {
        var codes = Enum.GetValues<AllowedIoControl>().Select(c => (uint)c).Order().ToArray();
        Assert.Equal(new uint[] { 0x0007_0000, 0x0009_0064, 0x0009_0073, 0x0009_00B3, 0x0009_00BB, 0x0009_00F4 }, codes);
    }

    [Theory]
    [InlineData(0x0009_00F8u)] // FSCTL_DELETE_USN_JOURNAL
    [InlineData(0x0009_00E7u)] // FSCTL_CREATE_USN_JOURNAL
    [InlineData(0x0009_00EFu)] // FSCTL_WRITE_USN_CLOSE_RECORD
    [InlineData(0x0009_0018u)] // FSCTL_LOCK_VOLUME
    [InlineData(0x0009_0020u)] // FSCTL_DISMOUNT_VOLUME
    [InlineData(0x0009_80C8u)] // FSCTL_SET_ZERO_DATA
    [InlineData(0x0009_00C4u)] // FSCTL_SET_SPARSE
    public void State_changing_codes_are_refused_even_when_cast_in(uint code)
    {
        Assert.False(Enum.IsDefined((AllowedIoControl)code));
        Assert.Throws<ArgumentOutOfRangeException>(() => SafeIoControl.EnsureAllowed((AllowedIoControl)code));
    }
}

public class NtfsVolumeDataTests
{
    private static byte[] Buffer(uint sector = 512, uint cluster = 4096, uint record = 1024)
    {
        var b = new byte[96];
        BitConverter.GetBytes(0x1234_5678_9ABC_DEF0UL).CopyTo(b, 0);
        BitConverter.GetBytes(1_000_000L).CopyTo(b, 8);
        BitConverter.GetBytes(125_000L).CopyTo(b, 16);
        BitConverter.GetBytes(sector).CopyTo(b, 40);
        BitConverter.GetBytes(cluster).CopyTo(b, 44);
        BitConverter.GetBytes(record).CopyTo(b, 48);
        BitConverter.GetBytes(262_144L).CopyTo(b, 56);
        BitConverter.GetBytes(786_432L).CopyTo(b, 64);
        BitConverter.GetBytes(2L).CopyTo(b, 72);
        return b;
    }

    [Fact]
    public void Parses_the_fixed_layout()
    {
        var d = NtfsVolumeData.Parse(Buffer());
        Assert.Equal(0x1234_5678_9ABC_DEF0UL, d.VolumeSerialNumber);
        Assert.Equal(512u, d.BytesPerSector);
        Assert.Equal(4096u, d.BytesPerCluster);
        Assert.Equal(1024u, d.BytesPerFileRecordSegment);
        Assert.Equal(262_144L, d.MftValidDataLength);
        Assert.Equal(786_432L, d.MftStartLcn);
        Assert.Equal(2L, d.Mft2StartLcn);
    }

    [Theory]
    [InlineData(0u, 4096u, 1024u)]
    [InlineData(500u, 4096u, 1024u)]
    [InlineData(4096u, 512u, 1024u)]
    [InlineData(512u, 4096u, 0u)]
    [InlineData(512u, 4096u, 1_000_000u)]
    public void Implausible_geometry_is_rejected(uint sector, uint cluster, uint record)
    {
        Assert.Throws<InvalidDataException>(() => NtfsVolumeData.Parse(Buffer(sector, cluster, record)));
    }

    [Fact]
    public void Short_buffer_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => NtfsVolumeData.Parse(new byte[95]));
    }
}

public class ReadOnlyHandleStreamTests
{
    [Fact]
    public void Stream_reads_and_seeks_but_cannot_write()
    {
        var path = Path.Combine(Path.GetTempPath(), "xinskan-" + Guid.NewGuid().ToString("N") + ".bin");
        var content = Enumerable.Range(0, 10_000).Select(i => (byte)(i % 251)).ToArray();
        System.IO.File.WriteAllBytes(path, content);
        try
        {
            using var handle = System.IO.File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var s = new ReadOnlyHandleStream(handle, ownsHandle: false);

            Assert.False(s.CanWrite);
            Assert.True(s.CanRead);
            Assert.Equal(content.Length, s.Length);

            s.Seek(5000, SeekOrigin.Begin);
            var part = new byte[100];
            Assert.Equal(100, s.Read(part, 0, 100));
            Assert.Equal(content.AsSpan(5000, 100).ToArray(), part);

            using var copy = new MemoryStream();
            s.Position = 0;
            s.CopyTo(copy);
            Assert.Equal(content, copy.ToArray());

            Assert.Throws<NotSupportedException>(() => s.Write(new byte[1], 0, 1));
            Assert.Throws<NotSupportedException>(() => s.WriteByte(1));
            Assert.Throws<NotSupportedException>(() => s.SetLength(0));
            Assert.Throws<ArgumentOutOfRangeException>(() => s.Seek(-1, SeekOrigin.Begin));
        }
        finally
        {
            System.IO.File.Delete(path);
        }

        Assert.False(System.IO.File.Exists(path));
    }

    [Fact]
    public void Reading_past_the_end_returns_zero()
    {
        var path = Path.Combine(Path.GetTempPath(), "xinskan-" + Guid.NewGuid().ToString("N") + ".bin");
        System.IO.File.WriteAllBytes(path, [1, 2, 3]);
        try
        {
            using var handle = System.IO.File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var s = new ReadOnlyHandleStream(handle, ownsHandle: false);
            s.Position = 10;
            Assert.Equal(0, s.Read(new byte[4], 0, 4));
        }
        finally
        {
            System.IO.File.Delete(path);
        }
    }
}
