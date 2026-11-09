using System.Buffers.Binary;
using XINSkan.Ntfs;
using XINSkan.NtfsTests.Support;

namespace XINSkan.NtfsTests;

public sealed class MftRecordTests
{
    private const long T2024 = 133_485_408_000_000_000; // 2024-01-01T00:00:00Z

    private static RecordBuilder File(string name = "client.jar") => new RecordBuilder()
        .Resident(MftRecord.TypeStandardInformation, RecordBuilder.StandardInformation(T2024, T2024 + 10, T2024 + 20, T2024 + 30))
        .Resident(MftRecord.TypeFileName, RecordBuilder.FileName(64, 3, name, T2024));

    [Fact]
    public void A_well_formed_record_is_parsed_without_problems()
    {
        var r = MftRecord.Parse(File().Build(100), 100);

        Assert.Equal(MftRecordState.Parsed, r.State);
        Assert.True(r.FixupOk);
        Assert.Empty(r.Problems);
        Assert.True(r.InUse);
        Assert.Equal("client.jar", r.PrimaryName!.Name);
        Assert.Equal(new FileReference(64, 3), r.PrimaryName.Parent);
        Assert.Equal(T2024 + 10, r.StandardInformation!.Times.Modified);
        Assert.Equal(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero), NtfsTime.ToUtc(r.PrimaryName.Times.Created));
    }

    [Fact]
    public void The_input_buffer_is_never_modified()
    {
        var bytes = File().Build(100);
        var copy = (byte[])bytes.Clone();
        _ = MftRecord.Parse(bytes, 100);
        Assert.Equal(copy, bytes);
    }

    [Fact]
    public void A_torn_write_is_detected_by_the_update_sequence()
    {
        var bytes = File().Build(100);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(1022), 0x1234); // second sector never written
        var r = MftRecord.Parse(bytes, 100);

        Assert.False(r.FixupOk);
        Assert.Contains(r.Problems, p => p.Contains("Проверка секторов", StringComparison.Ordinal));
        Assert.Equal("client.jar", r.PrimaryName!.Name); // the first sector is still usable
    }

    [Fact]
    public void Empty_and_bad_records_are_told_apart()
    {
        Assert.Equal(MftRecordState.Empty, MftRecord.Parse(new byte[1024], 7).State);

        var baad = File().Build(7);
        "BAAD"u8.CopyTo(baad);
        var r = MftRecord.Parse(baad, 7);
        Assert.Equal(MftRecordState.Invalid, r.State);
        Assert.Contains("BAAD", r.Problems.Single(), StringComparison.Ordinal);

        Assert.Equal(MftRecordState.Invalid, MftRecord.Parse(new byte[20], 7).State);
    }

    [Fact]
    public void The_long_name_wins_over_the_dos_name()
    {
        var r = MftRecord.Parse(new RecordBuilder()
            .Resident(MftRecord.TypeFileName, RecordBuilder.FileName(64, 3, "CHEATC~1.JAR", T2024, FileNameNamespace.Dos))
            .Resident(MftRecord.TypeFileName, RecordBuilder.FileName(64, 3, "cheat client.jar", T2024, FileNameNamespace.Win32))
            .Build(9), 9);

        Assert.Equal("cheat client.jar", r.PrimaryName!.Name);
        Assert.Equal(2, r.FileNames.Count);
    }

    [Fact]
    public void Attribute_and_name_bounds_are_checked()
    {
        var bad = new byte[24];
        BitConverter.TryWriteBytes(bad.AsSpan(0), MftRecord.TypeFileName);
        BitConverter.TryWriteBytes(bad.AsSpan(4), 4000u); // longer than the record
        var r = MftRecord.Parse(new RecordBuilder().Raw(bad).Build(9), 9);
        Assert.Contains(r.Problems, p => p.Contains("Длина атрибута", StringComparison.Ordinal));

        var name = RecordBuilder.FileName(64, 3, "x.jar", T2024);
        name[64] = 200; // claims 200 characters
        r = MftRecord.Parse(new RecordBuilder().Resident(MftRecord.TypeFileName, name).Build(9), 9);
        Assert.Empty(r.FileNames);
        Assert.Contains(r.Problems, p => p.Contains("Имя в $FILE_NAME", StringComparison.Ordinal));
    }

    [Fact]
    public void Non_resident_content_reports_size_and_optionally_runs()
    {
        byte[] runs = [0x11, 0x05, 0x40, 0x21, 0x03, 0x00, 0x10];
        var bytes = new RecordBuilder().NonResidentData(30_000, runs).Build(9);

        var without = MftRecord.Parse(bytes, 9);
        Assert.Equal(30_000, without.MainData!.Size);
        Assert.Null(without.MainData.Runs);

        var with = MftRecord.Parse(bytes, 9, includeRuns: true);
        Assert.Equal(new[] { new DataRun(0x40, 5), new DataRun(0x40 + 0x1000, 3) }, with.MainData!.Runs);
    }

    [Fact]
    public void Resident_values_above_the_limit_are_not_kept()
    {
        var r = MftRecord.Parse(new RecordBuilder().Resident(MftRecord.TypeData, new byte[600]).Build(9), 9, maxResidentBytes: 512);
        Assert.Equal(600, r.MainData!.Size);
        Assert.Null(r.MainData.ResidentValue);
    }

    [Fact]
    public void Resident_attribute_list_entries_are_read()
    {
        var list = new byte[64];
        void Entry(int at, uint type, long vcn, ulong entry, ushort seq)
        {
            BitConverter.TryWriteBytes(list.AsSpan(at), type);
            BitConverter.TryWriteBytes(list.AsSpan(at + 4), (ushort)32);
            list[at + 7] = 26;
            BitConverter.TryWriteBytes(list.AsSpan(at + 8), vcn);
            BitConverter.TryWriteBytes(list.AsSpan(at + 16), entry | ((ulong)seq << 48));
        }

        Entry(0, MftRecord.TypeData, 0, 9, 1);
        Entry(32, MftRecord.TypeData, 559, 2120, 2);
        var r = MftRecord.Parse(new RecordBuilder().Resident(MftRecord.TypeAttributeList, list).Build(9), 9);

        Assert.Equal(new[] { "9-1:0", "2120-2:559" }, r.AttributeList!.Select(a => $"{a.Record.Entry}-{a.Record.Sequence}:{a.StartVcn}"));
    }

    [Fact]
    public void An_extension_record_names_its_base()
    {
        var r = MftRecord.Parse(new RecordBuilder { BaseRecord = 485 | (2UL << 48) }.Build(432), 432);
        Assert.True(r.IsExtension);
        Assert.Equal(new FileReference(485, 2), r.BaseRecord);
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-5L)]
    [InlineData(long.MaxValue)]
    [InlineData(100_000_000_000_000_000L)] // 1917
    [InlineData(170_000_000_000_000_000L)] // 2139
    public void Impossible_times_are_not_converted(long fileTime) => Assert.Null(NtfsTime.ToUtc(fileTime));

    [Fact]
    public void Whole_second_times_are_recognised()
    {
        Assert.True(NtfsTime.HasZeroFraction(T2024));
        Assert.False(NtfsTime.HasZeroFraction(T2024 + 1));
        Assert.False(NtfsTime.HasZeroFraction(0));
    }

    [Fact]
    public void Random_damage_never_throws_and_never_hangs()
    {
        var images = PlayerVolume.Instance.Value;
        var seeds = images.Records.Where(r => r.State == MftRecordState.Parsed).Select(r => r.Entry).Take(400).ToList();
        var raw = TestImages.PlayerCopy();
        var rng = new Random(20261109);
        var mftOffset = images.Reader.Boot.MftLcn * images.Reader.Boot.BytesPerCluster;
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var parsed = 0;
        for (var i = 0; i < 30_000; i++)
        {
            var entry = seeds[rng.Next(seeds.Count)];
            var record = raw.AsSpan((int)(mftOffset + ((long)entry * 1024)), 1024).ToArray();
            var mutations = rng.Next(1, 12);
            for (var m = 0; m < mutations; m++)
            {
                switch (rng.Next(4))
                {
                    case 0: record[rng.Next(record.Length)] = (byte)rng.Next(256); break;
                    case 1: BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(rng.Next(record.Length - 4)), (uint)rng.Next()); break;
                    case 2: record.AsSpan(rng.Next(record.Length - 64), 64).Fill(0xFF); break;
                    default: BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(rng.Next(16, 64)), (ushort)rng.Next(65536)); break;
                }
            }

            var r = MftRecord.Parse(record, entry, includeRuns: true);
            _ = r.PrimaryName;
            parsed++;
        }

        Assert.Equal(30_000, parsed);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(30), $"30 000 damaged records took {watch.Elapsed}.");
    }
}
