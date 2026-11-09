using XINSkan.Ntfs;
using XINSkan.NtfsTests.Support;

namespace XINSkan.NtfsTests;

/// <summary>
/// Real $MFT files from other systems (the MFT library's test corpus at the reviewed commit, see
/// docs/LIBRARY_REVIEW.md). Expected values are those the library's own tests assert, which were in turn
/// checked there against independent decoders — so this is a cross-check of two implementations.
/// </summary>
public sealed class ReferenceSampleTests
{
    private sealed record Parsed(List<MftRecord> Records, MftIndex Index)
    {
        public string Path(ulong entry)
        {
            var n = Records[(int)entry].PrimaryName!;
            return Index.Resolve(n.Parent, n.Name).Path;
        }
    }

    private static Parsed Load(params string[] parts)
    {
        using var s = File.OpenRead(SampleFactAttribute.File(parts));
        var records = MftReader.ReadExtracted(s).Select(r => MftRecord.Parse(r.Bytes.Span, r.Entry)).ToList();
        var index = new MftIndex(records.Count, ".");
        records.ForEach(index.Add);
        return new Parsed(records, index);
    }

    [SampleFact]
    public void Windows_xp_system_tdungan_counts_paths_times_and_attribute_list()
    {
        var p = Load("tdungan", "$MFT");
        var parsed = p.Records.Where(r => r.State == MftRecordState.Parsed).ToList();
        Assert.Equal(42861, parsed.Count(r => r.InUse));
        Assert.Equal(9459, parsed.Count(r => !r.InUse));
        Assert.Equal(0, p.Records.Count(r => r.State != MftRecordState.Parsed));
        Assert.DoesNotContain(parsed, r => r.InUse && r.Problems.Count > 0);

        Assert.Equal(@".\Documents and Settings\RSydow\Local Settings\Temp\vmmsi.log", p.Path(329));
        Assert.Equal(@".\WINDOWS\$NtServicePackUninstall$\reg00099", p.Path(40000));

        var root = p.Records[5];
        Assert.Equal(5, root.Sequence);
        Assert.Equal(new DateTimeOffset(2010, 11, 10, 17, 38, 1, 62, TimeSpan.Zero).AddTicks(5000), NtfsTime.ToUtc(root.StandardInformation!.Times.Created));

        var log = p.Records[329];
        Assert.Equal(1040u, log.StandardInformation!.SecurityId);
        Assert.Equal(new[] { "329-2:0", "329-2:0", "1473-2:0", "2120-2:559" }, log.AttributeList!.Select(a => $"{a.Record.Entry}-{a.Record.Sequence}:{a.StartVcn}"));
    }

    [SampleFact]
    public void Windows_xp_system_xw_counts_paths_and_a_deleted_record_with_remnant_attributes()
    {
        var p = Load("xw", "$MFT");
        var parsed = p.Records.Where(r => r.State == MftRecordState.Parsed).ToList();
        Assert.Equal(467, parsed.Count(r => r.InUse));
        Assert.Equal(159, parsed.Count(r => !r.InUse));
        Assert.Equal(2, p.Records.Count(r => r.State == MftRecordState.Invalid));

        Assert.Equal(@".\Documents and Settings\EdgarAllanPoe\Local Settings\Temp\Temporary Internet Files\Content.IE5\0P2NGHQ3\home_navi[1].htm", p.Path(100));
        Assert.Equal(new FileReference(485, 2), p.Records[432].BaseRecord);

        // Record 179 is free; its used size ends before $DATA, but the attribute chain is intact.
        var r179 = p.Records[179];
        Assert.False(r179.InUse);
        Assert.True(r179.HasRemnantAttributes);
        Assert.Equal(2, r179.FileNames.Count);
        Assert.Equal(34304, r179.MainData!.Size);
        var withRuns = MftRecord.Parse(File.ReadAllBytes(SampleFactAttribute.File("xw", "$MFT")).AsSpan(179 * 1024, 1024), 179, includeRuns: true);
        Assert.Equal(3614, Assert.Single(withRuns.MainData!.Runs!).Lcn);
    }

    [SampleFact]
    public void Nist_dfr16_deep_folders_and_never_used_records()
    {
        var p = Load("NIST", "DFR-16", "$MFT");
        Assert.Equal(117, p.Records.Count(r => r.State == MftRecordState.Parsed && r.InUse));
        Assert.Equal(37, p.Records.Count(r => r.State == MftRecordState.Empty));
        Assert.Equal(@".\Y05\Y05L01\Y05L02\Y05L03", p.Path(77));
        Assert.Equal(@".\$Extend\$RmMetadata\$Txf", p.Path(30));
    }
}
