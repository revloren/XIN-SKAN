using System.Text;
using XINSkan.Ntfs;
using XINSkan.NtfsTests.Support;

namespace XINSkan.NtfsTests;

/// <summary>
/// The player image (TestData/make-player-image.sh) has a known history: live files, deletions, a deleted
/// folder, a reused folder record, a rename, a hard link, an alternate data stream. Every expectation here
/// was also confirmed with ntfsundelete and ntfsinfo from ntfs-3g, an independent implementation.
/// </summary>
public sealed class MftPlayerImageTests
{
    private const string Mc = @"C:\Users\player\AppData\Roaming\.minecraft";
    private static PlayerVolume V => PlayerVolume.Instance.Value;

    [Fact]
    public void Mft_is_located_from_its_own_record_and_read_completely()
    {
        Assert.Empty(V.Reader.Problems);
        Assert.Equal(4096, V.Reader.Boot.BytesPerCluster);
        Assert.Equal(1024, V.Reader.Boot.BytesPerRecord);

        // 1500 filler files (one later deleted) force $MFT past its initial allocation.
        Assert.True(V.Reader.RecordCount > 1500);
        Assert.Equal(V.Reader.RecordCount, V.Records.Count);
        Assert.Equal(0, V.Reader.Statistics.UnreadableBytes);
        Assert.All(V.Records.Where(r => r.State == MftRecordState.Parsed), r => Assert.True(r.FixupOk, $"record {r.Entry}"));
        Assert.DoesNotContain(V.Records, r => r.State == MftRecordState.Invalid);
    }

    [Fact]
    public void Exactly_the_deleted_objects_are_found_with_their_last_names_and_paths()
    {
        var deleted = V.Records.Where(r => r.State == MftRecordState.Parsed && !r.InUse && r.PrimaryName is not null && !r.IsExtension)
            .Select(r => (Path: V.Index.Resolve(r.PrimaryName!.Parent, r.PrimaryName.Name), r.IsDirectory))
            .OrderBy(x => x.Path.Path, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(
            new[]
            {
                (@"C:\?\impact.jar", PathQuality.ReusedAncestor, false),
                (@"C:\Filler\f1.txt", PathQuality.Complete, false),
                (Mc + @"\config\wurst", PathQuality.Complete, true),
                (Mc + @"\config\wurst\settings.json", PathQuality.DeletedAncestor, false),
                (Mc + @"\mods\wurst-client.jar", PathQuality.Complete, false),
                (@"C:\Users\player\Downloads\injector.exe", PathQuality.Complete, false),
                (@"C:\Users\player\Temp\Reused", PathQuality.Complete, true),
                (@"C:\Users\player\Temp\Reused\old.jar", PathQuality.DeletedAncestor, false),
                (@"C:\Windows\System32\update.dll", PathQuality.Complete, false),
            },
            deleted.Select(d => (d.Path.Path, d.Path.Quality, d.IsDirectory)));
    }

    [Fact]
    public void A_freed_record_carries_the_next_sequence_number()
    {
        var wurst = DeletedNamed("wurst-client.jar");

        // Created with sequence 1, freed → 2. References made while the file existed carry 1.
        Assert.Equal(2, wurst.Sequence);
        Assert.Equal(ReferenceState.Deleted, V.Index.Check(new FileReference(wurst.Entry, 1)));
        Assert.Equal(ReferenceState.Deleted, V.Index.Check(new FileReference(wurst.Entry, 2)));
        Assert.Equal(ReferenceState.Reused, V.Index.Check(new FileReference(wurst.Entry, 7)));
    }

    [Fact]
    public void A_deleted_file_keeps_its_resident_download_origin()
    {
        var wurst = DeletedNamed("wurst-client.jar");
        var zone = Assert.Single(wurst.Data, d => d.Name == "Zone.Identifier");
        Assert.False(zone.NonResident);
        Assert.Contains("HostUrl=https://example.org/wurst-client.jar", Encoding.ASCII.GetString(zone.ResidentValue!), StringComparison.Ordinal);

        var content = wurst.MainData!;
        Assert.Equal("wurst\n", Encoding.ASCII.GetString(content.ResidentValue!));
    }

    [Fact]
    public void A_deleted_file_with_non_resident_content_reports_its_size()
    {
        var injector = DeletedNamed("injector.exe");
        var data = injector.MainData!;
        Assert.True(data.NonResident);
        Assert.Equal(5000, data.Size);
        Assert.Null(data.ResidentValue);
    }

    [Fact]
    public void A_folder_record_reused_by_another_object_is_not_mistaken_for_the_old_folder()
    {
        var impact = DeletedNamed("impact.jar");
        var parent = impact.PrimaryName!.Parent;

        // The Impact folder record now belongs to new.txt: same entry, live, different object.
        var owner = V.Records[(int)parent.Entry];
        Assert.True(owner.InUse);
        Assert.Equal("new.txt", owner.PrimaryName!.Name);
        Assert.Equal(ReferenceState.Reused, V.Index.Check(parent));
        Assert.Equal(PathQuality.ReusedAncestor, V.Index.Resolve(parent, impact.PrimaryName.Name).Quality);
    }

    [Fact]
    public void Rename_leaves_only_the_new_name_in_the_mft()
    {
        var homework = V.Live(@"C:\Users\player\Desktop\homework.txt");
        Assert.Single(homework.FileNames);

        // The old name client.jar is not in the MFT at all; only the USN journal can show the rename.
        Assert.DoesNotContain(V.Records, r => r.FileNames.Any(f => f.Name == "client.jar"));
    }

    [Fact]
    public void A_hard_link_is_one_record_with_a_name_in_each_folder()
    {
        var shared = V.Live(@"C:\Users\player\Downloads\shared.jar");
        Assert.Equal(2, shared.LinkCount);
        var paths = shared.FileNames.Select(f => V.Index.Resolve(f.Parent, f.Name).Path).Order(StringComparer.Ordinal).ToList();
        Assert.Equal(new[] { @"C:\Users\player\Desktop\shared-link.jar", @"C:\Users\player\Downloads\shared.jar" }, paths);
    }

    [Fact]
    public void Non_ascii_and_long_names_are_read_exactly()
    {
        Assert.Equal("чит-клиент.jar", V.Live(@"C:\Users\player\Downloads\чит-клиент.jar").PrimaryName!.Name);
        var longName = new string('a', 200) + ".jar";
        Assert.Equal(longName, V.Live(@"C:\Users\player\Downloads\" + longName).PrimaryName!.Name);
    }

    [Fact]
    public void Standard_information_and_file_name_times_are_both_read()
    {
        var old = V.Live(Mc + @"\mods\old-times.jar");
        var si = old.StandardInformation!.Times;
        var fn = old.PrimaryName!.Times;
        var expected = new DateTimeOffset(2015, 1, 1, 0, 0, 0, TimeSpan.Zero);

        Assert.Equal(expected, NtfsTime.ToUtc(si.Created));
        Assert.NotNull(NtfsTime.ToUtc(si.Modified));

        // $FILE_NAME keeps the time NTFS set when the name was created; whether ntfs-3g mirrors a changed
        // creation time into it depends on later operations, so only the order is fixed: never earlier.
        Assert.True(NtfsTime.ToUtc(fn.Created) >= expected);
        Assert.True(NtfsTime.HasZeroFraction(si.Created));
    }

    [Fact]
    public void Every_live_object_resolves_to_a_complete_path()
    {
        var live = V.Records.Where(r => r.State == MftRecordState.Parsed && r.InUse && !r.IsExtension && r.PrimaryName is not null && r.Entry != MftIndex.RootEntry);
        Assert.All(live, r => Assert.Equal(PathQuality.Complete, V.Index.Resolve(r.PrimaryName!.Parent, r.PrimaryName.Name).Quality));
        Assert.Equal(1499, V.Records.Count(r => r.InUse && r.PrimaryName is not null && V.PathOf(r).StartsWith(@"C:\Filler\f", StringComparison.Ordinal)));
    }

    private static MftRecord DeletedNamed(string name) =>
        V.Records.Single(r => r.State == MftRecordState.Parsed && !r.InUse && r.PrimaryName?.Name == name);
}
