using XINSkan.Models;

namespace XINSkan.UnitTests.Models;

public class UlidTests
{
    [Fact]
    public void New_ulid_round_trips_and_keeps_millisecond_timestamp()
    {
        var t = new DateTimeOffset(2026, 11, 8, 17, 30, 15, 123, TimeSpan.Zero);
        var id = Ulid.NewUlid(t);

        Assert.Equal(26, id.Value.Length);
        Assert.Equal(t, id.Timestamp);
        Assert.Equal(id, Ulid.Parse(id.Value));
        Assert.Equal(id, Ulid.Parse(id.Value.ToLowerInvariant()));
    }

    [Fact]
    public void Ulids_sort_by_creation_time()
    {
        var a = Ulid.NewUlid(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var b = Ulid.NewUlid(new DateTimeOffset(2026, 1, 1, 0, 0, 0, 1, TimeSpan.Zero));
        Assert.True(a < b);
    }

    [Fact]
    public void Ulids_created_in_the_same_millisecond_are_distinct()
    {
        var ids = Enumerable.Range(0, 10_000).Select(_ => Ulid.NewUlid(Samples.T0)).ToHashSet();
        Assert.Equal(10_000, ids.Count);
    }

    [Theory]
    [InlineData((string?)null)]
    [InlineData("")]
    [InlineData("01ARZ3NDEKTSV4RRFFQ69G5FA")] // 25 chars
    [InlineData("01ARZ3NDEKTSV4RRFFQ69G5FAVX")] // 27 chars
    [InlineData("01ARZ3NDEKTSV4RRFFQ69G5FAI")] // I is not in the alphabet
    [InlineData("81ARZ3NDEKTSV4RRFFQ69G5FAV")] // timestamp overflow
    public void Invalid_ulids_are_rejected(string? value)
    {
        Assert.False(Ulid.TryParse(value, out _));
    }

    [Fact]
    public void Default_ulid_is_empty_and_has_no_value()
    {
        var empty = default(Ulid);
        Assert.True(empty.IsEmpty);
        Assert.Throws<InvalidOperationException>(() => empty.Value);
    }
}

public class Sha256HashTests
{
    [Fact]
    public void Hash_of_known_input_matches_reference()
    {
        var digest = System.Security.Cryptography.SHA256.HashData("abc"u8);
        var h = Sha256Hash.FromBytes(digest);
        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", h.Hex);
    }

    [Fact]
    public void Parse_normalises_to_lower_case()
    {
        var h = Sha256Hash.Parse("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", h.Hex);
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("zz7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    public void Invalid_hashes_are_rejected(string value)
    {
        Assert.False(Sha256Hash.TryParse(value, out _));
    }

    [Fact]
    public void Wrong_digest_length_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => Sha256Hash.FromBytes(new byte[31]));
    }
}

public class EvidenceTimestampTests
{
    [Fact]
    public void Non_utc_values_are_rejected()
    {
        Assert.Throws<ArgumentException>(() =>
            new EvidenceTimestamp(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.FromHours(5)), "$SI.Created", TimestampPrecision.HundredNanoseconds));
    }

    [Fact]
    public void Tolerance_combines_precision_and_uncertainty()
    {
        var dos = new EvidenceTimestamp(Samples.T0, "Zip.Entry.Modified", TimestampPrecision.TwoSeconds, "local", TimeSpan.FromHours(1));
        Assert.Equal(TimeSpan.FromHours(1) + TimeSpan.FromSeconds(2), dos.Tolerance);

        var ft = new EvidenceTimestamp(Samples.T0, "$SI.Created", TimestampPrecision.HundredNanoseconds);
        Assert.Equal(TimeSpan.FromTicks(1), ft.Tolerance);
    }

    [Fact]
    public void Negative_uncertainty_is_rejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new EvidenceTimestamp(Samples.T0, "x", TimestampPrecision.Seconds, uncertainty: TimeSpan.FromSeconds(-1)));
    }
}

public class EvidenceValidationTests
{
    private static readonly Ulid Inv = Ulid.NewUlid(Samples.T0);

    private static Evidence Valid() => Samples.Evidence(Inv, "file-hunter", Ulid.NewUlid(Samples.T0));

    [Fact]
    public void Well_formed_evidence_has_no_problems()
    {
        Assert.Empty(Valid().Validate());
    }

    [Fact]
    public void High_confidence_is_reserved_for_correlation()
    {
        var e = Valid() with { Confidence = Confidence.High };
        Assert.Contains(e.Validate(), p => p.Contains("only correlation", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(Confidence.Informational)]
    [InlineData(Confidence.Low)]
    [InlineData(Confidence.Medium)]
    [InlineData(Confidence.Inconclusive)]
    public void Single_record_confidences_up_to_medium_are_allowed(Confidence c)
    {
        Assert.Empty((Valid() with { Confidence = c }).Validate());
    }

    [Theory]
    [InlineData(EvidenceSourceKind.FileSystem)]
    [InlineData(EvidenceSourceKind.Mft)]
    [InlineData(EvidenceSourceKind.UsnJournal)]
    [InlineData(EvidenceSourceKind.RecycleBin)]
    [InlineData(EvidenceSourceKind.ZoneIdentifier)]
    public void File_presence_sources_cannot_claim_execution(EvidenceSourceKind kind)
    {
        var e = Valid() with
        {
            Source = new SourceRef(kind, "x", "test", "1"),
            EventType = EvidenceEventType.Executed,
        };
        Assert.Contains(e.Validate(), p => p.Contains("cannot prove execution", StringComparison.Ordinal));
    }

    [Fact]
    public void Prefetch_may_record_execution()
    {
        var e = Valid() with
        {
            Source = new SourceRef(EvidenceSourceKind.Prefetch, @"C:\Windows\Prefetch\X.EXE-1.pf", "test", "1"),
            EventType = EvidenceEventType.Executed,
        };
        Assert.Empty(e.Validate());
    }

    [Theory]
    [InlineData(CollectionStatus.Partial)]
    [InlineData(CollectionStatus.Skipped)]
    [InlineData(CollectionStatus.Failed)]
    public void Incomplete_collection_must_state_limitations(CollectionStatus status)
    {
        var e = Valid() with { CollectionStatus = status };
        Assert.Contains(e.Validate(), p => p.Contains("limitation", StringComparison.Ordinal));

        var withLimit = e with { Limitations = [new Limitation("TEST.PARTIAL", "Only part of the record was readable.")] };
        Assert.Empty(withLimit.Validate());
    }

    [Fact]
    public void Missing_rationale_locator_and_identity_are_reported()
    {
        var e = Valid() with { Rationale = " ", Locator = "", Target = new ObjectRef() };
        var problems = e.Validate();
        Assert.Contains(problems, p => p.Contains("Rationale", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.Contains("Locator", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.Contains("no path", StringComparison.Ordinal));
    }

    [Fact]
    public void Mft_reference_alone_identifies_an_object()
    {
        var e = Valid() with { Target = new ObjectRef { MftEntry = 1234, MftSequence = 5 } };
        Assert.Empty(e.Validate());
    }

    [Fact]
    public void Entry_without_sequence_does_not_count_as_mft_reference()
    {
        var e = Valid() with { Target = new ObjectRef { MftEntry = 1234 } };
        Assert.Contains(e.Validate(), p => p.Contains("no path", StringComparison.Ordinal));
    }

    [Fact]
    public void Limitation_requires_code_and_text()
    {
        Assert.Throws<ArgumentException>(() => new Limitation("", "text"));
        Assert.Throws<ArgumentException>(() => new Limitation("CODE", " "));
    }
}

public class SourceCoverageTests
{
    [Fact]
    public void Inverted_window_is_reported()
    {
        var c = new SourceCoverage
        {
            InvestigationId = Ulid.NewUlid(Samples.T0),
            ModuleId = "history",
            Source = EvidenceSourceKind.UsnJournal,
            Scope = "C:",
            Status = CollectionStatus.Collected,
            EarliestUtc = Samples.T0,
            LatestUtc = Samples.T0.AddDays(-1),
        };
        Assert.Contains(c.Validate(), p => p.Contains("after", StringComparison.Ordinal));
    }

    [Fact]
    public void Skipped_source_must_say_why()
    {
        var c = new SourceCoverage
        {
            InvestigationId = Ulid.NewUlid(Samples.T0),
            ModuleId = "history",
            Source = EvidenceSourceKind.UsnJournal,
            Scope = "D:",
            Status = CollectionStatus.Skipped,
        };
        Assert.NotEmpty(c.Validate());
        Assert.Empty((c with { Limitations = [new Limitation("FS.NOT_NTFS", "D: is exFAT; it has no USN journal.")] }).Validate());
    }
}
