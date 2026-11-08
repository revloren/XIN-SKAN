namespace XINSkan.Models;

/// <summary>
/// A point in time as reported by an artifact. Always stored in UTC; the original zone of the source, its
/// resolution and any known uncertainty travel with it so that correlation never compares a 2-second DOS time
/// to a 100 ns FILETIME as if they were equally precise.
/// </summary>
public sealed record EvidenceTimestamp
{
    /// <param name="valueUtc">The moment in UTC (offset must be zero).</param>
    /// <param name="field">Which field of the source this is, for example "$SI.Created" or "Prefetch.LastRun[0]".</param>
    /// <param name="precision">Resolution of the source field.</param>
    /// <param name="sourceTimeZone">
    /// Zone the source recorded the value in, when the source is not UTC-based (for example "local" for ZIP entry times);
    /// null when the source stores UTC.
    /// </param>
    /// <param name="uncertainty">Known +/- error beyond the precision (for example an unreliable local clock).</param>
    public EvidenceTimestamp(
        DateTimeOffset valueUtc,
        string field,
        TimestampPrecision precision,
        string? sourceTimeZone = null,
        TimeSpan? uncertainty = null)
    {
        if (valueUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Evidence timestamps are stored in UTC.", nameof(valueUtc));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(field);
        if (uncertainty is { } u && u < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(uncertainty), "Uncertainty cannot be negative.");
        }

        ValueUtc = valueUtc;
        Field = field;
        Precision = precision;
        SourceTimeZone = sourceTimeZone;
        Uncertainty = uncertainty ?? TimeSpan.Zero;
    }

    public DateTimeOffset ValueUtc { get; }

    public string Field { get; }

    public TimestampPrecision Precision { get; }

    public string? SourceTimeZone { get; }

    public TimeSpan Uncertainty { get; }

    /// <summary>Half-width of the interval in which the real moment lies: resolution plus stated uncertainty.</summary>
    public TimeSpan Tolerance => Uncertainty + Precision switch
    {
        TimestampPrecision.HundredNanoseconds => TimeSpan.FromTicks(1),
        TimestampPrecision.Milliseconds => TimeSpan.FromMilliseconds(1),
        TimestampPrecision.Seconds => TimeSpan.FromSeconds(1),
        TimestampPrecision.TwoSeconds => TimeSpan.FromSeconds(2),
        TimestampPrecision.Day => TimeSpan.FromDays(1),
        _ => TimeSpan.Zero,
    };
}
