using System.Globalization;
using System.Text.Json;
using XINSkan.Models;

namespace XINSkan.Storage;

/// <summary>JSON shapes of the structured columns (OtherTimestamps, Limitations, Attributes).</summary>
internal static class Rows
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    internal sealed record TimestampDto(long Ticks, string Field, string Precision, string? Zone, long UncertaintyTicks);

    internal sealed record LimitationDto(string Code, string Text);

    public static string Timestamps(IReadOnlyList<EvidenceTimestamp> ts) =>
        JsonSerializer.Serialize(ts.Select(t => new TimestampDto(t.ValueUtc.UtcTicks, t.Field, t.Precision.ToString(), t.SourceTimeZone, t.Uncertainty.Ticks)).ToList(), Json);

    public static IReadOnlyList<EvidenceTimestamp> Timestamps(string json) =>
        (JsonSerializer.Deserialize<List<TimestampDto>>(json, Json) ?? [])
        .Select(d => new EvidenceTimestamp(new DateTimeOffset(d.Ticks, TimeSpan.Zero), d.Field, Enum.Parse<TimestampPrecision>(d.Precision), d.Zone, TimeSpan.FromTicks(d.UncertaintyTicks)))
        .ToList();

    public static string Limitations(IReadOnlyList<Limitation> l) =>
        JsonSerializer.Serialize(l.Select(x => new LimitationDto(x.Code, x.Text)).ToList(), Json);

    public static IReadOnlyList<Limitation> Limitations(string json) =>
        (JsonSerializer.Deserialize<List<LimitationDto>>(json, Json) ?? []).Select(d => new Limitation(d.Code, d.Text)).ToList();

    public static string Attributes(IReadOnlyDictionary<string, string> a) =>
        JsonSerializer.Serialize(new SortedDictionary<string, string>(a.ToDictionary(k => k.Key, v => v.Value), StringComparer.Ordinal), Json);

    public static IReadOnlyDictionary<string, string> Attributes(string json) =>
        JsonSerializer.Deserialize<Dictionary<string, string>>(json, Json) ?? [];

    public static string Strings(IEnumerable<string> list) => JsonSerializer.Serialize(list.ToList(), Json);

    public static IReadOnlyList<string> Strings(string json) => JsonSerializer.Deserialize<List<string>>(json, Json) ?? [];

    public static string? Serial(ulong? serial) => serial?.ToString("X16", CultureInfo.InvariantCulture);

    public static ulong? Serial(string? hex) => hex is null ? null : ulong.Parse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    public static string Utc(DateTimeOffset t) => t.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    public static DateTimeOffset FromTicks(long ticks) => new(ticks, TimeSpan.Zero);
}
