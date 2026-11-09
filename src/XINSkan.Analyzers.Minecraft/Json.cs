using System.Text.Json;

namespace XINSkan.Analyzers.Minecraft;

/// <summary>Bounded JSON reading for launcher files: no exception escapes, size and depth are capped.</summary>
internal static class Json
{
    public const int MaxBytes = 16 * 1024 * 1024;

    private static readonly JsonDocumentOptions Options = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
        MaxDepth = 64,
    };

    public static JsonDocument? Parse(byte[]? bytes)
    {
        if (bytes is null || bytes.Length == 0)
        {
            return null;
        }

        try
        {
            return JsonDocument.Parse(bytes, Options);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static JsonElement? Get(this JsonElement e, params string[] path)
    {
        var current = e;
        foreach (var p in path)
        {
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(p, out current))
            {
                return null;
            }
        }

        return current;
    }

    public static string? Str(this JsonElement e, params string[] path) =>
        e.Get(path) is { ValueKind: JsonValueKind.String } v ? v.GetString() : null;

    public static long? Num(this JsonElement e, params string[] path) =>
        e.Get(path) is { ValueKind: JsonValueKind.Number } v && v.TryGetInt64(out var n) ? n : null;

    public static IEnumerable<JsonElement> Items(this JsonElement e, params string[] path) =>
        e.Get(path) is { ValueKind: JsonValueKind.Array } a ? a.EnumerateArray() : [];

    public static IEnumerable<JsonProperty> Props(this JsonElement e, params string[] path) =>
        e.Get(path) is { ValueKind: JsonValueKind.Object } o ? o.EnumerateObject() : [];
}
