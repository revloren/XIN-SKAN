namespace XINSkan.Models;

/// <summary>
/// A stated limit on what an evidence record or a source can show. Codes are stable identifiers
/// (for example "USN.RETENTION") so reports can group them; text is written for the reader.
/// </summary>
public sealed record Limitation
{
    public Limitation(string code, string text)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        ArgumentException.ThrowIfNullOrWhiteSpace(text);
        Code = code;
        Text = text;
    }

    public string Code { get; }

    public string Text { get; }
}
