using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace XINSkan.Security;

/// <summary>One line of the audit log.</summary>
public sealed record AuditEntry(long Sequence, DateTimeOffset Utc, string Action, string Target, string Access, string Result, string? Detail, string PreviousHash, string Hash);

/// <summary>Outcome of checking an audit log.</summary>
public sealed record AuditVerification(bool Intact, long Entries, long? FirstBrokenSequence, string? Problem);

/// <summary>
/// Append-only JSON Lines log of every source XIN SKAN opens: what, with which access, and what happened.
/// Each line carries the SHA-256 of the previous line, so a removed, reordered or edited line breaks the chain.
/// </summary>
/// <remarks>
/// Without an external signature or anchor the chain detects accidental damage and naive edits, not a forger
/// who recomputes every hash. docs/SECURITY.md states this limit.
/// </remarks>
public sealed class AuditLogger : IDisposable
{
    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    private readonly Stream _stream;
    private readonly TimeProvider _time;
    private readonly Lock _gate = new();
    private long _sequence;
    private string _previous = GenesisHash;

    public AuditLogger(Stream appendOnlyStream, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(appendOnlyStream);
        if (!appendOnlyStream.CanWrite)
        {
            throw new ArgumentException("The audit stream must be writable.", nameof(appendOnlyStream));
        }

        _stream = appendOnlyStream;
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    /// <param name="action">For example "open", "read", "skip".</param>
    /// <param name="target">The object: a path, a volume, a registry key.</param>
    /// <param name="access">The access requested, for example "GENERIC_READ, share RWD".</param>
    /// <param name="result">"ok", "denied", "not-found", ...</param>
    public AuditEntry Record(string action, string target, string access, string result, string? detail = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        ArgumentException.ThrowIfNullOrWhiteSpace(access);
        ArgumentException.ThrowIfNullOrWhiteSpace(result);

        lock (_gate)
        {
            var seq = ++_sequence;
            var utc = _time.GetUtcNow();
            var hash = ComputeHash(seq, utc, action, target, access, result, detail, _previous);
            var entry = new AuditEntry(seq, utc, action, target, access, result, detail, _previous, hash);

            var line = Serialize(entry);
            _stream.Write(line);
            _stream.WriteByte((byte)'\n');
            _stream.Flush();
            _previous = hash;
            return entry;
        }
    }

    public void Dispose() => _stream.Dispose();

    public static AuditVerification Verify(Stream log)
    {
        ArgumentNullException.ThrowIfNull(log);
        using var reader = new StreamReader(log, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        var expectedPrevious = GenesisHash;
        long expectedSeq = 1;
        long count = 0;
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (line.Length == 0)
            {
                continue;
            }

            AuditEntry e;
            try
            {
                e = Parse(line);
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
            {
                return new AuditVerification(false, count, expectedSeq, $"Line {count + 1} is not a valid audit entry: {ex.Message}");
            }

            if (e.Sequence != expectedSeq)
            {
                return new AuditVerification(false, count, expectedSeq, $"Expected entry {expectedSeq}, found {e.Sequence}: an entry is missing or out of order.");
            }

            if (!string.Equals(e.PreviousHash, expectedPrevious, StringComparison.Ordinal))
            {
                return new AuditVerification(false, count, e.Sequence, $"Entry {e.Sequence} does not continue the chain.");
            }

            var recomputed = ComputeHash(e.Sequence, e.Utc, e.Action, e.Target, e.Access, e.Result, e.Detail, e.PreviousHash);
            if (!string.Equals(recomputed, e.Hash, StringComparison.Ordinal))
            {
                return new AuditVerification(false, count, e.Sequence, $"Entry {e.Sequence} was modified after it was written.");
            }

            expectedPrevious = e.Hash;
            expectedSeq++;
            count++;
        }

        return new AuditVerification(true, count, null, null);
    }

    private static string ComputeHash(long seq, DateTimeOffset utc, string action, string target, string access, string result, string? detail, string previous)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            WriteFields(w, seq, utc, action, target, access, result, detail, previous);
            w.WriteEndObject();
        }

        return Convert.ToHexStringLower(SHA256.HashData(buffer.ToArray()));
    }

    private static void WriteFields(Utf8JsonWriter w, long seq, DateTimeOffset utc, string action, string target, string access, string result, string? detail, string previous)
    {
        w.WriteStartObject();
        w.WriteNumber("seq", seq);
        w.WriteString("utc", utc.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        w.WriteString("action", action);
        w.WriteString("target", target);
        w.WriteString("access", access);
        w.WriteString("result", result);
        if (detail is null)
        {
            w.WriteNull("detail");
        }
        else
        {
            w.WriteString("detail", detail);
        }

        w.WriteString("prev", previous);
    }

    private static byte[] Serialize(AuditEntry e)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            WriteFields(w, e.Sequence, e.Utc, e.Action, e.Target, e.Access, e.Result, e.Detail, e.PreviousHash);
            w.WriteString("hash", e.Hash);
            w.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private static AuditEntry Parse(string line)
    {
        using var doc = JsonDocument.Parse(line);
        var r = doc.RootElement;
        var detail = r.GetProperty("detail");
        return new AuditEntry(
            r.GetProperty("seq").GetInt64(),
            DateTimeOffset.Parse(r.GetProperty("utc").GetString()!, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal),
            r.GetProperty("action").GetString()!,
            r.GetProperty("target").GetString()!,
            r.GetProperty("access").GetString()!,
            r.GetProperty("result").GetString()!,
            detail.ValueKind == JsonValueKind.Null ? null : detail.GetString(),
            r.GetProperty("prev").GetString()!,
            r.GetProperty("hash").GetString()!);
    }
}
