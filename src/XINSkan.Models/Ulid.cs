using System.Security.Cryptography;

namespace XINSkan.Models;

/// <summary>
/// Universally unique, lexicographically sortable identifier (26 characters, Crockford Base32):
/// 48 bits of Unix milliseconds followed by 80 random bits. Used for evidence and investigation IDs so that
/// identifiers sort by creation time without a central counter.
/// </summary>
public readonly record struct Ulid : IComparable<Ulid>
{
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private readonly string _value;

    private Ulid(string value) => _value = value;

    public static Ulid NewUlid(DateTimeOffset timestamp)
    {
        var ms = timestamp.ToUnixTimeMilliseconds();
        if (ms < 0 || ms > 0xFFFF_FFFF_FFFFL)
        {
            throw new ArgumentOutOfRangeException(nameof(timestamp), "ULID timestamps cover 1970 to 10889.");
        }

        Span<byte> random = stackalloc byte[10];
        RandomNumberGenerator.Fill(random);

        Span<char> chars = stackalloc char[26];
        for (var i = 9; i >= 0; i--)
        {
            chars[i] = Alphabet[(int)(ms & 31)];
            ms >>= 5;
        }

        // 80 random bits -> 16 characters
        var bits = new System.Numerics.BigInteger(random, isUnsigned: true, isBigEndian: true);
        for (var i = 25; i >= 10; i--)
        {
            chars[i] = Alphabet[(int)(bits & 31)];
            bits >>= 5;
        }

        return new Ulid(new string(chars));
    }

    public static Ulid Parse(string value)
    {
        if (!TryParse(value, out var ulid))
        {
            throw new FormatException($"'{value}' is not a valid ULID.");
        }

        return ulid;
    }

    public static bool TryParse(string? value, out Ulid ulid)
    {
        ulid = default;
        if (value is null || value.Length != 26)
        {
            return false;
        }

        var upper = value.ToUpperInvariant();
        foreach (var c in upper)
        {
            if (!Alphabet.Contains(c, StringComparison.Ordinal))
            {
                return false;
            }
        }

        // The first character can only encode the top 3 bits of a 48-bit timestamp.
        if (upper[0] > '7')
        {
            return false;
        }

        ulid = new Ulid(upper);
        return true;
    }

    public DateTimeOffset Timestamp
    {
        get
        {
            long ms = 0;
            for (var i = 0; i < 10; i++)
            {
                ms = (ms << 5) | (long)Alphabet.IndexOf(Value[i], StringComparison.Ordinal);
            }

            return DateTimeOffset.FromUnixTimeMilliseconds(ms);
        }
    }

    public string Value => _value ?? throw new InvalidOperationException("Default ULID has no value.");

    public bool IsEmpty => _value is null;

    public int CompareTo(Ulid other) => string.CompareOrdinal(_value, other._value);

    public static bool operator <(Ulid left, Ulid right) => left.CompareTo(right) < 0;

    public static bool operator >(Ulid left, Ulid right) => left.CompareTo(right) > 0;

    public static bool operator <=(Ulid left, Ulid right) => left.CompareTo(right) <= 0;

    public static bool operator >=(Ulid left, Ulid right) => left.CompareTo(right) >= 0;

    public override string ToString() => _value ?? string.Empty;
}
