namespace XINSkan.Models;

/// <summary>A SHA-256 digest stored as 64 lowercase hex characters. Validated on construction.</summary>
public readonly record struct Sha256Hash
{
    private readonly string _hex;

    private Sha256Hash(string hex) => _hex = hex;

    public static Sha256Hash FromBytes(ReadOnlySpan<byte> digest)
    {
        if (digest.Length != 32)
        {
            throw new ArgumentException($"A SHA-256 digest is 32 bytes, got {digest.Length}.", nameof(digest));
        }

        return new Sha256Hash(Convert.ToHexStringLower(digest));
    }

    public static Sha256Hash Parse(string hex)
    {
        if (!TryParse(hex, out var hash))
        {
            throw new FormatException("A SHA-256 hash is 64 hexadecimal characters.");
        }

        return hash;
    }

    public static bool TryParse(string? hex, out Sha256Hash hash)
    {
        hash = default;
        if (hex is null || hex.Length != 64)
        {
            return false;
        }

        foreach (var c in hex)
        {
            if (!Uri.IsHexDigit(c))
            {
                return false;
            }
        }

        hash = new Sha256Hash(hex.ToLowerInvariant());
        return true;
    }

    public string Hex => _hex ?? throw new InvalidOperationException("Default hash has no value.");

    public override string ToString() => _hex ?? string.Empty;
}
