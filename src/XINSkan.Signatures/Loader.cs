using System.Security.Cryptography;
using System.Text.Json;

namespace XINSkan.Signatures;

/// <summary>
/// Public keys whose signatures make an update bundle trusted: key id → SubjectPublicKeyInfo (base64, ECDSA P-256).
/// Empty until the owner adds the key that signs updates (tools/XINSkan.DbTool keygen prints the line to add):
/// without a trusted key every update is refused and the database built into the application is used.
/// </summary>
public static class TrustedKeys
{
    public static readonly IReadOnlyDictionary<string, string> Default = new Dictionary<string, string>(StringComparer.Ordinal);
}

/// <summary>Result of looking for a database: the one used, and why an update was not.</summary>
public sealed record LoadResult(SignatureDatabase Database, IReadOnlyList<string> Notes);

public static class DatabaseLoader
{
    public const string ManifestFile = "manifest.json";
    public const string SignatureFile = "manifest.sig";

    /// <summary>The database built into the application.</summary>
    public static SignatureDatabase Embedded()
    {
        var asm = typeof(DatabaseLoader).Assembly;
        byte[]? Resource(string name)
        {
            using var s = asm.GetManifestResourceStream("database/" + name);
            if (s is null)
            {
                return null;
            }

            using var ms = new MemoryStream();
            s.CopyTo(ms);
            return ms.ToArray();
        }

        return SignatureDatabase.Load(Resource(ManifestFile) ?? throw new InvalidDataException("В сборке нет встроенной базы."), Resource, "embedded", null);
    }

    /// <summary>
    /// Uses a signed update from <paramref name="updateFolder"/> when its signature is from a trusted key, every file
    /// matches the manifest and its version is newer than the built-in one; otherwise the built-in database, with
    /// the reason in <see cref="LoadResult.Notes"/>. A rejected update never falls back to "partly trusted".
    /// </summary>
    public static LoadResult Load(string? updateFolder, Func<string, byte[]?> readFile, IReadOnlyDictionary<string, string> trustedKeys)
    {
        ArgumentNullException.ThrowIfNull(readFile);
        ArgumentNullException.ThrowIfNull(trustedKeys);
        var embedded = Embedded();
        var notes = new List<string>();
        if (updateFolder is null)
        {
            return new LoadResult(embedded, notes);
        }

        string Path(string name) => updateFolder.Contains('\\', StringComparison.Ordinal) ? updateFolder.TrimEnd('\\') + "\\" + name : System.IO.Path.Combine(updateFolder, name);
        var manifest = readFile(Path(ManifestFile));
        if (manifest is null)
        {
            return new LoadResult(embedded, notes);
        }

        try
        {
            var signature = readFile(Path(SignatureFile)) ?? throw new InvalidDataException("Обновление без подписи (manifest.sig).");
            var keyId = Verify(manifest, signature, trustedKeys);
            var update = SignatureDatabase.Load(manifest, name => readFile(Path(name)), updateFolder, keyId);
            if (CompareVersions(update.Manifest.Version, embedded.Manifest.Version) <= 0)
            {
                notes.Add($"Обновление {update.Manifest.Version} не новее встроенной базы {embedded.Manifest.Version}: используется встроенная.");
                return new LoadResult(embedded, notes);
            }

            notes.Add($"Используется подписанное обновление {update.Manifest.Version} (ключ {keyId}).");
            return new LoadResult(update, notes);
        }
        catch (InvalidDataException ex)
        {
            notes.Add($"Обновление базы в {updateFolder} отклонено: {ex.Message} Используется встроенная база {embedded.Manifest.Version}.");
            return new LoadResult(embedded, notes);
        }
    }

    /// <returns>The id of the key that signed the manifest.</returns>
    /// <exception cref="InvalidDataException">No valid signature from a trusted key.</exception>
    public static string Verify(byte[] manifest, byte[] signatureFile, IReadOnlyDictionary<string, string> trustedKeys)
    {
        ArgumentNullException.ThrowIfNull(trustedKeys);
        ManifestSignature? sig;
        try
        {
            sig = JsonSerializer.Deserialize<ManifestSignature>(signatureFile, SignatureDatabase.Json);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("manifest.sig не разобран: " + ex.Message, ex);
        }

        if (sig is null || !trustedKeys.TryGetValue(sig.KeyId, out var publicKey))
        {
            throw new InvalidDataException(trustedKeys.Count == 0
                ? "В приложении не задан ни один доверенный ключ для обновлений базы."
                : $"Подпись ключом «{sig?.KeyId}», которого нет среди доверенных.");
        }

        using var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
            if (ecdsa.KeySize != 256 || !ecdsa.VerifyData(manifest, Convert.FromBase64String(sig.Signature), HashAlgorithmName.SHA256))
            {
                throw new InvalidDataException("Подпись manifest.json неверна: файл изменён или подписан другим ключом.");
            }
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException("Подпись или ключ не в base64.", ex);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidDataException("Подпись не проверена: " + ex.Message, ex);
        }

        return sig.KeyId;
    }

    /// <summary>Key id: the first 16 hex digits of SHA-256 of the SubjectPublicKeyInfo.</summary>
    public static string KeyId(byte[] subjectPublicKeyInfo) => Convert.ToHexStringLower(SHA256.HashData(subjectPublicKeyInfo))[..16];

    /// <summary>Compares dotted versions ("2026.11.10.1") number by number.</summary>
    public static int CompareVersions(string a, string b)
    {
        var x = a.Split('.');
        var y = b.Split('.');
        for (var i = 0; i < Math.Max(x.Length, y.Length); i++)
        {
            var p = i < x.Length && long.TryParse(x[i], out var xv) ? xv : 0;
            var q = i < y.Length && long.TryParse(y[i], out var yv) ? yv : 0;
            if (p != q)
            {
                return p.CompareTo(q);
            }
        }

        return 0;
    }
}
