using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using XINSkan.Signatures;

namespace XINSkan.DbTool;

/// <summary>
/// xinskan-db manifest &lt;dir&gt; --version V [--change "text"]...   recompute file hashes, add a changelog entry
/// xinskan-db check &lt;dir&gt;                                      load and validate like the application does
/// xinskan-db keygen &lt;private.pem&gt;                              new ECDSA P-256 key; prints the TrustedKeys line
/// xinskan-db sign &lt;dir&gt; --key &lt;private.pem&gt;                     write manifest.sig
/// xinskan-db verify &lt;dir&gt; --public &lt;base64 SPKI&gt;               check a signed bundle
/// </summary>
internal static class Program
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    private static readonly JsonSerializerOptions Camel = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    private static int Main(string[] args)
    {
        try
        {
            return args switch
            {
                ["manifest", var dir, .. var rest] => Manifest(dir, rest),
                ["check", var dir] => Check(dir),
                ["keygen", var file] => KeyGen(file),
                ["sign", var dir, "--key", var key] => Sign(dir, key),
                ["verify", var dir, "--public", var pub] => Verify(dir, pub),
                _ => Usage(),
            };
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or CryptographicException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Ошибка: " + ex.Message);
            return 1;
        }
    }

    private static int Usage()
    {
        Console.Error.WriteLine("xinskan-db manifest <dir> --version V [--change \"text\"]... | check <dir> | keygen <private.pem> | sign <dir> --key <private.pem> | verify <dir> --public <base64>");
        return 64;
    }

    private static int Manifest(string dir, string[] rest)
    {
        string? version = null;
        var changes = new List<string>();
        for (var i = 0; i + 1 < rest.Length; i += 2)
        {
            switch (rest[i])
            {
                case "--version":
                    version = rest[i + 1];
                    break;
                case "--change":
                    changes.Add(rest[i + 1]);
                    break;
            }
        }

        var path = Path.Combine(dir, DatabaseLoader.ManifestFile);
        var manifest = File.Exists(path) ? JsonNode.Parse(File.ReadAllText(path))!.AsObject() : new JsonObject { ["format"] = 1, ["changelog"] = new JsonArray() };
        var today = DateTime.UtcNow.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        if (version is not null)
        {
            if (manifest["version"]?.GetValue<string>() is { } old && DatabaseLoader.CompareVersions(version, old) <= 0)
            {
                throw new InvalidDataException($"Новая версия {version} должна быть больше {old}.");
            }

            manifest["version"] = version;
            manifest["created"] = today;
            ((JsonArray)manifest["changelog"]!).Add(new JsonObject { ["version"] = version, ["date"] = today, ["changes"] = new JsonArray([.. changes.Select(c => (JsonNode)c)]) });
        }

        var files = new JsonObject();
        foreach (var name in SignatureDatabase.DataFiles)
        {
            files[name] = SignatureDatabase.Sha256(File.ReadAllBytes(Path.Combine(dir, name)));
        }

        manifest["files"] = files;
        File.WriteAllText(path, manifest.ToJsonString(Indented) + "\n");
        Console.WriteLine($"manifest.json: версия {manifest["version"]}, файлов {files.Count}.");
        return Check(dir);
    }

    private static int Check(string dir)
    {
        var db = SignatureDatabase.Load(File.ReadAllBytes(Path.Combine(dir, DatabaseLoader.ManifestFile)), n => File.Exists(Path.Combine(dir, n)) ? File.ReadAllBytes(Path.Combine(dir, n)) : null, dir, null);
        Console.WriteLine($"База {db.Manifest.Version}: записей {db.Clients.Count} (проверенных {db.Clients.Count(c => c.Status == "verified")}), написаний {db.Aliases.Count}, хешей {db.Hashes.Count}, функций {db.Features.Count} (проверенных {db.Features.Count(f => f.Status == "verified")}, сильных {db.Features.Count(f => f.Strength == "strong")}), официальных клиентов Minecraft {db.MojangClients.Count}.");
        foreach (var p in db.Problems)
        {
            Console.WriteLine("  отклонено: " + p);
        }

        return db.Problems.Count == 0 ? 0 : 2;
    }

    private static int KeyGen(string file)
    {
        if (File.Exists(file))
        {
            throw new IOException($"{file} уже существует: ключ не перезаписывается.");
        }

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(file, key.ExportPkcs8PrivateKeyPem());
        var spki = key.ExportSubjectPublicKeyInfo();
        Console.WriteLine($"Закрытый ключ: {file} — храните его вне репозитория и вне компьютеров, которые проверяются.");
        Console.WriteLine("Строка для TrustedKeys.Default (src/XINSkan.Signatures/Loader.cs):");
        Console.WriteLine($"    [\"{DatabaseLoader.KeyId(spki)}\"] = \"{Convert.ToBase64String(spki)}\",");
        return 0;
    }

    private static int Sign(string dir, string keyFile)
    {
        using var key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText(keyFile));
        var manifest = File.ReadAllBytes(Path.Combine(dir, DatabaseLoader.ManifestFile));
        _ = SignatureDatabase.Load(manifest, n => File.Exists(Path.Combine(dir, n)) ? File.ReadAllBytes(Path.Combine(dir, n)) : null, dir, null);
        var keyId = DatabaseLoader.KeyId(key.ExportSubjectPublicKeyInfo());
        var signature = new ManifestSignature { KeyId = keyId, Signature = Convert.ToBase64String(key.SignData(manifest, HashAlgorithmName.SHA256)) };
        File.WriteAllText(Path.Combine(dir, DatabaseLoader.SignatureFile), JsonSerializer.Serialize(signature, Camel));
        Console.WriteLine($"manifest.sig записан, ключ {keyId}.");
        return 0;
    }

    private static int Verify(string dir, string publicKey)
    {
        using var probe = ECDsa.Create();
        probe.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
        var keyId = DatabaseLoader.KeyId(Convert.FromBase64String(publicKey));
        var id = DatabaseLoader.Verify(
            File.ReadAllBytes(Path.Combine(dir, DatabaseLoader.ManifestFile)),
            File.ReadAllBytes(Path.Combine(dir, DatabaseLoader.SignatureFile)),
            new Dictionary<string, string> { [keyId] = publicKey });
        Console.WriteLine($"Подпись верна (ключ {id}).");
        return Check(dir);
    }
}
