"""Prints the official client JAR of every Minecraft version, as Mojang's own version files state it.

Each version file is checked against the SHA-1 the version manifest gives for it, so every line below is what
piston-meta.mojang.com serves. Output (tab-separated), one line per version:
  MOJANG  id  type  releaseTime  versionJsonSha1  clientSha1  clientSize  clientUrl
and a summary line:
  MANIFEST  url  sha1-of-manifest  versions  with-client
The maintainer builds database/mojang.json from this output; nothing here is invented or derived.
"""
import concurrent.futures
import hashlib
import json
import sys
import urllib.request

MANIFEST = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"


def get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read()


def one(v):
    data = get(v["url"])
    sha = hashlib.sha1(data).hexdigest()
    if sha != v["sha1"]:
        return f"FAILED\t{v['id']}\tversion file SHA-1 {sha}, manifest says {v['sha1']}"
    client = json.loads(data).get("downloads", {}).get("client")
    if not client:
        return f"NOCLIENT\t{v['id']}"
    return "\t".join(["MOJANG", v["id"], v["type"], v["releaseTime"], v["sha1"], client["sha1"], str(client["size"]), client["url"]])


def main():
    raw = get(MANIFEST)
    manifest = json.loads(raw)
    versions = manifest["versions"]
    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        lines = list(pool.map(one, versions))
    for line in lines:
        print(line)
    ok = sum(1 for l in lines if l.startswith("MOJANG"))
    print(f"MANIFEST\t{MANIFEST}\t{hashlib.sha1(raw).hexdigest()}\t{len(versions)}\t{ok}")
    return 0 if ok > 0 and not any(l.startswith("FAILED") for l in lines) else 1


if __name__ == "__main__":
    sys.exit(main())
