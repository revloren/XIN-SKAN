#!/usr/bin/env bash
# Builds player.img.gz: a small NTFS volume with a known history, for XINSkan.NtfsTests.
# Linux only (mkntfs + ntfs-3g FUSE). Run as root from this folder. Output is deterministic in content,
# not in timestamps; tests assert relations between times, never absolute values.
set -euo pipefail
work=$(mktemp -d)
img="$work/player.img"
truncate -s 32M "$img"
mkntfs -F -f -q -L PLAYER -c 4096 -s 512 "$img" >/dev/null 2>&1
mkdir "$work/m"
ntfs-3g -o streams_interface=xattr "$img" "$work/m"
m="$work/m"
P="$m/Users/player"
MC="$P/AppData/Roaming/.minecraft"
mkdir -p "$MC/mods" "$MC/versions/1.20.1" "$MC/logs" "$P/Downloads" "$P/Desktop" "$P/Games/Impact" "$m/Users/Public" "$m/Windows/Temp"

# Many files first, so that $MFT grows beyond its initial allocation (and nothing created later reuses
# the records freed at the end).
mkdir -p "$m/Filler"
for i in $(seq 1 1500); do echo "$i" > "$m/Filler/f$i.txt"; done

echo "sodium" > "$MC/mods/sodium-fabric-0.5.3.jar"
echo "kept" > "$MC/mods/kept-mod.jar"
echo "log" > "$MC/logs/latest.log"
echo "{}" > "$MC/versions/1.20.1/1.20.1.json"
echo "notes" > "$P/Downloads/notes.txt"

# Renamed to hide the extension (same record, new name).
echo "jar" > "$P/Desktop/client.jar"
mv "$P/Desktop/client.jar" "$P/Desktop/homework.txt"

# Hard link: one record, two names in different folders.
echo "shared" > "$P/Downloads/shared.jar"
ln "$P/Downloads/shared.jar" "$P/Desktop/shared-link.jar"

# Non-ASCII and long names.
echo "x" > "$P/Downloads/чит-клиент.jar"
long=$(printf 'a%.0s' $(seq 1 200))
echo "x" > "$P/Downloads/$long.jar"

# Times set back to 2015 in $STANDARD_INFORMATION. ntfs-3g may or may not mirror the creation time into
# $FILE_NAME (it depends on later operations), so tests rely only on SI here. Timestomping as Windows'
# SetFileTime does it is tested on a real NTFS volume in CI.
echo "old" > "$MC/mods/old-times.jar"
python3 - "$MC/mods/old-times.jar" <<'PY'
import os, struct, sys
ft = (1420070400 + 11644473600) * 10_000_000   # 2015-01-01T00:00:00Z as FILETIME
os.setxattr(sys.argv[1], 'system.ntfs_crtime', struct.pack('<Q', ft))
os.utime(sys.argv[1], (1420070400, 1420070400))
PY

# Objects that will be deleted. They are created after everything else and deleted together at the end,
# because ntfs-3g gives a new file the lowest free record: a later creation would reuse them.
mkdir -p "$P/Temp/Reused"
echo "old" > "$P/Temp/Reused/old.jar"
echo "wurst" > "$MC/mods/wurst-client.jar"
python3 -c "import os,sys; os.setxattr(sys.argv[1], 'user.Zone.Identifier', b'[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.org/wurst-client.jar\r\n')" "$MC/mods/wurst-client.jar"
head -c 5000 /dev/zero | tr '\0' 'M' > "$P/Downloads/injector.exe"
echo "impact" > "$P/Games/Impact/impact.jar"

rm "$MC/mods/wurst-client.jar"           # deleted, with a resident Zone.Identifier stream
rm "$P/Downloads/injector.exe"           # deleted, non-resident content
rm -r "$P/Games/Impact"                  # folder and file deleted: the file keeps a reference to the deleted folder
rm -r "$P/Temp/Reused"

# Exactly one new file: it takes the lowest free record, which is the deleted Impact folder (created by
# mkdir at the start). impact.jar now points to a record that belongs to another object.
echo "new" > "$P/Temp/new.txt"

sync
fusermount -u "$m" 2>/dev/null || umount "$m"
gzip -9 -n -c "$img" > player.img.gz
rm -rf "$work"
ls -la player.img.gz
