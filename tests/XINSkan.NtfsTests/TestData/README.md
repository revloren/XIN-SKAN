# NTFS test images

`player.img.gz` — a 32 MB NTFS volume with a known history, built on Linux by `make-player-image.sh`
(mkntfs + ntfs-3g; run as root). Contents are ours; nothing third-party. Timestamps differ on every
rebuild, so tests check relations between times, never absolute values.

What it contains (all confirmed with `ntfsundelete -s` and `ntfsinfo` from ntfs-3g, an independent
implementation):

| Object | State |
| --- | --- |
| `Users\player\AppData\Roaming\.minecraft\mods\wurst-client.jar` | deleted; resident content and a resident `Zone.Identifier` stream with `HostUrl` |
| `Users\player\Downloads\injector.exe` | deleted; 5000 bytes, non-resident |
| `Users\player\Games\Impact` and `impact.jar` inside | both deleted; the folder record was then reused by `Users\player\Temp\new.txt` (created after a remount, which resets ntfs-3g's allocation hint), so `impact.jar` points to a record that belongs to another object |
| `Users\player\Temp\Reused` and `old.jar` inside | both deleted; the folder record is free, so the path is still known |
| `Users\player\AppData\Roaming\.minecraft\config\wurst` and `settings.json` inside | both deleted |
| `Windows\System32\update.dll`, `Filler\f1.txt` | deleted outside the checked area |
| `Users\player\Desktop\homework.txt` | renamed from `client.jar` (only the new name is in the MFT) |
| `Users\player\Downloads\shared.jar` = `Desktop\shared-link.jar` | one record, two names |
| `Users\player\Downloads\чит-клиент.jar`, a 200-character name | live |
| `...\mods\old-times.jar` | creation time set to 2015 |
| `Filler\f1.txt` … `f1500.txt` | push `$MFT` past its initial allocation |

Third-party reference samples (`tdungan`, `xw`, `NIST/DFR-16`) are not stored here. CI checks them out from
the MFT library repository at the reviewed commit and sets `XINSKAN_NTFS_SAMPLES`.
