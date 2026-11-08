#!/usr/bin/env bash
# Clones the reviewed library revisions into ./.src (not committed).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .src
while read -r name sha; do
  [ -d ".src/$name" ] || git clone -q "https://github.com/EricZimmerman/$name.git" ".src/$name"
  git -C ".src/$name" checkout -q "$sha"
done <<'LIST'
MFT 3eecafae50ac8935b239cf3ded690b11af5020f4
Prefetch 841212266356a9121a1c34ee538cbce2bb2b9cf3
JumpList c125c8e008e62255afb3bd176e00efa171d5c1b4
Lnk dab1c8ab9c1c18d2cf89a4938ab95794d17d3a44
OleCf bd49022e75aa82cdd7c65eb3333d7ffb92d0865e
ExtensionBlocks 6dd29c0318c15d16ac86755dba021f35913461d1
GuidMapping e2c93615a491ca43197b36960a436b559062cb52
LIST
