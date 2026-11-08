#!/usr/bin/env bash
# Builds the libraries from the pinned sources and runs the corruption tests.
set -euo pipefail
cd "$(dirname "$0")"
./clone-pinned.sh
dotnet build Fuzz/Fuzz.csproj -c Release -nologo -v q
dotnet build Perf/Perf.csproj -c Release -nologo -v q
out=${1:-reports}; mkdir -p "$out"
seeds=${SEEDS:-"1 2 3"}
export DOTNET_GCHeapHardLimit=0x80000000
F=Fuzz/bin/Release/net10.0/Fuzz.dll
for s in $seeds; do dotnet $F prefetch   .src/Prefetch/Prefetch.Test/TestFiles 300 "$out/prefetch-seed$s.txt" $s; done
for s in $seeds; do dotnet $F autodest   .src/JumpList/JumpList.Test/TestFiles 300 "$out/autodest-seed$s.txt" $s; done
for s in $seeds; do dotnet $F customdest .src/JumpList/JumpList.Test/TestFiles 300 "$out/customdest-seed$s.txt" $s; done
for s in $seeds; do dotnet $F lnk        .src/Lnk/Lnk.Test/TestFiles 150 "$out/lnk-seed$s.txt" $s; done
for s in $seeds; do dotnet $F mftrecord  .src/MFT/MFT.Test/TestFiles 150 "$out/mftrecord-seed$s.txt" $s; done
for s in $seeds; do dotnet $F mftfile    .src/MFT/MFT.Test/TestFiles 120 "$out/mftfile-seed$s.txt" $s; done
for s in $seeds; do dotnet $F usn        .src/MFT/MFT.Test/TestFiles/DFIRArtifactMuseum/J 300 "$out/usn-seed$s.txt" $s; done
dotnet Perf/bin/Release/net10.0/Perf.dll ".src/MFT/MFT.Test/TestFiles/tdungan/\$MFT" | tee "$out/mft-perf.txt"
