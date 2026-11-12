#!/usr/bin/env bash
# The Rust crates inside AWS Emulator are compiled into one binary that syft cannot read (no audit data in it), but AWS
# ships their names and versions in THIRD_PARTY_LICENSES, one line each:
#     ** adler2 2.0.1 (0BSD OR MIT OR Apache-2.0) - https://crates.io/crates/adler2/2.0.1
# This turns that list into a CycloneDX SBOM (purl pkg:cargo/<name>@<version>) so grype can scan the crates, as it scans
# the Java dependency list of the fork's image. Pure bash/jq/awk, no network.
#
#   scripts/engine-crates-sbom.sh <THIRD_PARTY_LICENSES> <out.cdx.json>
#
# Exits 1 when the file lists no crate (an empty list must never read as "no findings").
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 <THIRD_PARTY_LICENSES> <out.cdx.json>" >&2; exit 2; }
IN="$1"; OUT="$2"
command -v jq >/dev/null || { echo "engine-crates-sbom: jq is required" >&2; exit 2; }
[ -s "$IN" ] || { echo "engine-crates-sbom: $IN is missing or empty" >&2; exit 1; }
LC_ALL=C sed -n 's|^\*\* \([A-Za-z0-9_.+-]*\) \([0-9][0-9A-Za-z.+-]*\) (.*) - https://crates\.io/crates/.*$|\1 \2|p' "$IN" | sort -u \
  | jq -R -s '
      split("\n") | map(select(length > 0) | split(" ") | {type: "library", name: .[0], version: .[1], purl: ("pkg:cargo/" + .[0] + "@" + .[1])})
      | {bomFormat: "CycloneDX", specVersion: "1.5", version: 1,
         metadata: {component: {type: "application", name: "aws-emulator", description: "crates listed in the engine package THIRD_PARTY_LICENSES"}},
         components: .}' > "$OUT"
n="$(jq '.components | length' "$OUT")"
[ "$n" -gt 0 ] || { echo "engine-crates-sbom: no crate found in $IN" >&2; exit 1; }
echo "engine-crates-sbom: $n crates written to $OUT"
