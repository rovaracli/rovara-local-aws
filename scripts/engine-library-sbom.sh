#!/usr/bin/env bash
# One SBOM for the engine image's library scan: syft's SPDX SBOM of the image (OS packages and the Go front, which syft reads
# from the binary's build info) plus the Rust crates inside the engine binary, which syft cannot read but AWS lists, with
# versions, in the THIRD_PARTY_LICENSES it ships. Rovara Cloud's catalog-build reads the pair
#   sbom-<arch>/sbom.spdx.json   (this file)   and   scan-library-<arch>.json   (grype sbom:<this file> -o json)
# and requires every finding of the scan to name a package of this SBOM (by purl, or by name and version).
#
#   scripts/engine-library-sbom.sh <syft image sbom.spdx.json> <THIRD_PARTY_LICENSES> <out sbom.spdx.json>
#
# Each crate becomes an SPDX package with a pkg:cargo purl. Exits 1 when the image SBOM is not SPDX JSON with packages or
# when the notices list no crate (an empty list must never read as "no findings"). Needs jq; no network.
set -euo pipefail
[ $# -eq 3 ] || { echo "usage: $0 <image sbom.spdx.json> <THIRD_PARTY_LICENSES> <out sbom.spdx.json>" >&2; exit 2; }
IMG="$1"; NOTICES="$2"; OUT="$3"
command -v jq >/dev/null || { echo "engine-library-sbom: jq is required" >&2; exit 2; }
[ -s "$IMG" ] || { echo "engine-library-sbom: $IMG is missing or empty" >&2; exit 1; }
jq -e '(.spdxVersion // "" | startswith("SPDX-")) and (.packages | type == "array" and length > 0)' "$IMG" >/dev/null \
  || { echo "engine-library-sbom: $IMG is not an SPDX JSON document with packages" >&2; exit 1; }
[ -s "$NOTICES" ] || { echo "engine-library-sbom: $NOTICES is missing or empty" >&2; exit 1; }
crates="$(mktemp)"; trap 'rm -f "$crates"' EXIT
LC_ALL=C sed -n 's|^\*\* \([A-Za-z0-9_.+-]*\) \([0-9][0-9A-Za-z.+-]*\) (.*) - https://crates\.io/crates/.*$|\1 \2|p' "$NOTICES" | sort -u > "$crates"
[ -s "$crates" ] || { echo "engine-library-sbom: no crate found in $NOTICES" >&2; exit 1; }
jq -R -s --slurpfile img "$IMG" '
  ($img[0]) as $doc
  | (split("\n") | map(select(length > 0) | split(" ")) | to_entries
     | map({SPDXID: ("SPDXRef-Package-cargo-" + (.key | tostring) + "-" + (.value[0] | gsub("[^A-Za-z0-9.-]"; "-"))),
            name: .value[0], versionInfo: .value[1], downloadLocation: "NOASSERTION", filesAnalyzed: false,
            licenseConcluded: "NOASSERTION", licenseDeclared: "NOASSERTION", copyrightText: "NOASSERTION",
            supplier: "NOASSERTION",
            externalRefs: [{referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: ("pkg:cargo/" + .value[0] + "@" + .value[1])}]})) as $crates
  | $doc | .packages += $crates
  | .relationships = ((.relationships // []) + ($crates | map({spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: .SPDXID})))' "$crates" > "$OUT"
echo "engine-library-sbom: $(jq '.packages | length' "$OUT") packages ($(wc -l < "$crates" | tr -d ' ') crates added to the image SBOM) in $OUT"
