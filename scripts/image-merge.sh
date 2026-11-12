#!/usr/bin/env bash
# Combines single-platform OCI layouts (linux/arm64, linux/amd64, or both) into one OCI layout whose only image
# is an OCI index of exactly those platforms (one is fine), and writes the digest file and the catalog sources-file entry. Pure file work
# (bash, jq, a sha256 tool): no container engine, so it can be tested anywhere.
#
#   scripts/image-merge.sh [--amd64 <layout dir>] [--arm64 <layout dir>] --out <dir> --registry-ref <host/path>
#                          [--catalog-id local-aws@r1]
#
# Writes in <dir>:
#   oci/                 the merged OCI layout (oci-layout, index.json, blobs/sha256/...)
#   index.digest         sha256:<hex> of the index (one line)
#   platforms.json       {"linux/arm64": "sha256:<child manifest>"} and/or "linux/amd64", only the platforms given
#   sources-entry.json   {"schemaVersion":1,"sources":{"<catalog id>":"<registry-ref>@sha256:<hex>"}}: the file
#                        scripts/catalog-build.ts reads (merge the entry into the full sources file)
#   repack-entry.json    {"schemaVersion":1,"entries":{"<catalog id>":"<registry-ref>@sha256:<hex>"}}: the same
#                        reference in the shape scripts/catalog-repack.ts reads
# At least one layout is required. A layout that does not hold exactly one image of its platform refuses the merge;
# so does an existing <dir>/oci.
set -euo pipefail

CATALOG_ID="local-aws@r1"
AMD64=""; ARM64=""; OUT=""; REF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --amd64) AMD64="$2"; shift 2 ;;
    --arm64) ARM64="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --registry-ref) REF="$2"; shift 2 ;;
    --catalog-id) CATALOG_ID="$2"; shift 2 ;;
    *) echo "image-merge: unknown argument $1" >&2; exit 2 ;;
  esac
done
for v in OUT REF; do [ -n "${!v}" ] || { echo "image-merge: --$(echo "$v" | tr 'A-Z' 'a-z' | sed 's/^ref$/registry-ref/') is required" >&2; exit 2; }; done
[ -n "$AMD64$ARM64" ] || { echo "image-merge: give --arm64 and/or --amd64" >&2; exit 2; }
command -v jq >/dev/null || { echo "image-merge: jq is required" >&2; exit 2; }
# Same shape catalog-build's SourceRefSchema accepts: lower-case host/path, no tag, no scheme.
[[ "$REF" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?/[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$ ]] \
  || { echo "image-merge: --registry-ref must be host/path with no tag and no digest" >&2; exit 2; }
[[ "$CATALOG_ID" =~ ^[a-z][a-z0-9-]*@[A-Za-z0-9._-]+$ ]] || { echo "image-merge: bad catalog id" >&2; exit 2; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
blob() { echo "$1/blobs/sha256/${2#sha256:}"; }

# image_manifest <layout> <os/arch>: prints the digest of the layout's single image manifest, descending through
# at most one index level and ignoring attestation manifests (unknown/unknown). Refuses anything but exactly one image
# whose config says the wanted platform.
image_manifest() {
  local dir="$1" want="$2" top digests d mt
  [ -f "$dir/index.json" ] && [ -f "$dir/oci-layout" ] || { echo "image-merge: $dir is not an OCI layout" >&2; return 1; }
  top=$(jq -r '.manifests[] | select((.platform.os // "") != "unknown") | .digest + " " + .mediaType' "$dir/index.json")
  digests=""
  while read -r d mt; do
    [ -n "$d" ] || continue
    case "$mt" in
      application/vnd.oci.image.index.v1+json|application/vnd.docker.distribution.manifest.list.v2+json)
        digests="$digests $(jq -r '.manifests[] | select((.platform.os // "") != "unknown") | .digest' "$(blob "$dir" "$d")")" ;;
      *) digests="$digests $d" ;;
    esac
  done <<<"$top"
  set -- $digests
  [ $# -eq 1 ] || { echo "image-merge: $dir must hold exactly one image, found $#" >&2; return 1; }
  local cfg os arch
  cfg=$(jq -r '.config.digest' "$(blob "$dir" "$1")")
  os=$(jq -r '.os' "$(blob "$dir" "$cfg")"); arch=$(jq -r '.architecture' "$(blob "$dir" "$cfg")")
  [ "$os/$arch" = "$want" ] || { echo "image-merge: $dir holds $os/$arch, expected $want" >&2; return 1; }
  echo "$1"
}

A=""; B=""
[ -z "$AMD64" ] || A=$(image_manifest "$AMD64" linux/amd64)
[ -z "$ARM64" ] || B=$(image_manifest "$ARM64" linux/arm64)
[ ! -e "$OUT/oci" ] || { echo "image-merge: $OUT/oci already exists" >&2; exit 1; }
mkdir -p "$OUT/oci/blobs/sha256"
# Blobs are content-addressed: copying both layouts' blobs into one directory cannot clash.
for dir in "$AMD64" "$ARM64"; do
  [ -n "$dir" ] || continue
  for f in "$dir"/blobs/sha256/*; do
    [ -e "$OUT/oci/blobs/sha256/$(basename "$f")" ] || cp "$f" "$OUT/oci/blobs/sha256/"
  done
done
printf '{"imageLayoutVersion":"1.0.0"}' > "$OUT/oci/oci-layout"

descriptor() {  # layout manifest-digest os arch
  local dir="$1" d="$2" cfg variant
  cfg=$(jq -r '.config.digest' "$(blob "$dir" "$d")")
  variant=$(jq -r '.variant // empty' "$(blob "$dir" "$cfg")")
  jq -cn --arg d "$d" --argjson s "$(wc -c < "$(blob "$dir" "$d")" | tr -d ' ')" --arg os "$3" --arg arch "$4" --arg variant "$variant" \
    --arg mt "$(jq -r '.mediaType // "application/vnd.oci.image.manifest.v1+json"' "$(blob "$dir" "$d")")" \
    '{mediaType:$mt, digest:$d, size:$s, platform:({architecture:$arch, os:$os} + (if $variant != "" then {variant:$variant} else {} end))}'
}
# Fixed key order and fixed platform order (amd64 then arm64): the same inputs always give the same index digest.
DESCS=()
[ -z "$AMD64" ] || DESCS+=("$(descriptor "$AMD64" "$A" linux amd64)")
[ -z "$ARM64" ] || DESCS+=("$(descriptor "$ARM64" "$B" linux arm64)")
printf '%s\n' "${DESCS[@]}" | jq -cS -s '{schemaVersion:2, mediaType:"application/vnd.oci.image.index.v1+json", manifests:.}' > "$OUT/.index.tmp"
printf '%s' "$(cat "$OUT/.index.tmp")" > "$OUT/.index.tmp"   # no trailing newline
HEX=$(sha256_of "$OUT/.index.tmp")
SIZE=$(wc -c < "$OUT/.index.tmp" | tr -d ' ')
mv "$OUT/.index.tmp" "$OUT/oci/blobs/sha256/$HEX"
jq -cn --arg d "sha256:$HEX" --argjson s "$SIZE" \
  '{schemaVersion:2, manifests:[{mediaType:"application/vnd.oci.image.index.v1+json", digest:$d, size:$s}]}' > "$OUT/oci/index.json"

echo "sha256:$HEX" > "$OUT/index.digest"
jq -n --arg a "$A" --arg b "$B" '(if $a == "" then {} else {"linux/amd64":$a} end) + (if $b == "" then {} else {"linux/arm64":$b} end)' > "$OUT/platforms.json"
jq -n --arg id "$CATALOG_ID" --arg ref "$REF@sha256:$HEX" '{schemaVersion:1, sources:{($id):$ref}}' > "$OUT/sources-entry.json"
jq -n --arg id "$CATALOG_ID" --arg ref "$REF@sha256:$HEX" '{schemaVersion:1, entries:{($id):$ref}}' > "$OUT/repack-entry.json"
echo "merged index sha256:$HEX (amd64 ${A:-none}, arm64 ${B:-none})"
