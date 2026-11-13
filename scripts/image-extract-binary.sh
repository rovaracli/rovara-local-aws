#!/usr/bin/env bash
# Takes the native binary (and the shared libraries beside it) out of a single-platform OCI layout, without a
# container engine: it reads the image manifest, unpacks its layers in order into a scratch root with tar, and copies
# /usr/local/bin/rovara-local-aws and /usr/lib/rovara/ out. This is the binary that ships in the image.
#
#   scripts/image-extract-binary.sh <oci layout dir> <out dir>
#
# Writes <out dir>/rovara-local-aws and <out dir>/lib/. Run it with LD_LIBRARY_PATH=<out dir>/lib. Needs jq and tar.
#
#   scripts/image-extract-binary.sh --engine <oci layout dir> <out dir>
#
# For the engine image (image/Containerfile.engine): writes <out dir>/rovara-aws-front and <out dir>/aws-emulator (the
# engine binary, from /opt/aws-emulator/bin) and <out dir>/THIRD_PARTY_LICENSES. Both are linked against glibc only.
# Refuses an image with more than one image manifest, an unknown layer type, or no binary in it.
set -euo pipefail
MODE=fork
if [ "${1:-}" = "--engine" ]; then MODE=engine; shift; fi
[ $# -eq 2 ] || { echo "usage: $0 [--engine] <oci layout dir> <out dir>" >&2; exit 2; }
LAYOUT="$1"; OUT="$2"
command -v jq >/dev/null || { echo "image-extract-binary: jq is required" >&2; exit 2; }
if [ ! -f "$LAYOUT/index.json" ] || [ ! -f "$LAYOUT/oci-layout" ]; then echo "image-extract-binary: $LAYOUT is not an OCI layout" >&2; exit 1; fi
blob() { echo "$LAYOUT/blobs/sha256/${1#sha256:}"; }

# the one image manifest (descending through at most one index level, ignoring attestation manifests)
digests=""
while read -r d mt; do
  [ -n "$d" ] || continue
  case "$mt" in
    application/vnd.oci.image.index.v1+json|application/vnd.docker.distribution.manifest.list.v2+json)
      digests="$digests $(jq -r '.manifests[] | select((.platform.os // "") != "unknown") | .digest' "$(blob "$d")")" ;;
    *) digests="$digests $d" ;;
  esac
done < <(jq -r '.manifests[] | select((.platform.os // "") != "unknown") | .digest + " " + .mediaType' "$LAYOUT/index.json")
read -r -a found <<<"$digests"
[ "${#found[@]}" -eq 1 ] || { echo "image-extract-binary: expected exactly one image manifest in $LAYOUT, found ${#found[@]}" >&2; exit 1; }
MANIFEST="${found[0]}"

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/image-root.XXXXXX")"
# image files are often read-only (0555 binary, 0555 directories): make them removable first
trap 'chmod -R u+rwX "$ROOT" 2>/dev/null; rm -rf "$ROOT"' EXIT
while read -r d mt; do
  case "$mt" in
    *tar+gzip|*tar.gzip) tar -xzf "$(blob "$d")" -C "$ROOT" ;;
    *tar) tar -xf "$(blob "$d")" -C "$ROOT" ;;
    *) echo "image-extract-binary: unsupported layer type $mt" >&2; exit 1 ;;
  esac
done < <(jq -r '.layers[] | .digest + " " + .mediaType' "$(blob "$MANIFEST")")

if [ "$MODE" = engine ]; then
  FRONT="$ROOT/usr/local/bin/rovara-aws-front"; ENG="$ROOT/opt/aws-emulator/bin/aws-emulator"
  [ -f "$FRONT" ] || { echo "image-extract-binary: no /usr/local/bin/rovara-aws-front in the image" >&2; exit 1; }
  [ -f "$ENG" ] || { echo "image-extract-binary: no /opt/aws-emulator/bin/aws-emulator in the image" >&2; exit 1; }
  mkdir -p "$OUT"
  cp "$FRONT" "$OUT/rovara-aws-front"; cp "$ENG" "$OUT/aws-emulator"; chmod 0755 "$OUT/rovara-aws-front" "$OUT/aws-emulator"
  cp "$ROOT/opt/aws-emulator/THIRD_PARTY_LICENSES" "$OUT/THIRD_PARTY_LICENSES" 2>/dev/null || true
  echo "extracted $OUT/rovara-aws-front ($(wc -c < "$OUT/rovara-aws-front" | tr -d ' ') bytes) and $OUT/aws-emulator ($(wc -c < "$OUT/aws-emulator" | tr -d ' ') bytes)"
  exit 0
fi
BIN="$ROOT/usr/local/bin/rovara-local-aws"
[ -f "$BIN" ] || { echo "image-extract-binary: no /usr/local/bin/rovara-local-aws in the image" >&2; exit 1; }
mkdir -p "$OUT/lib"
cp "$BIN" "$OUT/rovara-local-aws"; chmod 0755 "$OUT/rovara-local-aws"
if [ -d "$ROOT/usr/lib/rovara" ]; then cp -R "$ROOT/usr/lib/rovara/." "$OUT/lib/"; fi
echo "extracted $OUT/rovara-local-aws ($(wc -c < "$OUT/rovara-local-aws" | tr -d ' ') bytes) and $(find "$OUT/lib" -type f | wc -l | tr -d ' ') shared libraries"
