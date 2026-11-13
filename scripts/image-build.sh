#!/usr/bin/env bash
# Builds the Rovara local AWS catalog image (linux/arm64 by default; linux/amd64 on request) and writes, under --out:
#   layout-amd64/ layout-arm64/   one OCI layout per platform
#   oci/                          the merged OCI layout: one index of the platforms built (arm64, amd64 or both)
#   index.digest                  sha256:<hex> of the index
#   platforms.json                child manifest digest per platform
#   sources-entry.json            the entry for the sources file scripts/catalog-build.ts reads
#   repack-entry.json             the same reference in the shape scripts/catalog-repack.ts reads
#   catalog-entry.json            image/catalog-entry.json with the digest filled in (still unpinned until
#                                 catalog-build adds the SBOM and scan)
#   sbom-amd64/ sbom-arm64/       java-dependencies.cdx.json: the Java libraries compiled into the binary (CycloneDX), for the scan
#   build-info.json               revision, version, builder and base digests, push commands
#
# RUNS ONLY ON LINUX (a CI runner or a staging builder) with Docker Buildx, jq and git. It refuses to start on
# any other system: the native Linux binary cannot be built on macOS, and no container engine runs on a
# developer Mac. Never run it there.
#
#   scripts/image-build.sh --registry-ref <host/path> [--out image/out] [--version r1]
#                          [--platform linux/arm64|linux/amd64]   build that one platform only (a matrix job), then --merge-only
#                          [--platform both]                      build and merge both; with no --platform: arm64 only, merged
#                          [--merge-only]                         merge the layout-arm64 and/or layout-amd64 already in --out
#                          [--native-xmx 5g]                      heap cap of the native-image builder JVM (build arg NATIVE_IMAGE_XMX)
#                          [--allow-emulation] [--allow-dirty]
#                          [--engine]                             build image/Containerfile.engine (AWS Emulator behind the Rovara front)
#                                                                 instead of the Java fork's native image: linux/arm64 only, catalog id
#                                                                 local-aws@r1 (--catalog-id to change), the entry image/catalog-entry.engine.json,
#                                                                 no Java dependency list (the workflow builds the generic library
#                                                                 SBOM and scan pair instead). The output layout is the same. Without --engine
#                                                                 nothing below changes.
#
# --registry-ref is where the index will be pushed by the operator (for example
# <account>.dkr.ecr.<region>.amazonaws.com/rovara-catalog/<env>/svc/local-aws). The script does NOT push: it
# prints the push commands, which on staging go through ~/.local/share/rovara-tools/staging-aws.sh with the owner's OK.
#
# The first image is linux/arm64 only (Rovara's workers are Graviton); linux/amd64 is built only when asked. A one-platform
# index is a normal result. Each platform is built natively on its own host. Building the other architecture needs QEMU, which makes the
# GraalVM native build many times slower and is refused unless --allow-emulation is given.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

OUT="$ROOT/image/out"; VERSION="r1"; REF=""; ONLY=""; MERGE_ONLY=0; EMULATION=0; DIRTY=0; XMX="${NATIVE_IMAGE_XMX:-5g}"
ENGINE=0; CATALOG_ID=""
while [ $# -gt 0 ]; do
  case "$1" in
    --registry-ref) REF="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --platform) ONLY="$2"; shift 2 ;;
    --merge-only) MERGE_ONLY=1; shift ;;
    --native-xmx) XMX="$2"; shift 2 ;;
    --allow-emulation) EMULATION=1; shift ;;
    --allow-dirty) DIRTY=1; shift ;;
    --engine) ENGINE=1; shift ;;
    --catalog-id) CATALOG_ID="$2"; shift 2 ;;
    *) echo "image-build: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -n "$REF" ] || { echo "image-build: --registry-ref <host/path> is required" >&2; exit 2; }
if [ "$ENGINE" = 1 ]; then
  CONTAINERFILE="image/Containerfile.engine"; ENTRY_FILE="image/catalog-entry.engine.json"; CATALOG_ID="${CATALOG_ID:-local-aws@r1}"
else
  CONTAINERFILE="image/Containerfile"; ENTRY_FILE="image/catalog-entry.json"; CATALOG_ID="${CATALOG_ID:-local-aws@r1}"
fi
BOTH=0
if [ "$ENGINE" = 1 ]; then
  # the engine package AWS publishes for this image is the arm64 one (Rovara's workers are Graviton)
  case "$ONLY" in ""|linux/arm64) ;; *) echo "image-build: --engine builds linux/arm64 only" >&2; exit 2 ;; esac
fi
case "$ONLY" in ""|linux/amd64|linux/arm64) ;; both) BOTH=1; ONLY="" ;; *) echo "image-build: --platform is linux/arm64, linux/amd64 or both" >&2; exit 2 ;; esac

[ "$(uname -s)" = "Linux" ] || { echo "image-build: Linux only (CI runner or staging builder). Refusing to run on $(uname -s)." >&2; exit 2; }
for tool in jq git; do command -v "$tool" >/dev/null || { echo "image-build: $tool is required" >&2; exit 2; }; done
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"

REVISION="$(git rev-parse HEAD)"
if [ "$DIRTY" = 0 ] && [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "image-build: the working tree has uncommitted changes; the image records the commit, so commit first (or --allow-dirty)" >&2; exit 2
fi
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"; export SOURCE_DATE_EPOCH
SOURCE_URL="https://github.com/PrepLabsAI/rovara-local-aws"

host_platform() { case "$(uname -m)" in x86_64) echo linux/amd64 ;; aarch64|arm64) echo linux/arm64 ;; *) echo unknown ;; esac; }

build_one() {  # platform
  local platform="$1" arch="${1#linux/}" dir tar
  if [ "$platform" != "$(host_platform)" ] && [ "$EMULATION" = 0 ]; then
    echo "image-build: $platform is not this host's platform ($(host_platform)); build it on a native host, or pass --allow-emulation (very slow)" >&2; exit 2
  fi
  command -v docker >/dev/null || { echo "image-build: docker with buildx is required" >&2; exit 2; }
  docker buildx version >/dev/null 2>&1 || { echo "image-build: docker buildx is required" >&2; exit 2; }
  # The OCI exporter needs a builder with the docker-container driver (docker buildx create --use).
  if docker buildx inspect 2>/dev/null | grep -qE '^Driver:[[:space:]]+docker$'; then
    echo "image-build: the current buildx builder uses the docker driver, which cannot export an OCI layout; run: docker buildx create --use" >&2; exit 2
  fi
  dir="$OUT/layout-$arch"; tar="$OUT/oci-$arch.tar"
  rm -rf "$dir" "$tar"; mkdir -p "$dir"
  local xmx_arg=(--build-arg "NATIVE_IMAGE_XMX=$XMX")
  [ "$ENGINE" = 1 ] && xmx_arg=()   # the engine image has no native-image build
  docker buildx build --file "$CONTAINERFILE" --platform "$platform" \
    --provenance=false --sbom=false \
    --build-arg "VERSION=$VERSION" --build-arg "REVISION=$REVISION" --build-arg "SOURCE_URL=$SOURCE_URL" \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" ${xmx_arg[@]+"${xmx_arg[@]}"} \
    --output "type=oci,dest=$tar,rewrite-timestamp=true" .
  tar -xf "$tar" -C "$dir"
  rm -f "$tar"
  # The engine image has no Java libraries inside a binary: its Go and Rust contents are read by the image scan and by
  # scripts/engine-library-sbom.sh (the workflow), so there is no dependency list to export here.
  [ "$ENGINE" = 1 ] && return 0
  # The Java libraries are inside the native binary: export the dependency list the build made (cached, not rebuilt).
  rm -rf "$OUT/sbom-$arch"
  docker buildx build --file image/Containerfile --platform "$platform" --target sbom \
    --build-arg "VERSION=$VERSION" --build-arg "REVISION=$REVISION" --build-arg "SOURCE_URL=$SOURCE_URL" \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" --build-arg "NATIVE_IMAGE_XMX=$XMX" \
    --output "type=local,dest=$OUT/sbom-$arch" .
  [ -s "$OUT/sbom-$arch/java-dependencies.cdx.json" ] || { echo "image-build: the Java dependency list is missing for $platform" >&2; exit 1; }
}

if [ "$MERGE_ONLY" = 0 ]; then
  if [ -n "$ONLY" ]; then build_one "$ONLY"; echo "built $ONLY in $OUT/layout-${ONLY#linux/}; run with --merge-only to make the index"; exit 0; fi
  # No --platform: the first image, linux/arm64 only. --platform both builds the two.
  build_one linux/arm64
  [ "$BOTH" = 1 ] && build_one linux/amd64
fi

# The index holds the platforms whose layouts are in --out: arm64, amd64, or both.
MERGE=()
[ -d "$OUT/layout-arm64" ] && MERGE+=(--arm64 "$OUT/layout-arm64")
[ -d "$OUT/layout-amd64" ] && MERGE+=(--amd64 "$OUT/layout-amd64")
[ ${#MERGE[@]} -gt 0 ] || { echo "image-build: no layout-arm64 or layout-amd64 in $OUT" >&2; exit 2; }
rm -rf "$OUT/oci"
scripts/image-merge.sh "${MERGE[@]}" --out "$OUT" --registry-ref "$REF" --catalog-id "$CATALOG_ID"
DIGEST="$(cat "$OUT/index.digest")"

# The draft catalog entry with the digest filled in. SBOM and scan stay placeholders: catalog-build takes them.
jq --arg d "${DIGEST#sha256:}" --arg v "$VERSION" --slurpfile p "$OUT/platforms.json" \
  'del(._notes) | .image.digest = $d | .version = $v | .image.platforms = ($p[0] | keys | reverse)' "$ENTRY_FILE" > "$OUT/catalog-entry.json"

BUILDER_STAGE=builder; [ "$ENGINE" = 1 ] && BUILDER_STAGE=front   # the engine image builds the front in its first stage
BUILDER_DIGEST="$(sed -n "s/^FROM .*@\(sha256:[a-f0-9]\{64\}\) AS $BUILDER_STAGE\$/\1/p" "$CONTAINERFILE")"
BASE_DIGEST="$(sed -n 's/^FROM .*@\(sha256:[a-f0-9]\{64\}\) AS final$/\1/p' "$CONTAINERFILE")"
jq -n --arg rev "$REVISION" --arg ver "$VERSION" --arg b "$BUILDER_DIGEST" --arg f "$BASE_DIGEST" --arg ref "$REF" --arg d "$DIGEST" --arg epoch "$SOURCE_DATE_EPOCH" \
  '{revision:$rev, version:$ver, sourceDateEpoch:($epoch|tonumber), builderImage:$b, baseImage:$f, indexDigest:$d,
    verifyBeforePush: ["cosign verify-blob --key <IMAGE_SIGNING_KEY> --signature statement.sig statement.json", "check that statement.json names this index digest, the sources entry and the sha256 of every sbom-* and scan-* file, and that the files hash to them"],
    push: ["skopeo copy --all --preserve-digests --dest-authfile <authfile> oci:image/out/oci docker://" + $ref + ":" + ($d | ltrimstr("sha256:") | .[0:32])]}' > "$OUT/build-info.json"

echo "index $DIGEST"
echo "next (operator, owner OK on staging): FIRST verify statement.sig (the signed bundle from image.yml), then push the layout, then add sources-entry.json's entry to the sources file:"
jq -r '.verifyBeforePush[]' "$OUT/build-info.json" | sed 's/^/  verify: /'
jq -r '.push[]' "$OUT/build-info.json" | sed 's/^/  push:   /'
