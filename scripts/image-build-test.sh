#!/usr/bin/env bash
# Tests of scripts/image-build.sh with a stand-in `docker` (no container engine, no network): the fork build keeps its
# old behaviour (Containerfile, catalog id local-aws@r1, the Java dependency list), and --engine builds
# image/Containerfile.engine for linux/arm64 only, with catalog id local-aws@r2, the engine's catalog entry, and no Java list.
# Linux only (image-build.sh refuses anything else).
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(uname -s)" = Linux ] || { echo "skip: image-build.sh runs on Linux only"; exit 0; }
FAIL=0
ok() { echo "ok:   $*"; }
fail() { echo "FAIL: $*"; FAIL=1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
# a docker that records its arguments and writes a tiny, valid single-image OCI layout for the platform asked
cat > "$TMP/bin/docker" <<'STUB'
#!/usr/bin/env bash
echo "docker $*" >> "$STUB_LOG"
case "$1 $2" in
  "buildx version"|"buildx inspect") exit 0 ;;
esac
platform=""; out=""; target=""
while [ $# -gt 0 ]; do case "$1" in --platform) platform="$2"; shift 2 ;; --output) out="$2"; shift 2 ;; --target) target="$2"; shift 2 ;; *) shift ;; esac; done
if [ "$target" = sbom ]; then
  dest="${out#type=local,dest=}"; mkdir -p "$dest"; echo '{"bomFormat":"CycloneDX"}' > "$dest/java-dependencies.cdx.json"; exit 0
fi
dest="${out#type=oci,dest=}"; dest="${dest%%,*}"
python3 - "$platform" "$dest" <<'PY'
import hashlib, json, os, sys, tarfile, tempfile
platform, dest = sys.argv[1], sys.argv[2].split(",")[0]
arch = platform.split("/")[1]
d = tempfile.mkdtemp(); os.makedirs(d + "/blobs/sha256")
def blob(b):
    h = hashlib.sha256(b).hexdigest(); open(d + "/blobs/sha256/" + h, "wb").write(b); return h, len(b)
ch, cs = blob(json.dumps({"architecture": arch, "os": "linux", "config": {}}).encode())
mh, ms = blob(json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + ch, "size": cs}, "layers": []}).encode())
open(d + "/oci-layout", "w").write('{"imageLayoutVersion":"1.0.0"}')
open(d + "/index.json", "w").write(json.dumps({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + mh, "size": ms}]}))
with tarfile.open(dest, "w") as t:
    for n in ("oci-layout", "index.json", "blobs"): t.add(d + "/" + n, arcname=n)
PY
STUB
chmod +x "$TMP/bin/docker"
export STUB_LOG="$TMP/docker.log" PATH="$TMP/bin:$PATH"
REF=registry.example/rovara-catalog/test/svc/local-aws

# fork build: as before
: > "$STUB_LOG"
if "$HERE/scripts/image-build.sh" --registry-ref "$REF" --version r1 --platform linux/arm64 --out "$TMP/fork" --allow-dirty --allow-emulation >/dev/null 2>&1 \
   && "$HERE/scripts/image-build.sh" --registry-ref "$REF" --version r1 --merge-only --out "$TMP/fork" --allow-dirty >/dev/null 2>&1; then ok "fork build and merge run"; else fail "fork build did not run"; fi
grep -q -- '--file image/Containerfile ' "$STUB_LOG" && ok "fork: image/Containerfile" || fail "fork did not build image/Containerfile"
grep -q -- '--target sbom' "$STUB_LOG" && [ -s "$TMP/fork/sbom-arm64/java-dependencies.cdx.json" ] && ok "fork: the Java dependency list is exported" || fail "fork: no Java dependency list"
grep -q -- 'NATIVE_IMAGE_XMX' "$STUB_LOG" && ok "fork: native heap build arg" || fail "fork: no NATIVE_IMAGE_XMX"
[ "$(jq -r '.sources | keys[0]' "$TMP/fork/sources-entry.json")" = "local-aws@r1" ] && ok "fork: catalog id local-aws@r1" || fail "fork: wrong catalog id"
[ "$(jq -r '.id' "$TMP/fork/catalog-entry.json")" = "local-aws@r1" ] && ok "fork: catalog entry is image/catalog-entry.json" || fail "fork: wrong catalog entry"

# engine build
: > "$STUB_LOG"
if "$HERE/scripts/image-build.sh" --engine --registry-ref "$REF" --version r2 --platform linux/arm64 --out "$TMP/engine" --allow-dirty >/dev/null 2>&1 \
   && "$HERE/scripts/image-build.sh" --engine --registry-ref "$REF" --version r2 --merge-only --out "$TMP/engine" --allow-dirty >"$TMP/engine.log" 2>&1; then ok "engine build and merge run"; else fail "engine build did not run"; cat "$TMP/engine.log"; fi
grep -q -- '--file image/Containerfile.engine ' "$STUB_LOG" && ok "engine: image/Containerfile.engine" || fail "engine did not build image/Containerfile.engine"
grep -q -- '--target sbom' "$STUB_LOG" && fail "engine: asked for a Java dependency list" || ok "engine: no Java dependency list"
grep -q -- 'NATIVE_IMAGE_XMX' "$STUB_LOG" && fail "engine: passed the native heap arg" || ok "engine: no native heap arg"
[ ! -e "$TMP/engine/sbom-arm64" ] && ok "engine: no sbom-arm64 directory" || fail "engine: sbom-arm64 exists"
[ "$(jq -r '.sources | keys[0]' "$TMP/engine/sources-entry.json")" = "local-aws@r2" ] && ok "engine: catalog id local-aws@r2" || fail "engine: wrong catalog id"
[ "$(jq -r '.id + " " + .version + " " + (.image.platforms|join(","))' "$TMP/engine/catalog-entry.json")" = "local-aws@r2 r2 linux/arm64" ] && ok "engine: catalog entry is image/catalog-entry.engine.json, filled" || fail "engine: wrong catalog entry"
[ "$(jq -r 'has("_notes")' "$TMP/engine/catalog-entry.json")" = false ] && ok "engine: _notes dropped" || fail "engine: _notes kept"
[[ "$(cat "$TMP/engine/index.digest")" =~ ^sha256:[0-9a-f]{64}$ ]] && ok "engine: index.digest is one sha256" || fail "engine: bad index.digest"
[ "$(jq -r 'keys|join(",")' "$TMP/engine/platforms.json")" = "linux/arm64" ] && ok "engine: one platform, linux/arm64" || fail "engine: platforms"
jq -e '.builderImage|test("^sha256:")' "$TMP/engine/build-info.json" >/dev/null && jq -e '.baseImage|test("^sha256:")' "$TMP/engine/build-info.json" >/dev/null && ok "engine: build-info names the builder and base digests" || fail "engine: build-info digests"
[ -f "$TMP/engine/oci/oci-layout" ] && [ -f "$TMP/engine/oci/index.json" ] && ok "engine: OCI layout in oci/" || fail "engine: no oci/"
if "$HERE/scripts/image-build.sh" --engine --registry-ref "$REF" --platform linux/amd64 --out "$TMP/e2" --allow-dirty >/dev/null 2>&1; then fail "engine: amd64 was accepted"; else ok "engine: linux/amd64 is refused"; fi
if "$HERE/scripts/image-build.sh" --engine --registry-ref "$REF" --platform both --out "$TMP/e3" --allow-dirty >/dev/null 2>&1; then fail "engine: both was accepted"; else ok "engine: both is refused"; fi
[ "$FAIL" = 0 ] && echo "image-build-test: all passed" || echo "image-build-test: FAILED"
exit "$FAIL"
