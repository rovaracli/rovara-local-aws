#!/usr/bin/env bash
# Tests of scripts/image-build.sh with a stand-in `docker` (no container engine, no network): the fork build keeps its
# old behaviour (Containerfile, catalog id local-aws@r1, the Java dependency list), and --engine builds
# image/Containerfile.engine for linux/arm64 only, with catalog id local-aws@r1, the engine's catalog entry, and no Java list.
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
if grep -q -- '--file image/Containerfile ' "$STUB_LOG"; then ok "fork: image/Containerfile"; else fail "fork did not build image/Containerfile"; fi
if grep -q -- '--target sbom' "$STUB_LOG" && [ -s "$TMP/fork/sbom-arm64/java-dependencies.cdx.json" ]; then ok "fork: the Java dependency list is exported"; else fail "fork: no Java dependency list"; fi
if grep -q -- 'NATIVE_IMAGE_XMX' "$STUB_LOG"; then ok "fork: native heap build arg"; else fail "fork: no NATIVE_IMAGE_XMX"; fi
if [ "$(jq -r '.sources | keys[0]' "$TMP/fork/sources-entry.json")" = "local-aws@r1" ]; then ok "fork: catalog id local-aws@r1"; else fail "fork: wrong catalog id"; fi
if [ "$(jq -r '.id' "$TMP/fork/catalog-entry.json")" = "local-aws@r1" ]; then ok "fork: catalog entry is image/catalog-entry.json"; else fail "fork: wrong catalog entry"; fi

# engine build
: > "$STUB_LOG"
if "$HERE/scripts/image-build.sh" --engine --registry-ref "$REF" --version r1 --platform linux/arm64 --out "$TMP/engine" --allow-dirty >/dev/null 2>&1 \
   && "$HERE/scripts/image-build.sh" --engine --registry-ref "$REF" --version r1 --merge-only --out "$TMP/engine" --allow-dirty >"$TMP/engine.log" 2>&1; then ok "engine build and merge run"; else fail "engine build did not run"; cat "$TMP/engine.log"; fi
if grep -q -- '--file image/Containerfile.engine ' "$STUB_LOG"; then ok "engine: image/Containerfile.engine"; else fail "engine did not build image/Containerfile.engine"; fi
if grep -q -- '--target sbom' "$STUB_LOG"; then fail "engine: asked for a Java dependency list"; else ok "engine: no Java dependency list"; fi
if grep -q -- 'NATIVE_IMAGE_XMX' "$STUB_LOG"; then fail "engine: passed the native heap arg"; else ok "engine: no native heap arg"; fi
if [ ! -e "$TMP/engine/sbom-arm64" ]; then ok "engine: no sbom-arm64 directory"; else fail "engine: sbom-arm64 exists"; fi
if [ "$(jq -r '.sources | keys[0]' "$TMP/engine/sources-entry.json")" = "local-aws@r1" ]; then ok "engine: catalog id local-aws@r1"; else fail "engine: wrong catalog id"; fi
if [ "$(jq -r '.id + " " + .version + " " + (.image.platforms|join(",")) + " " + (.resources.memMiB|tostring)' "$TMP/engine/catalog-entry.json")" = "local-aws@r1 r1 linux/arm64 512" ]; then ok "engine: catalog entry is image/catalog-entry.engine.json, filled"; else fail "engine: wrong catalog entry"; fi
if [ "$(jq -r 'has("_notes")' "$TMP/engine/catalog-entry.json")" = false ]; then ok "engine: _notes dropped"; else fail "engine: _notes kept"; fi
if [[ "$(cat "$TMP/engine/index.digest")" =~ ^sha256:[0-9a-f]{64}$ ]]; then ok "engine: index.digest is one sha256"; else fail "engine: bad index.digest"; fi
if [ "$(jq -r 'keys|join(",")' "$TMP/engine/platforms.json")" = "linux/arm64" ]; then ok "engine: one platform, linux/arm64"; else fail "engine: platforms"; fi
if jq -e '.builderImage|test("^sha256:")' "$TMP/engine/build-info.json" >/dev/null && jq -e '.baseImage|test("^sha256:")' "$TMP/engine/build-info.json" >/dev/null; then ok "engine: build-info names the builder and base digests"; else fail "engine: build-info digests"; fi
if [ -f "$TMP/engine/oci/oci-layout" ] && [ -f "$TMP/engine/oci/index.json" ]; then ok "engine: OCI layout in oci/"; else fail "engine: no oci/"; fi
if "$HERE/scripts/image-build.sh" --engine --registry-ref "$REF" --platform linux/amd64 --out "$TMP/e2" --allow-dirty >/dev/null 2>&1; then fail "engine: amd64 was accepted"; else ok "engine: linux/amd64 is refused"; fi
if "$HERE/scripts/image-build.sh" --engine --registry-ref "$REF" --platform both --out "$TMP/e3" --allow-dirty >/dev/null 2>&1; then fail "engine: both was accepted"; else ok "engine: both is refused"; fi
# the two small Go images (0.5.19): their own Containerfile and build context, their own catalog id, no catalog entry, no Java list
for t in function-agent model-stand-in; do
  : > "$STUB_LOG"
  REFT=registry.example/rovara-catalog/test/svc/$t
  if "$HERE/scripts/image-build.sh" --target "$t" --registry-ref "$REFT" --version r1 --platform linux/arm64 --out "$TMP/$t" --allow-dirty --allow-emulation >/dev/null 2>&1 \
     && "$HERE/scripts/image-build.sh" --target "$t" --registry-ref "$REFT" --version r1 --merge-only --out "$TMP/$t" --allow-dirty >"$TMP/$t.log" 2>&1; then ok "$t: build and merge run"; else fail "$t: build did not run"; cat "$TMP/$t.log"; fi
  ctx=runner/agent; [ "$t" = model-stand-in ] && ctx=model-stand-in
  if grep -q -- "--file $ctx/Containerfile " "$STUB_LOG" && grep -q -- "rewrite-timestamp=true $ctx\$" "$STUB_LOG"; then ok "$t: $ctx/Containerfile with $ctx as the context"; else fail "$t: wrong Containerfile or context"; fi
  if grep -q -- '--target sbom' "$STUB_LOG" || grep -q -- 'NATIVE_IMAGE_XMX' "$STUB_LOG"; then fail "$t: asked for the fork's Java build"; else ok "$t: no Java list, no native heap arg"; fi
  if [ "$(jq -r '.sources | keys[0]' "$TMP/$t/sources-entry.json")" = "$t@r1" ] && [ "$(jq -r '.entries | keys[0]' "$TMP/$t/repack-entry.json")" = "$t@r1" ]; then ok "$t: catalog id $t@r1"; else fail "$t: wrong catalog id"; fi
  if [ ! -e "$TMP/$t/catalog-entry.json" ] && [ ! -e "$TMP/$t/sbom-arm64" ]; then ok "$t: no catalog-entry.json, no sbom-arm64"; else fail "$t: stray catalog entry or sbom dir"; fi
  if jq -e '.builderImage|test("^sha256:[0-9a-f]{64}$")' "$TMP/$t/build-info.json" >/dev/null; then ok "$t: build-info names the Go build image digest"; else fail "$t: build-info builder digest"; fi
done
if [ "$(jq -r '.baseImage' "$TMP/function-agent/build-info.json")" = "" ] && jq -e '.baseImage|test("^sha256:[0-9a-f]{64}$")' "$TMP/model-stand-in/build-info.json" >/dev/null; then ok "base image: none for FROM scratch, the distroless digest for the stand-in"; else fail "base image digests"; fi
if "$HERE/scripts/image-build.sh" --target function-agent --registry-ref "$REF" --platform linux/amd64 --out "$TMP/f2" --allow-dirty >/dev/null 2>&1; then fail "function-agent: amd64 was accepted"; else ok "function-agent: linux/amd64 is refused"; fi
if "$HERE/scripts/image-build.sh" --target nonsense --registry-ref "$REF" --out "$TMP/f3" --allow-dirty >/dev/null 2>&1; then fail "an unknown target was accepted"; else ok "an unknown target is refused"; fi
[ "$FAIL" = 0 ] && echo "image-build-test: all passed" || echo "image-build-test: FAILED"
exit "$FAIL"
