#!/usr/bin/env bash
# Tests of scripts/engine-library-sbom.sh: the merged SBOM keeps the image's packages, adds one package per crate with a cargo
# purl, is read by the shape Rovara Cloud's catalog-build expects (name and versionInfo, purl in externalRefs), and the script
# refuses an SBOM that is not SPDX or notices with no crate.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
S="$HERE/scripts/engine-library-sbom.sh"
FAIL=0
ok() { echo "ok:   $*"; }
fail() { echo "FAIL: $*"; FAIL=1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/img.spdx.json" <<'JSON'
{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"image","packages":[
 {"SPDXID":"SPDXRef-Package-deb-libc6","name":"libc6","versionInfo":"2.41-12","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:deb/debian/libc6@2.41-12"}]},
 {"SPDXID":"SPDXRef-Package-go-module-x","name":"rovara-aws-front","versionInfo":"(devel)"}],"relationships":[]}
JSON
cat > "$TMP/notices" <<'TXT'
Third-party software notices for aws-emulator

================================================================================

** adler2 2.0.1 (0BSD OR MIT OR Apache-2.0) - https://crates.io/crates/adler2/2.0.1

licence text

** adler2 2.0.1 (0BSD OR MIT OR Apache-2.0) - https://crates.io/crates/adler2/2.0.1
** tokio 1.40.0 (MIT) - https://crates.io/crates/tokio/1.40.0
** rustls-pemfile 2.2.0 (Apache-2.0 OR ISC OR MIT) - https://crates.io/crates/rustls-pemfile/2.2.0
TXT
if "$S" "$TMP/img.spdx.json" "$TMP/notices" "$TMP/out.json" >"$TMP/log" 2>&1; then ok "the merge runs"; else fail "the merge failed"; cat "$TMP/log"; fi
if [ "$(jq '.packages | length' "$TMP/out.json")" = 5 ]; then ok "2 image packages + 3 distinct crates"; else fail "package count"; fi
if jq -e '.packages[] | select(.name=="libc6") | .versionInfo=="2.41-12"' "$TMP/out.json" >/dev/null; then ok "the image's packages are kept"; else fail "image packages lost"; fi
if jq -e '[.packages[] | select(.externalRefs[0].referenceLocator? == "pkg:cargo/tokio@1.40.0")] | length == 1' "$TMP/out.json" >/dev/null; then ok "a crate has its pkg:cargo purl"; else fail "no cargo purl"; fi
if jq -e '[.packages[] | select(.name and .versionInfo)] | length >= 5' "$TMP/out.json" >/dev/null; then ok "the packages Cloud reads (name and versionInfo) are there"; else fail "name/versionInfo"; fi
if jq -e '.spdxVersion | startswith("SPDX-")' "$TMP/out.json" >/dev/null; then ok "still an SPDX document"; else fail "not SPDX"; fi
if [ "$(jq -r '[.packages[].SPDXID] | unique | length' "$TMP/out.json")" = 5 ]; then ok "SPDXIDs are unique"; else fail "SPDXIDs clash"; fi
echo '{"bomFormat":"CycloneDX","components":[]}' > "$TMP/cdx.json"
if "$S" "$TMP/cdx.json" "$TMP/notices" "$TMP/o2.json" >/dev/null 2>&1; then fail "a CycloneDX image SBOM was accepted"; else ok "an image SBOM that is not SPDX is refused"; fi
echo "no crates here" > "$TMP/empty"
if "$S" "$TMP/img.spdx.json" "$TMP/empty" "$TMP/o3.json" >/dev/null 2>&1; then fail "notices with no crate were accepted"; else ok "notices with no crate are refused"; fi
[ "$FAIL" = 0 ] && echo "engine-library-sbom-test: all passed" || echo "engine-library-sbom-test: FAILED"
exit "$FAIL"
