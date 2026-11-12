#!/usr/bin/env bash
# Tests for scripts/image-check.sh and scripts/image-merge.sh. No container engine, no network.
#   scripts/image-check-test.sh
# 1. the real image files pass image-check.sh;
# 2. each mutation of a copy (an unpinned FROM, root USER, a second EXPOSE, a token in ENV, ...) makes it fail;
# 3. image-merge.sh turns two fabricated single-platform layouts into one two-platform index with the right digests.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/image-check-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
PASS=0; BAD=0
t_ok() { PASS=$((PASS+1)); echo "pass: $1"; }
t_bad() { BAD=$((BAD+1)); echo "FAIL: $1"; }

fresh() {  # name -> a copy of the image files under $WORK/name
  local d="$WORK/$1"; rm -rf "$d"; mkdir -p "$d/image" "$d/.github/workflows" "$d/scripts"
  cp "$HERE/image/Containerfile" "$HERE/image/catalog-entry.json" "$d/image/"
  cp "$HERE/.github/workflows/image.yml" "$d/.github/workflows/"
  cp "$HERE/.dockerignore" "$d/"
  cp "$HERE"/scripts/image-*.sh "$HERE/scripts/control-check.sh" "$d/scripts/"
  mkdir -p "$d/src/test/java/ai/rovara/localaws/rovara"
  cp "$HERE"/src/test/java/ai/rovara/localaws/rovara/RovaraControl{Closed,Token}IntegrationTest.java "$d/src/test/java/ai/rovara/localaws/rovara/"
  echo "$d"
}
edit() {  # file python-expression-on-s
  python3 -I - "$1" "$2" <<'PY'
import sys
p, expr = sys.argv[1], sys.argv[2]
s = open(p).read()
t = eval(expr, {"s": s})
assert t != s, "mutation changed nothing: " + expr
open(p, "w").write(t)
PY
}
expect_pass() {
  local d; d="$(fresh "$1")"
  if IMAGE_CHECK_ROOT="$d" "$HERE/scripts/image-check.sh" >"$WORK/$1.out" 2>&1; then t_ok "$1"; else t_bad "$1 should pass"; tail -5 "$WORK/$1.out"; fi
}
expect_fail() {  # name file expression expected-text
  local d; d="$(fresh "$1")"
  edit "$d/$2" "$3" || { t_bad "$1: mutation did not apply"; return; }
  if IMAGE_CHECK_ROOT="$d" "$HERE/scripts/image-check.sh" >"$WORK/$1.out" 2>&1; then t_bad "$1 should fail"
  elif grep -q "$4" "$WORK/$1.out"; then t_ok "$1"
  else t_bad "$1 failed, but not with '$4'"; grep FAIL "$WORK/$1.out" | head -3; fi
}

# ---- the real files
if "$HERE/scripts/image-check.sh" >"$WORK/real.out" 2>&1; then t_ok "the repository's image files pass"; else t_bad "the repository's image files should pass"; grep FAIL "$WORK/real.out"; fi
expect_pass copy-passes

# ---- Containerfile mutations
CF=image/Containerfile
expect_fail from-builder-unpinned $CF 's.replace("@sha256:4af907423955d43beb791ee247516e13128fc880b4e58f6a66171a90f850e1fb","")' "FROM is not pinned"
expect_fail from-final-unpinned $CF 's.replace("@sha256:9039a88709bcc2bacf5a2faac331d65dd6840f763f225ad9594cc0c67bcd0fba","")' "FROM is not pinned"
expect_fail from-latest-tag $CF 's.replace(":nonroot@sha256:9039a88709bcc2bacf5a2faac331d65dd6840f763f225ad9594cc0c67bcd0fba",":latest")' "FROM is not pinned"
expect_fail inlining-on $CF 's.replace("-H:-AOTSingleCallsiteInline","-H:+AOTSingleCallsiteInline")' "NATIVE_BUILD_ARGS"
expect_fail user-root $CF 's.replace("USER 10001:10001","USER root")' "numeric"
expect_fail user-zero $CF 's.replace("USER 10001:10001","USER 0")' "numeric"
expect_fail user-gid-zero $CF 's.replace("USER 10001:10001","USER 10001:0")' "numeric"
expect_fail user-name $CF 's.replace("USER 10001:10001","USER nonroot")' "numeric"
expect_fail user-missing $CF 's.replace("USER 10001:10001\n","")' "numeric"
expect_fail second-expose $CF 's.replace("EXPOSE 4566\n","EXPOSE 4566\nEXPOSE 9169\n")' "exactly one"
expect_fail wrong-port $CF 's.replace("EXPOSE 4566\n","EXPOSE 8080\n")' "exactly one"
expect_fail no-expose $CF 's.replace("EXPOSE 4566\n","")' "exactly one"
expect_fail licence-path $CF 's.replace("COPY LICENSE NOTICE THIRD-PARTY-NOTICES.txt /usr/share/licenses/rovara-local-aws/","COPY LICENSE NOTICE THIRD-PARTY-NOTICES.txt /usr/share/doc/")' "licence"
expect_fail licence-dir-path $CF 's.replace("COPY licenses/ /usr/share/licenses/rovara-local-aws/licenses/","COPY licenses/ /opt/licenses/")' "licenses/ is not copied"
expect_fail licence-missing-notice $CF 's.replace("COPY LICENSE NOTICE THIRD-PARTY-NOTICES.txt","COPY LICENSE THIRD-PARTY-NOTICES.txt")' "must be one COPY"
UP="$(printf 'Fl%s' 'oci')"
expect_fail upstream-name-in-label $CF "s.replace('io.rovara.service=\"local-aws\"','io.rovara.service=\"local-aws\" io.rovara.upstream=\"$UP\"')" "upstream name"
TK="$(printf 'TO%s' KEN)"
expect_fail env-token $CF "s.replace('ENV LD_LIBRARY_PATH','ENV ROVARA_AWS_CONTROL_${TK}=value LD_LIBRARY_PATH')" "token, secret"
expect_fail env-password $CF 's.replace("ARG VERSION=dev","ARG VERSION=dev\nARG DB_PASSWORD=x")' "token, secret"
expect_fail docker-host $CF 's.replace("ENV LD_LIBRARY_PATH","ENV DOCKER_HOST=unix:///var/run/x LD_LIBRARY_PATH")' "docker socket"
expect_fail docker-socket $CF 's.replace("WORKDIR /tmp","WORKDIR /tmp\nCOPY --from=builder /var/run/docker.sock /x")' "docker socket"
expect_fail volume $CF 's.replace("WORKDIR /tmp","WORKDIR /tmp\nVOLUME [\"/data\"]")' "docker socket"
expect_fail run-in-final $CF 's.replace("WORKDIR /tmp","WORKDIR /tmp\nRUN true")' "RUN"
expect_fail entrypoint-shell $CF 's.replace("ENTRYPOINT [\"/usr/local/bin/rovara-local-aws\", \"-Xmx192m\"]","ENTRYPOINT /usr/local/bin/rovara-local-aws -Xmx192m")' "exec form"
expect_fail entrypoint-no-heap-cap $CF 's.replace("ENTRYPOINT [\"/usr/local/bin/rovara-local-aws\", \"-Xmx192m\"]","ENTRYPOINT [\"/usr/local/bin/rovara-local-aws\"]")' "heap cap"
expect_fail missing-source-label $CF 's.replace("org.opencontainers.image.source=","org.opencontainers.image.src=")' "label"
expect_fail double-underscore-health $CF 's.replace("/_rovara/health","/__rovara/health")' "health"

# ---- catalog entry mutations
CE=image/catalog-entry.json
expect_fail catalog-user $CE 's.replace("\"10001:10001\"","\"999:999\"")' "run.user"
expect_fail catalog-port $CE 's.replace("4566\n    ]","4567\n    ]")' "ports"
expect_fail catalog-health $CE 's.replace("/_rovara/health","/__rovara/health")' "health"
expect_fail catalog-platform $CE 's.replace("\"linux/arm64\"","\"linux/s390x\"")' "platforms"
expect_fail catalog-digest-filled $CE 's.replace("PLACEHOLDER-index-sha256-filled-by-scripts-image-build.sh","0"*64)' "PLACEHOLDER"
expect_fail catalog-notes-missing-env $CE 's.replace("ROVARA_AWS_AUTH_PRESIGN_SECRET","ROVARA_AWS_X")' "_notes.runEnv"
expect_fail catalog-rw-root $CE 's.replace("\"readOnlyRoot\": true","\"readOnlyRoot\": false")' "readOnlyRoot"

# ---- workflow mutations
WF=.github/workflows/image.yml
expect_fail workflow-push $WF 's.replace("on:\n  workflow_dispatch:","on:\n  push:\n    branches: [main]\n  workflow_dispatch:")' "workflow_dispatch only"
expect_fail workflow-schedule $WF 's.replace("on:\n  workflow_dispatch:","on:\n  schedule:\n    - cron: \"0 3 * * *\"\n  workflow_dispatch:")' "workflow_dispatch only"
expect_fail workflow-pr $WF 's.replace("on:\n  workflow_dispatch:","on:\n  pull_request:\n  workflow_dispatch:")' "workflow_dispatch only"
expect_fail workflow-tag-pin $WF 's.replace("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1","actions/checkout@v7",1)' "not pinned by sha"
expect_fail workflow-id-token-everywhere $WF 's.replace("permissions:\n  contents: read\n\nconcurrency","permissions:\n  contents: read\n  id-token: write\n\nconcurrency")' "id-token"
expect_fail workflow-retention $WF 's.replace("retention-days: 1\n          if-no-files-found: error\n\n  measure","retention-days: 7\n          if-no-files-found: error\n\n  measure")' "retention"
expect_fail workflow-release-whole-out $WF 's.replace("            ${{ runner.temp }}/out/statement.json\n","            ${{ runner.temp }}/out\n            ${{ runner.temp }}/out/statement.json\n")' "image-release"
expect_fail workflow-release-has-oci $WF 's.replace("            ${{ runner.temp }}/out/statement.json\n","            ${{ runner.temp }}/out/oci\n            ${{ runner.temp }}/out/statement.json\n")' "image-release"
expect_fail workflow-no-measure-gate $WF 's.replace("scripts/perf-gate.sh native","scripts/perf-gate.sh jvm")' "measure job"
expect_fail workflow-sign-not-after-measure $WF 's.replace("needs: [assemble, measure, measure-engine]","needs: assemble")' "measure job"
expect_fail workflow-qemu $WF 's.replace("      - name: Add swap for the native build (small runner)","      - name: qemu\n        uses: docker/setup-qemu-action@99012661954931238ded8c8b007157a8430204e1\n      - name: Add swap for the native build (small runner)")' "no QEMU"
expect_fail workflow-platforms-default-both $WF 's.replace("default: \"linux/arm64\"","default: \"both\"")' "platforms"
expect_fail workflow-no-plan-matrix $WF 's.replace("fromJSON(needs.plan.outputs.matrix)","fromJSON(\x27{}\x27)")' "platforms"
expect_fail workflow-arm-runner-hardcoded $WF 's.replace("ARM64_RUNNER:-ubuntu-24.04-arm","ARM64_RUNNER:-ubuntu-24.04")' "platforms"
expect_fail workflow-sign-default-true $WF 's.replace("required: false\n        default: false\n        type: boolean","required: false\n        default: true\n        type: boolean")' "sign"
expect_fail workflow-sign-always $WF 's.replace("    if: ${{ inputs.sign && !failure() && !cancelled() }}\n","")' "sign"
expect_fail workflow-no-unsigned-notice $WF 's.replace("UNSIGNED: not for the catalog","signed")' "sign"
expect_fail workflow-no-xmx $WF 's.replace("NATIVE_IMAGE_XMX","NATIVE_XMX")' "NATIVE_IMAGE_XMX"
expect_fail catalog-platform-amd64-only $CE 's.replace("\"linux/arm64\"","\"linux/amd64\"")' "platforms"
expect_fail workflow-no-role-check $WF 's.replace("IMAGE_SIGNING_ROLE_ARN","IMAGE_SIGNING_ROLE_X")' "IMAGE_SIGNING_ROLE_ARN"
expect_fail workflow-no-java-scan $WF 's.replace("sbom:sbom-","dir:sbom-")' "scan"
expect_fail containerfile-no-sbom-stage image/Containerfile 's.replace("FROM scratch AS sbom","FROM scratch AS other")' "CycloneDX"

# ---- the real-HTTP control tests must exist
d="$(fresh missing-control-check)"; rm -f "$d/scripts/control-check.sh"
if IMAGE_CHECK_ROOT="$d" "$HERE/scripts/image-check.sh" >"$WORK/mcc.out" 2>&1; then t_bad "a missing control-check.sh should fail"; elif grep -q "missing: scripts/control-check.sh" "$WORK/mcc.out"; then t_ok "missing-control-check"; else t_bad "missing-control-check: wrong reason"; fi

# ---- a key-shaped string anywhere in the image files
KEYLIKE="$(printf 'AKI%s' 'AABCDEFGHIJKLMNOP')"
expect_fail key-shaped $CF "s.replace('WORKDIR /tmp','WORKDIR /tmp\n# $KEYLIKE')" "key-shaped"

# ---- image-merge.sh on fabricated layouts
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
fabricate() {  # dir arch [variant]: a one-image OCI layout with an image-manifest descriptor in index.json
  local dir="$1" arch="$2" variant="${3:-}" b="$1/blobs/sha256" cfg man layer
  mkdir -p "$b"; printf '{"imageLayoutVersion":"1.0.0"}' > "$dir/oci-layout"
  if [ -n "$variant" ]; then printf '{"architecture":"%s","os":"linux","variant":"%s","config":{}}' "$arch" "$variant" > "$dir/cfg"
  else printf '{"architecture":"%s","os":"linux","config":{}}' "$arch" > "$dir/cfg"; fi
  printf 'layer-%s' "$arch" > "$dir/layer"
  cfg="$(sha "$dir/cfg")"; layer="$(sha "$dir/layer")"
  mv "$dir/cfg" "$b/$cfg"; mv "$dir/layer" "$b/$layer"
  printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%s","size":%s},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:%s","size":%s}]}' \
    "$cfg" "$(wc -c < "$b/$cfg" | tr -d ' ')" "$layer" "$(wc -c < "$b/$layer" | tr -d ' ')" > "$dir/man"
  man="$(sha "$dir/man")"; mv "$dir/man" "$b/$man"
  printf '{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":%s}]}' "$man" "$(wc -c < "$b/$man" | tr -d ' ')" > "$dir/index.json"
  echo "sha256:$man"
}
if command -v jq >/dev/null 2>&1; then
  M="$WORK/merge"; mkdir -p "$M"
  MA="$(fabricate "$M/amd" amd64)"; MB="$(fabricate "$M/arm" arm64 v8)"
  REF="123456789012.dkr.ecr.us-west-2.amazonaws.com/rovara-catalog/staging/svc/local-aws"
  if "$HERE/scripts/image-merge.sh" --amd64 "$M/amd" --arm64 "$M/arm" --out "$M/out" --registry-ref "$REF" >"$M/merge.log" 2>&1; then
    t_ok "merge runs"
    D="$(cat "$M/out/index.digest")"
    [ "$D" = "sha256:$(sha "$M/out/oci/blobs/sha256/${D#sha256:}")" ] && t_ok "index.digest is the hash of the index blob" || t_bad "index digest does not match the blob"
    [ "$(jq -r '.manifests | length' "$M/out/oci/index.json")" = 1 ] && [ "$(jq -r '.manifests[0].digest' "$M/out/oci/index.json")" = "$D" ] && t_ok "the layout's only image is the index" || t_bad "index.json"
    [ "$(jq -r '[.manifests[].platform | .os + "/" + .architecture] | join(",")' "$M/out/oci/blobs/sha256/${D#sha256:}")" = "linux/amd64,linux/arm64" ] && t_ok "the index lists exactly linux/amd64 and linux/arm64" || t_bad "index platforms"
    [ "$(jq -r '.manifests[1].platform.variant' "$M/out/oci/blobs/sha256/${D#sha256:}")" = v8 ] && t_ok "arm64 variant kept from the config" || t_bad "variant"
    [ "$(jq -r '.manifests[0].digest + " " + .manifests[1].digest' "$M/out/oci/blobs/sha256/${D#sha256:}")" = "$MA $MB" ] && t_ok "child digests are the layouts' manifests, unchanged" || t_bad "child digests"
    [ "$(jq -r '.sources["local-aws@r1"]' "$M/out/sources-entry.json")" = "$REF@$D" ] && t_ok "sources entry is <ref>@<index digest>" || t_bad "sources entry"
    jq -e '.schemaVersion == 1 and (.sources | keys == ["local-aws@r1"])' "$M/out/sources-entry.json" >/dev/null && t_ok "sources file shape (schemaVersion 1, sources)" || t_bad "sources shape"
    jq -r '.sources["local-aws@r1"]' "$M/out/sources-entry.json" | grep -Eq '^[a-z0-9][a-z0-9.-]*(:[0-9]{1,5})?/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$' && t_ok "the reference has the form catalog-build accepts" || t_bad "reference form"
    bad=0; for f in "$M"/out/oci/blobs/sha256/*; do [ "$(sha "$f")" = "$(basename "$f")" ] || bad=1; done
    [ "$bad" = 0 ] && t_ok "every blob in the merged layout hashes to its name" || t_bad "blob names"
    "$HERE/scripts/image-merge.sh" --amd64 "$M/amd" --arm64 "$M/arm" --out "$M/out2" --registry-ref "$REF" >/dev/null 2>&1
    [ "$(cat "$M/out2/index.digest")" = "$D" ] && t_ok "the same inputs give the same index digest" || t_bad "not deterministic"
    "$HERE/scripts/image-merge.sh" --amd64 "$M/amd" --arm64 "$M/arm" --out "$M/out" --registry-ref "$REF" >/dev/null 2>&1 && t_bad "merge over an existing oci dir should refuse" || t_ok "merge refuses an existing oci dir"
  else t_bad "merge runs"; cat "$M/merge.log"; fi
  # a one-platform index (the first image is linux/arm64 only)
  if "$HERE/scripts/image-merge.sh" --arm64 "$M/arm" --out "$M/one" --registry-ref "$REF" >"$M/one.log" 2>&1; then
    D1="$(cat "$M/one/index.digest")"
    [ "$(jq -r '[.manifests[].platform | .os + "/" + .architecture] | join(",")' "$M/one/oci/blobs/sha256/${D1#sha256:}")" = "linux/arm64" ] && t_ok "a one-platform index lists exactly linux/arm64" || t_bad "one-platform index"
    [ "$(jq -c 'keys' "$M/one/platforms.json")" = '["linux/arm64"]' ] && t_ok "platforms.json holds only the built platform" || t_bad "one-platform platforms.json"
    [ "$D1" != "$D" ] && t_ok "a one-platform index has its own digest" || t_bad "one-platform digest equals the two-platform one"
    [ "$(jq -c --slurpfile p "$M/one/platforms.json" '.image.platforms = ($p[0] | keys | reverse) | .image.platforms' "$HERE/image/catalog-entry.json")" = '["linux/arm64"]' ] && t_ok "the filled catalog entry lists only linux/arm64" || t_bad "catalog platforms fill"
    [ "$(jq -c --slurpfile p "$M/out/platforms.json" '.image.platforms = ($p[0] | keys | reverse) | .image.platforms' "$HERE/image/catalog-entry.json")" = '["linux/arm64","linux/amd64"]' ] && t_ok "a two-platform fill lists arm64 then amd64" || t_bad "two-platform catalog fill"
  else t_bad "a one-platform merge should work"; cat "$M/one.log"; fi
  "$HERE/scripts/image-merge.sh" --out "$M/none" --registry-ref "$REF" >/dev/null 2>&1 && t_bad "a merge with no layout should be refused" || t_ok "a merge with no layout is refused"
  # wrong platform in a layout, and a tagged registry ref, are refused
  "$HERE/scripts/image-merge.sh" --amd64 "$M/arm" --arm64 "$M/arm" --out "$M/out3" --registry-ref "$REF" >/dev/null 2>&1 && t_bad "an arm64 layout passed as amd64 should be refused" || t_ok "a layout of the wrong platform is refused"
  "$HERE/scripts/image-merge.sh" --amd64 "$M/amd" --arm64 "$M/arm" --out "$M/out4" --registry-ref "$REF:latest" >/dev/null 2>&1 && t_bad "a tagged registry ref should be refused" || t_ok "a registry ref with a tag is refused"
else
  echo "skip: jq is not installed; the merge tests did not run"
fi

# ---- image-extract-binary.sh on a fabricated single-platform image whose layer holds the binary and a library
if command -v jq >/dev/null 2>&1; then
  X="$WORK/extract"; mkdir -p "$X/stage/usr/local/bin" "$X/stage/usr/lib/rovara" "$X/layout/blobs/sha256"
  printf '#!/bin/sh\necho fake-binary\n' > "$X/stage/usr/local/bin/rovara-local-aws"; chmod 0755 "$X/stage/usr/local/bin/rovara-local-aws"
  printf 'fake-lib' > "$X/stage/usr/lib/rovara/libz.so.1"
  tar -czf "$X/layer.tgz" -C "$X/stage" usr
  L="$(sha "$X/layer.tgz")"; mv "$X/layer.tgz" "$X/layout/blobs/sha256/$L"
  printf '{"architecture":"amd64","os":"linux","config":{}}' > "$X/cfg"; C="$(sha "$X/cfg")"; mv "$X/cfg" "$X/layout/blobs/sha256/$C"
  printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%s","size":1},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:%s","size":1}]}' "$C" "$L" > "$X/man"
  MM="$(sha "$X/man")"; mv "$X/man" "$X/layout/blobs/sha256/$MM"
  printf '{"imageLayoutVersion":"1.0.0"}' > "$X/layout/oci-layout"
  printf '{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":1}]}' "$MM" > "$X/layout/index.json"
  if "$HERE/scripts/image-extract-binary.sh" "$X/layout" "$X/out" >"$X/extract.log" 2>&1; then
    t_ok "extract runs"
    [ "$("$X/out/rovara-local-aws")" = fake-binary ] && [ -x "$X/out/rovara-local-aws" ] && t_ok "the binary comes out executable and intact" || t_bad "extracted binary"
    [ "$(cat "$X/out/lib/libz.so.1")" = fake-lib ] && t_ok "the shared library comes out in lib/" || t_bad "extracted library"
  else t_bad "extract runs"; cat "$X/extract.log"; fi
  # layers with read-only files and directories (a 0555 binary in a 0555 directory) must not make the cleanup fail
  chmod 0555 "$X/stage/usr/lib/rovara" 2>/dev/null; chmod 0444 "$X/stage/usr/lib/rovara/libz.so.1"
  mkdir -p "$X/stage/usr/local/bin"; printf '#!/bin/sh\necho fake-binary\n' > "$X/stage/usr/local/bin/rovara-local-aws"; chmod 0555 "$X/stage/usr/local/bin/rovara-local-aws" "$X/stage/usr/local/bin" "$X/stage/usr/local"
  tar -czf "$X/layerro.tgz" -C "$X/stage" usr; LR="$(sha "$X/layerro.tgz")"; mv "$X/layerro.tgz" "$X/layout/blobs/sha256/$LR"
  sed "s/$L/$LR/" "$X/layout/blobs/sha256/$MM" > "$X/manro"; MR="$(sha "$X/manro")"; mv "$X/manro" "$X/layout/blobs/sha256/$MR"
  printf '{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":1}]}' "$MR" > "$X/layout/index.json"
  "$HERE/scripts/image-extract-binary.sh" "$X/layout" "$X/out-ro" >/dev/null 2>&1 && t_ok "read-only files in the image do not break the cleanup" || t_bad "read-only image files made the extract fail"
  chmod -R u+rwX "$X/stage" 2>/dev/null
  # an image without the binary is refused
  rm -rf "$X/stage/usr/local"; tar -czf "$X/layer2.tgz" -C "$X/stage" usr; L2="$(sha "$X/layer2.tgz")"; mv "$X/layer2.tgz" "$X/layout/blobs/sha256/$L2"
  sed "s/$L/$L2/" "$X/layout/blobs/sha256/$MM" > "$X/man2"; M2="$(sha "$X/man2")"; mv "$X/man2" "$X/layout/blobs/sha256/$M2"
  printf '{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":1}]}' "$M2" > "$X/layout/index.json"
  "$HERE/scripts/image-extract-binary.sh" "$X/layout" "$X/out2" >/dev/null 2>&1 && t_bad "an image without the binary should be refused" || t_ok "an image without the binary is refused"
fi

# ---- perf-gate.sh honours ROVARA_PERF_CMD when there is no target/ (it used to exit 2 silently on the failing ls)
PGD="$(mktemp -d "$WORK/pg.XXXXXX")"; mkdir -p "$PGD/scripts" "$PGD/perf"
cp "$HERE/scripts/perf-gate.sh" "$PGD/scripts/"; cp "$HERE/perf/measure.py" "$HERE/perf/matrix.py" "$HERE/perf/local_process_runner.py" "$PGD/perf/"
if ROVARA_PERF_PYTHON=/usr/bin/false ROVARA_PERF_CMD=/bin/true ROVARA_PERF_OUT="$PGD/o.json" "$PGD/scripts/perf-gate.sh" native >"$PGD/out.log" 2>&1; then t_bad "perf-gate with a failing python should fail"
elif grep -q "function runner did not start" "$PGD/out.log"; then t_ok "perf-gate uses ROVARA_PERF_CMD when target/ is missing"
else t_bad "perf-gate stopped before it used ROVARA_PERF_CMD"; cat "$PGD/out.log"; fi
# the RSS split reads /proc/<pid>/status (Linux); checked here on a fake /proc
mkdir -p "$PGD/proc/42"; printf 'Name:\tx\nVmRSS:\t  95000 kB\nRssAnon:\t  40000 kB\nRssFile:\t  54000 kB\nRssShmem:\t  1000 kB\n' > "$PGD/proc/42/status"
if [ "$(python3 -c "import sys;sys.path.insert(0,'$PGD/perf');import measure,json;print(json.dumps(measure.rss_detail_kib(42, '$PGD/proc'), sort_keys=True))")" = '{"RssAnon": 40000, "RssFile": 54000, "RssShmem": 1000, "VmRSS": 95000}' ]; then t_ok "RSS split parses /proc status"; else t_bad "RSS split"; fi
[ "$(python3 -c "import sys;sys.path.insert(0,'$PGD/perf');import measure;print(measure.rss_detail_kib(43, '$PGD/proc'))")" = None ] && t_ok "RSS split is None without /proc" || t_bad "RSS split without /proc"
rm -rf "$PGD/perf/__pycache__"
# the memory parsers, the private-memory choice and the gate verdicts (perf/test_measure.py)
if python3 -B "$HERE/perf/test_measure.py" >"$PGD/tm.log" 2>&1; then t_ok "perf/test_measure.py (private-memory gate)"; else t_bad "perf/test_measure.py"; tail -15 "$PGD/tm.log"; fi

echo "$PASS passed, $BAD failed"
[ "$BAD" = 0 ]
