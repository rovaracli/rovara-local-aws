#!/usr/bin/env bash
# Static gates for the catalog image. They read files only: no container engine, no network, no build.
#
#   scripts/image-check.sh            checks this repository
#   IMAGE_CHECK_ROOT=<dir> scripts/image-check.sh   checks another tree with the same layout (the tests use this)
#
# Checks
#   Containerfile  every FROM is pinned by digest (a stage alias may be reused); the final stage runs as a numeric,
#                  non-zero USER; exactly one EXPOSE, the API port 4566; the licence files are copied to
#                  /usr/share/licenses/rovara-local-aws/; the final stage has no RUN (no shell needed to run it) and
#                  the entrypoint is in exec form; no ADD from a URL; no ENV/ARG that carries a token, secret or password;
#                  no VOLUME, docker socket, DOCKER_HOST or container-engine client; no upstream name; the health-path label
#   catalog entry  image/catalog-entry.json agrees with the Containerfile (user, port, health path, read-only root, /tmp
#                  tmpfs, both platforms) and holds explicit placeholders for the fields the build fills in
#   workflow       .github/workflows/image.yml has workflow_dispatch as its only trigger and every action is pinned by sha
#   files          none of the image files holds a key-shaped string; the scripts parse (bash -n)
#   optional       hadolint and shellcheck run when they are installed; nothing is downloaded
# Exit 0 only when every check passes.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="${IMAGE_CHECK_ROOT:-$HERE}"
CF="$ROOT/image/Containerfile"
CE="$ROOT/image/catalog-entry.json"
WF="$ROOT/.github/workflows/image.yml"
FAIL=0
fail() { echo "FAIL: $*"; FAIL=1; }
ok() { echo "ok:   $*"; }

[ -f "$CF" ] || { echo "FAIL: $CF is missing"; exit 1; }

# The Containerfile as instructions: comments dropped, continuation lines joined, one instruction per line.
INSTR="$(awk '
  /^[[:space:]]*#/ { next }
  { line = $0
    if (cont) { sub(/^[[:space:]]+/, "", line); buf = buf " " line } else { buf = line }
    if (buf ~ /\\[[:space:]]*$/) { sub(/\\[[:space:]]*$/, "", buf); cont = 1; next }
    cont = 0
    if (buf ~ /[^[:space:]]/) print buf
    buf = "" }
  END { if (cont && buf != "") print buf }' "$CF")"
upper() { printf '%s\n' "$INSTR" | grep -Ei "^[[:space:]]*$1([[:space:]]|\$)" || true; }
# The final stage: everything after the last FROM.
FINAL="$(printf '%s\n' "$INSTR" | awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*FROM[[:space:]]/ { buf = "" } { buf = buf $0 "\n" } END { printf "%s", buf }')"

# 1. every FROM pinned by digest
aliases=" "
froms="$(upper FROM)"
[ -n "$froms" ] || fail "the Containerfile has no FROM"
while IFS= read -r line; do
  [ -n "$line" ] || continue
  ref="$(printf '%s' "$line" | awk '{ for (i = 2; i <= NF; i++) if ($i !~ /^--/) { print $i; exit } }')"
  alias="$(printf '%s' "$line" | awk 'BEGIN{IGNORECASE=1} { for (i = 1; i < NF; i++) if (tolower($i) == "as") print $(i+1) }')"
  if [ "$ref" = scratch ]; then ok "FROM scratch (an export-only stage, nothing is pulled)"
  elif [[ "$ref" =~ @sha256:[a-f0-9]{64}$ ]]; then ok "FROM $ref"
  elif [[ "$aliases" == *" $ref "* ]]; then ok "FROM $ref (an earlier stage)"
  else fail "FROM is not pinned by digest: $line"; fi
  [ -n "$alias" ] && aliases="$aliases$alias "
done <<<"$froms"

# the Java dependency list is built and exported for the scan
if printf '%s\n' "$INSTR" | grep -Eq 'cyclonedx-maven-plugin:[0-9]+\.[0-9]+\.[0-9]+:makeBom' && printf '%s\n' "$INSTR" | grep -Eiq '^FROM scratch AS sbom'; then ok "a pinned CycloneDX list of the Java dependencies is built and exported (stage sbom)"; else fail "the Containerfile must build a CycloneDX list of the Java dependencies (pinned plugin version) and export it from a 'FROM scratch AS sbom' stage"; fi

# the Mandrel-only inlining option that breaks the aarch64 native build stays off (see the Containerfile comment)
if printf '%s\n' "$INSTR" | grep -q 'NATIVE_BUILD_ARGS="-H:-AOTSingleCallsiteInline"'; then ok "single-callsite inlining is switched off for the Mandrel build (aarch64 ADR range)"; else fail "the builder RUN must pass NATIVE_BUILD_ARGS=\"-H:-AOTSingleCallsiteInline\" (Mandrel's default inlining overflows the aarch64 ADR range)"; fi

# 2. the final stage runs as a numeric non-root user
user="$(printf '%s\n' "$FINAL" | grep -Ei '^[[:space:]]*USER[[:space:]]' | tail -1 | awk '{print $2}')"
if [[ "$user" =~ ^([0-9]+)(:([0-9]+))?$ ]] && [ "${BASH_REMATCH[1]}" != 0 ] && { [ -z "${BASH_REMATCH[3]}" ] || [ "${BASH_REMATCH[3]}" != 0 ]; }; then
  ok "final stage runs as numeric non-root user $user"
else fail "the final stage must end with USER <uid>[:<gid>] (numeric, not 0); found '${user:-none}'"; fi

# 3. exactly one EXPOSE, the API port
exposes="$(upper EXPOSE)"
nexp="$(printf '%s\n' "$exposes" | grep -c . || true)"
if [ "$nexp" = 1 ] && printf '%s' "$exposes" | grep -Eiq '^[[:space:]]*EXPOSE[[:space:]]+4566(/tcp)?[[:space:]]*$'; then ok "exactly one EXPOSE: 4566"
else fail "expected exactly one 'EXPOSE 4566', found: ${exposes:-none}"; fi

# 4. licence files at the right path, in the final stage
LIC=/usr/share/licenses/rovara-local-aws
copies="$(printf '%s\n' "$FINAL" | grep -Ei '^[[:space:]]*COPY[[:space:]]' | grep -v -- '--from=' || true)"
if printf '%s\n' "$copies" | grep -Eq "[[:space:]]$LIC/?[[:space:]]*\$"; then ok "LICENSE NOTICE THIRD-PARTY-NOTICES.txt copied to $LIC/"; else fail "no COPY of the licence files to $LIC/"; fi
printf '%s\n' "$copies" | grep -Eq "COPY[[:space:]]+(--[a-z]+=[^[:space:]]+[[:space:]]+)*licenses/[[:space:]]+$LIC/licenses/?[[:space:]]*\$" \
  && ok "licenses/ copied to $LIC/licenses/" || fail "licenses/ is not copied to $LIC/licenses/"
# the three files must be named in ONE copy that ends at the licence directory
printf '%s\n' "$copies" | grep -Eq "COPY[[:space:]]+(--[a-z]+=[^[:space:]]+[[:space:]]+)*LICENSE[[:space:]]+NOTICE[[:space:]]+THIRD-PARTY-NOTICES\.txt[[:space:]]+$LIC/?[[:space:]]*\$" \
  || fail "LICENSE, NOTICE and THIRD-PARTY-NOTICES.txt must be one COPY ending at $LIC/"

# 5. no RUN in the final stage; exec-form entrypoint; no URL ADD
if printf '%s\n' "$FINAL" | grep -Eiq '^[[:space:]]*RUN[[:space:]]'; then fail "the final stage has a RUN instruction (it must need no shell)"; else ok "the final stage has no RUN"; fi
ep="$(printf '%s\n' "$FINAL" | grep -Ei '^[[:space:]]*ENTRYPOINT[[:space:]]' | tail -1)"
if printf '%s' "$ep" | grep -Eq '^[[:space:]]*[Ee][Nn][Tt][Rr][Yy][Pp][Oo][Ii][Nn][Tt][[:space:]]+\["'; then ok "ENTRYPOINT is in exec form"; else fail "ENTRYPOINT must be in exec form: ${ep:-none}"; fi
# the native binary's maximum heap is set explicitly (an uncapped heap is a share of the container limit and can be OOM-killed with the tmpfs)
if printf '%s' "$ep" | grep -Eq '"-Xmx[0-9]+m"'; then ok "ENTRYPOINT caps the heap (-Xmx)"; else fail "ENTRYPOINT must pass an explicit -Xmx<N>m heap cap: ${ep:-none}"; fi
if printf '%s\n' "$INSTR" | grep -Eiq '^[[:space:]]*ADD[[:space:]].*https?://'; then fail "ADD from a URL"; fi

# 6. no ENV/ARG carrying a token, secret, password or key; the control token is never named there
envs="$(printf '%s\n' "$INSTR" | grep -Ei '^[[:space:]]*(ENV|ARG)[[:space:]]' || true)"
if printf '%s\n' "$envs" | grep -Eiq '(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)'; then
  fail "an ENV or ARG names a token, secret, password or key: $(printf '%s\n' "$envs" | grep -Ei '(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)' | head -3 | tr '\n' ';')"
else ok "no ENV or ARG carries a token, secret, password or key"; fi

# 7. no docker socket, volume, DOCKER_HOST or engine client
if printf '%s\n' "$INSTR" | grep -Eiq 'docker\.sock|/var/run/docker|DOCKER_HOST|podman\.sock|containerd\.sock|^[[:space:]]*VOLUME[[:space:]]|docker-ce|docker-cli|docker\.io|podman|nerdctl|kubectl'; then
  fail "the Containerfile mentions a docker socket, a volume, DOCKER_HOST or a container-engine client: $(printf '%s\n' "$INSTR" | grep -Ei 'docker\.sock|/var/run/docker|DOCKER_HOST|podman\.sock|containerd\.sock|^[[:space:]]*VOLUME[[:space:]]|docker-ce|docker-cli|docker\.io|podman|nerdctl|kubectl' | head -3 | tr '\n' ';')"
else ok "no docker socket, volume, DOCKER_HOST or engine client"; fi

# 8. labels: source, revision, licences; the health-path label matches the API
for l in org.opencontainers.image.source org.opencontainers.image.revision org.opencontainers.image.licenses; do
  printf '%s\n' "$FINAL" | grep -q "$l" && ok "label $l" || fail "missing label $l"
done
printf '%s\n' "$FINAL" | grep -q 'io.rovara.run.health-path="/_rovara/health"' && ok "health path label /_rovara/health" || fail "health-path label must be /_rovara/health"
if printf '%s\n' "$INSTR" | grep -q '/__rovara/'; then fail "the double-underscore health path does not exist: the emulator serves /_rovara/health"; fi

# 9. no upstream name (reuse the tree script; for another root, only the image files)
IMAGE_FILES=("$CF" "$CE" "$WF" "$ROOT/.dockerignore" "$ROOT/scripts/image-check.sh" "$ROOT/scripts/image-build.sh" "$ROOT/scripts/image-merge.sh")
existing=(); for f in "${IMAGE_FILES[@]}"; do [ -f "$f" ] && existing+=("$f"); done
NAMES_OUT="$(mktemp)"
if "$HERE/scripts/no-upstream-names.sh" --files "${existing[@]}" >"$NAMES_OUT" 2>&1; then ok "no upstream name in the image files"; else fail "upstream name in the image files: $(tr '\n' ' ' <"$NAMES_OUT")"; fi
rm -f "$NAMES_OUT"
if [ "$ROOT" = "$HERE" ]; then
  if "$HERE/scripts/no-upstream-names.sh" >/dev/null 2>&1; then ok "scripts/no-upstream-names.sh (whole tree)"; else fail "scripts/no-upstream-names.sh fails on the tree"; fi
fi

# 10. key-shaped strings (patterns are assembled so this file does not contain them)
KEYPAT="$(printf 'AKI%s|A3T%s|sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIV%s|xox[baprs]-[A-Za-z0-9-]{10,}' 'A[0-9A-Z]{16}' '[A-Z0-9]{17}' 'ATE KEY')"
if grep -Eqs -- "$KEYPAT" "${existing[@]}"; then fail "a key-shaped string in the image files"; else ok "no key-shaped string in the image files"; fi

# 11. the catalog entry agrees with the Containerfile
if [ -f "$CE" ] && command -v jq >/dev/null 2>&1; then
  jq -e . "$CE" >/dev/null 2>&1 || fail "$CE is not JSON"
  eu="$(jq -r '.run.user' "$CE")"; [ "$eu" = "$user" ] && ok "catalog user $eu = Containerfile USER" || fail "catalog run.user $eu != Containerfile USER $user"
  [ "$(jq -c '.run.ports' "$CE")" = "[4566]" ] && ok "catalog ports [4566]" || fail "catalog run.ports must be [4566]"
  [ "$(jq -r '.health.kind + " " + (.health.port|tostring) + " " + .health.path' "$CE")" = "http 4566 /_rovara/health" ] && ok "catalog health http 4566 /_rovara/health" || fail "catalog health must be http 4566 /_rovara/health"
  [ "$(jq -r '.run.readOnlyRoot' "$CE")" = true ] && ok "catalog readOnlyRoot true" || fail "catalog run.readOnlyRoot must be true"
  [ "$(jq -r '[.run.tmpfs[].path] | sort | join(",")' "$CE")" = "/tmp" ] && ok "catalog tmpfs is /tmp only" || fail "catalog tmpfs must be /tmp only (the image's one writable path)"
  case "$(jq -r '.image.platforms | sort | join(",")' "$CE")" in
    linux/arm64) ok "catalog platforms: linux/arm64 only (the first image)" ;;
    linux/amd64,linux/arm64) ok "catalog platforms: amd64 + arm64" ;;
    *) fail "catalog platforms must be linux/arm64 (the first image) or exactly linux/amd64 and linux/arm64" ;;
  esac
  for v in ROVARA_AWS_CONTROL_TOKEN QUARKUS_HTTP_HOST ROVARA_AWS_BASE_URL ROVARA_AWS_AUTH_PRESIGN_SECRET ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET; do
    jq -e --arg v "$v" '._notes.runEnv | has($v)' "$CE" >/dev/null 2>&1 || fail "catalog-entry.json _notes.runEnv must document $v"
  done
  [ "$(jq -r '.id' "$CE")" = "local-aws@r1" ] && [ "$(jq -r '.image.repository' "$CE")" = "svc/local-aws" ] && ok "catalog id and repository" || fail "catalog id/repository must be local-aws@r1 and svc/local-aws"
  for k in '.image.digest' '.sbomRef' '.scan.scannedAt' '.scan.highOpen'; do
    jq -r "$k" "$CE" | grep -q '^PLACEHOLDER-' || fail "catalog $k must be an explicit PLACEHOLDER- value"
  done
  [ "$(jq -r '.scan.criticalOpen' "$CE")" = 0 ] && ok "catalog placeholders for digest, SBOM and scan" || fail "catalog scan.criticalOpen must be 0"
else
  fail "image/catalog-entry.json is missing or jq is not installed"
fi

# 12. the workflow: manual only, actions pinned
if [ -f "$WF" ]; then
  trig="$(awk '/^on:/ {on=1; next} on && /^[^[:space:]]/ {on=0} on && /^  [a-z_]+:/ {print $1}' "$WF" | tr -d ':' | sort | tr '\n' ' ')"
  [ "$trig" = "workflow_dispatch " ] && ok "workflow trigger: workflow_dispatch only" || fail "workflow triggers must be workflow_dispatch only, found: ${trig:-none}"
  bad="$(grep -E '^\s*-?\s*uses:' "$WF" | grep -Ev 'uses:[[:space:]]+[^@[:space:]]+(/[^@[:space:]]+)*@[a-f0-9]{40}([[:space:]]|$)' || true)"
  [ -z "$bad" ] && ok "every action is pinned by commit sha" || fail "an action is not pinned by sha: $bad"
  # id-token: write only in the sign job (the one job that signs); the signer is required before any AWS call
  nid="$(grep -cE '^[[:space:]]+id-token:[[:space:]]*write' "$WF")"
  signline="$(grep -n '^  sign:' "$WF" | head -1 | cut -d: -f1)"
  idline="$(grep -nE '^[[:space:]]+id-token:[[:space:]]*write' "$WF" | head -1 | cut -d: -f1)"
  if [ "$nid" = 1 ] && [ -n "$signline" ] && [ -n "$idline" ] && [ "$idline" -gt "$signline" ]; then ok "id-token: write only in the sign job"; else fail "id-token: write must appear once, in the sign job"; fi
  reqline="$(grep -n 'Require a signer' "$WF" | head -1 | cut -d: -f1)"
  awsline="$(grep -n 'aws-actions/configure-aws-credentials@' "$WF" | head -1 | cut -d: -f1)"
  if [ -n "$reqline" ] && [ -n "$awsline" ] && [ "$reqline" -lt "$awsline" ] && grep -q 'IMAGE_SIGNING_ROLE_ARN' "$WF"; then ok "the sign job requires its signer variables before the AWS credential step"; else fail "the sign job must check IMAGE_SIGNING_ROLE_ARN before configure-aws-credentials"; fi
  # unsigned artifacts live one day; only the signed bundle (image-release) may live longer
  badret="$(awk '/uses: actions\/upload-artifact@/ {u=1; n=""} u && /name:/ {n=$2} u && /retention-days:/ {if (n != "image-release" && n !~ /^perf-/ && $2 > 1) print n ":" $2; u=0}' "$WF")"
  [ -z "$badret" ] && ok "unsigned artifacts are kept for 1 day" || fail "unsigned artifacts must have retention-days 1: $badret"
  # the long-lived signed artifact lists its files one by one and never the image layout
  rel="$(awk '/name: image-release/ {r=1} r && /path: \|/ {p=1; next} r && p && /^[[:space:]]+\$\{\{/ {print $0; next} r && p && !/^[[:space:]]+\$\{\{/ {exit}' "$WF")"
  if [ -n "$rel" ] && ! printf '%s\n' "$rel" | grep -Eq '/out$|/out/oci|/out/layout|/out/\*$' \
     && printf '%s\n' "$rel" | grep -q 'statement.sig' && printf '%s\n' "$rel" | grep -q 'statement.json'; then ok "image-release holds the signed statement and evidence, not the image layout"; else fail "image-release must list statement.json, statement.sig, SBOMs, scans and digest files one by one, and not the whole out dir or oci/"; fi
  # the speed gate runs on the shipped binary and gates the signing job
  if grep -q 'scripts/image-extract-binary.sh' "$WF" && grep -q 'scripts/perf-gate.sh native' "$WF" && grep -Eq 'needs: \[assemble, measure(, measure-engine)?\]' "$WF"; then ok "measure job: speed gate on the shipped binary; sign needs measure"; else fail "the workflow needs a measure job (extract the binary, perf-gate.sh native) and sign must need [assemble, measure]"; fi
  # platforms: a choice input (arm64 default, amd64, both) feeds a plan job that emits the matrix; no QEMU path
  if grep -q 'platforms:' "$WF" && grep -q 'default: "linux/arm64"' "$WF" && grep -q -- '- both' "$WF" && grep -q 'fromJSON(needs.plan.outputs.matrix)' "$WF" \
     && grep -q 'ARM64_RUNNER:-ubuntu-24.04-arm' "$WF" && ! grep -qi 'setup-qemu' "$WF"; then ok "platforms input -> plan job -> matrix; arm64 on ubuntu-24.04-arm unless ARM64_RUNNER; no QEMU"; else fail "the workflow needs a platforms choice input (default linux/arm64), a plan job emitting the matrix, ARM64_RUNNER over ubuntu-24.04-arm, and no QEMU"; fi
  # signing is opt-in; unsigned results say so
  signif="$(awk '/^  sign:/ {j=1} j && /^    if:/ {print; exit}' "$WF")"
  if grep -Eq '^      sign:' "$WF" && awk '/^      sign:/ {j=1} j && /default: false/ {f=1; exit} END {exit !f}' "$WF" && printf '%s' "$signif" | grep -q 'inputs.sign' && grep -q 'UNSIGNED: not for the catalog' "$WF"; then ok "sign is an opt-in input (default false); the sign job is skipped without it; the summary says UNSIGNED"; else fail "the workflow needs a boolean input 'sign' (default false), 'if: inputs.sign' on the sign job, and an 'UNSIGNED: not for the catalog' summary"; fi
  # the native-image builder heap is capped
  if grep -q 'NATIVE_IMAGE_XMX' "$WF" && grep -q '^ARG NATIVE_IMAGE_XMX=' "$CF"; then ok "the native-image heap cap is set (NATIVE_IMAGE_XMX)"; else fail "NATIVE_IMAGE_XMX must be a Containerfile build arg and set by the workflow"; fi
  # both scans: the image and the Java libraries inside the binary
  if grep -q 'oci-dir:oci' "$WF" && grep -q 'sbom:sbom-' "$WF" && [ "$(grep -c -- '--fail-on critical' "$WF")" -ge 2 ]; then ok "the workflow scans the image and the Java dependency list, failing on critical"; else fail "the workflow must scan oci-dir and sbom: with --fail-on critical"; fi
  # the signing behaviour itself (fail-closed, statement) is covered by the control-path and run-contract tests only for
  # the emulator; the workflow is never run here, so its signing steps are reviewed, not tested.
else
  fail "$WF is missing"
fi

# The closed-by-default behaviour is NOT checked here by reading strings. It is exercised over real HTTP by these:
for f in src/test/java/ai/rovara/localaws/rovara/RovaraControlClosedIntegrationTest.java src/test/java/ai/rovara/localaws/rovara/RovaraControlTokenIntegrationTest.java scripts/control-check.sh; do
  [ -f "$ROOT/$f" ] && ok "present: $f (runs the real stack/binary with no token, a token and the dev switch)" || fail "missing: $f"
done

# 13. scripts parse; optional linters
for s in image-check.sh image-build.sh image-merge.sh image-extract-binary.sh image-check-test.sh control-check.sh; do
  [ -f "$ROOT/scripts/$s" ] && { bash -n "$ROOT/scripts/$s" 2>/dev/null && ok "bash -n $s" || fail "$s does not parse"; }
done
if command -v hadolint >/dev/null 2>&1; then
  hadolint "$CF" && ok "hadolint" || fail "hadolint reported findings"
else echo "skip: hadolint is not installed"; fi
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S warning "$ROOT"/scripts/image-*.sh && ok "shellcheck" || fail "shellcheck reported findings"
else echo "skip: shellcheck is not installed"; fi

[ "$FAIL" = 0 ] && echo "IMAGE CHECK OK" || echo "IMAGE CHECK FAILED"
exit "$FAIL"
