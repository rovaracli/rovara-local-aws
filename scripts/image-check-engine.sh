#!/usr/bin/env bash
# Static gates for the engine image (AWS Emulator behind the Rovara front). They read files only: no container engine,
# no network, no build. The same spirit as scripts/image-check.sh, for image/Containerfile.engine.
#
#   scripts/image-check-engine.sh                      checks this repository
#   IMAGE_CHECK_ROOT=<dir> scripts/image-check-engine.sh   checks another tree with the same layout (the test uses this)
#
# Checks
#   Containerfile  every FROM pinned by digest; the final stage runs as a numeric non-zero USER, has exactly one EXPOSE
#                  (4566), no RUN, an exec-form ENTRYPOINT that starts the front, no ADD from a URL; the engine stage pins ONE
#                  version (never "latest"), downloads from downloads.aws.com, checks the sha256, checks AWS's key
#                  fingerprint (98BC F336 A3BE 53B7 34E9 67C5 2E5B F49B D940 F624), verifies the signature with gpg, and
#                  unpacks with dpkg-deb -x (never installs the package); no token, secret or password in ENV or ARG;
#                  no docker socket or engine client; labels; the licence files are copied
#   licences       image/engine-licenses/ holds NOTICE, CC0-1.0.txt and Apache-2.0.txt
#   catalog entry  image/catalog-entry.engine.json agrees with the Containerfile (user, port, health path, read-only root,
#                  /tmp tmpfs, arm64, memMiB 512) and keeps explicit placeholders for what the build fills in
#   front          front/ is standard library only (no require, no go.sum, no import with a dot in its first path
#                  element); the front starts the engine with telemetry off three ways and signature checks off; no
#                  InsecureSkipVerify; the front never dials anything but 127.0.0.1 (one dial site)
#   workflow       .github/workflows/image.yml builds this image (input image=engine, arm64 only, the engine build, its measure job,
#                  the crate SBOM and scan, one "index digest:" line, workflow_dispatch only, actions pinned)
#   files          no key-shaped string, no em dash, scripts parse (bash -n); hadolint and shellcheck run when installed
# Exit 0 only when every check passes.
# the patterns grepped for are single-quoted on purpose (they hold $ and braces to be matched literally)
# shellcheck disable=SC2016
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="${IMAGE_CHECK_ROOT:-$HERE}"
CF="$ROOT/image/Containerfile.engine"
CE="$ROOT/image/catalog-entry.engine.json"
LICDIR="$ROOT/image/engine-licenses"
FRONT="$ROOT/front"
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
FINAL="$(printf '%s\n' "$INSTR" | awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*FROM[[:space:]]/ { buf = "" } { buf = buf $0 "\n" } END { printf "%s", buf }')"
stage() { printf '%s\n' "$INSTR" | awk -v want="$1" 'BEGIN{IGNORECASE=1} /^[[:space:]]*FROM[[:space:]]/ { on = ($0 ~ ("[[:space:]]AS[[:space:]]+" want "([[:space:]]|$)")) } on { print }'; }

# 1. every FROM pinned by digest
aliases=" "
froms="$(upper FROM)"
[ -n "$froms" ] || fail "the Containerfile has no FROM"
n=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  n=$((n + 1))
  ref="$(printf '%s' "$line" | awk '{ for (i = 2; i <= NF; i++) if ($i !~ /^--/) { print $i; exit } }')"
  alias="$(printf '%s' "$line" | awk 'BEGIN{IGNORECASE=1} { for (i = 1; i < NF; i++) if (tolower($i) == "as") print $(i+1) }')"
  if [[ "$ref" =~ @sha256:[a-f0-9]{64}$ ]]; then ok "FROM $ref"
  elif [[ "$aliases" == *" $ref "* ]]; then ok "FROM $ref (an earlier stage)"
  else fail "FROM is not pinned by digest: $line"; fi
  [ -n "$alias" ] && aliases="$aliases$alias "
done <<<"$froms"
if [ "$n" = 3 ]; then ok "three stages (front, engine, final)"; else fail "expected three stages, found $n"; fi

# 2. the final stage
user="$(printf '%s\n' "$FINAL" | grep -Ei '^[[:space:]]*USER[[:space:]]' | tail -1 | awk '{print $2}')"
if [[ "$user" =~ ^([0-9]+)(:([0-9]+))?$ ]] && [ "${BASH_REMATCH[1]}" != 0 ] && { [ -z "${BASH_REMATCH[3]}" ] || [ "${BASH_REMATCH[3]}" != 0 ]; }; then
  ok "final stage runs as numeric non-root user $user"
else fail "the final stage must end with USER <uid>[:<gid>] (numeric, not 0); found '${user:-none}'"; fi
exposes="$(upper EXPOSE)"
nexp="$(printf '%s\n' "$exposes" | grep -c . || true)"
if [ "$nexp" = 1 ] && printf '%s' "$exposes" | grep -Eiq '^[[:space:]]*EXPOSE[[:space:]]+4566(/tcp)?[[:space:]]*$'; then ok "exactly one EXPOSE: 4566"
else fail "expected exactly one 'EXPOSE 4566', found: ${exposes:-none}"; fi
if printf '%s\n' "$FINAL" | grep -Eiq '^[[:space:]]*RUN[[:space:]]'; then fail "the final stage has a RUN instruction (it must need no shell)"; else ok "the final stage has no RUN"; fi
ep="$(printf '%s\n' "$FINAL" | grep -Ei '^[[:space:]]*ENTRYPOINT[[:space:]]' | tail -1)"
if printf '%s' "$ep" | grep -Eq '^[[:space:]]*[Ee][Nn][Tt][Rr][Yy][Pp][Oo][Ii][Nn][Tt][[:space:]]+\["/usr/local/bin/rovara-aws-front"\][[:space:]]*$'; then ok "ENTRYPOINT is the front, in exec form"; else fail "ENTRYPOINT must be [\"/usr/local/bin/rovara-aws-front\"]: ${ep:-none}"; fi
if printf '%s\n' "$INSTR" | grep -Eiq '^[[:space:]]*ADD[[:space:]].*https?://'; then fail "ADD from a URL"; fi
if printf '%s\n' "$FINAL" | grep -Eq 'ROVARA_AWS_ENGINE_BIN=/opt/aws-emulator/bin/aws-emulator'; then ok "the front is told where the engine is"; else fail "ENV ROVARA_AWS_ENGINE_BIN=/opt/aws-emulator/bin/aws-emulator is missing"; fi
if printf '%s\n' "$FINAL" | grep -Eq 'ROVARA_AWS_FRONT_WORKDIR=/tmp'; then ok "the front's work directory is /tmp (the one writable path)"; else fail "ENV ROVARA_AWS_FRONT_WORKDIR=/tmp is missing"; fi

# 3. the engine stage: one pinned version, signed and checked, unpacked and never installed
ENG="$(stage engine)"
ver="$(printf '%s\n' "$ENG" | sed -n 's/^[[:space:]]*ARG[[:space:]]\{1,\}ENGINE_VERSION=\([0-9][0-9.]*\)[[:space:]]*$/\1/p' | head -1)"
if [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then ok "engine version pinned: $ver"; else fail "ARG ENGINE_VERSION must be one x.y.z version"; fi
if printf '%s\n' "$INSTR" | grep -Eiq 'latest'; then fail "the Containerfile mentions \"latest\" (the engine is pinned to one version)"; else ok "no \"latest\""; fi
sha="$(printf '%s\n' "$ENG" | sed -n 's/^[[:space:]]*ARG[[:space:]]\{1,\}ENGINE_DEB_SHA256=\([a-f0-9]\{64\}\)[[:space:]]*$/\1/p' | head -1)"
if [ -n "$sha" ]; then ok "package sha256 pinned"; else fail "ARG ENGINE_DEB_SHA256 must be a 64 hex digit sha256"; fi
if printf '%s\n' "$ENG" | grep -Eq 'ARG[[:space:]]+ENGINE_SIGNER_FINGERPRINT=98BCF336A3BE53B734E967C52E5BF49BD940F624[[:space:]]*$'; then ok "AWS's key fingerprint is pinned (98BC F336 A3BE 53B7 34E9 67C5 2E5B F49B D940 F624)"; else fail "ARG ENGINE_SIGNER_FINGERPRINT must be 98BCF336A3BE53B734E967C52E5BF49BD940F624"; fi
if printf '%s\n' "$ENG" | grep -q 'ENGINE_BASE_URL=https://downloads.aws.com/aws-emulator/packages/aws-emulator/LTS[[:space:]]*$'; then ok "package URL is AWS's, over https"; else fail "ARG ENGINE_BASE_URL must be https://downloads.aws.com/aws-emulator/packages/aws-emulator/LTS"; fi
if printf '%s\n' "$ENG" | grep -Eq 'aws-emulator_\$\{ENGINE_VERSION\}-1_arm64\.deb'; then ok "the arm64 package at the pinned version is the one fetched"; else fail "the engine stage must fetch aws-emulator_\${ENGINE_VERSION}-1_arm64.deb"; fi
if printf '%s\n' "$ENG" | grep -Eq 'sha256sum -c'; then ok "the package's sha256 is checked"; else fail "the engine stage must run sha256sum -c"; fi
if printf '%s\n' "$ENG" | grep -Eq '\[ "\$\{found\}" = "\$\{ENGINE_SIGNER_FINGERPRINT\}" \]'; then ok "the key's fingerprint is compared before the signature is trusted"; else fail "the engine stage must compare the imported key's fingerprint with ENGINE_SIGNER_FINGERPRINT"; fi
if printf '%s\n' "$ENG" | grep -Fq 'gpg --batch --export "${ENGINE_SIGNER_FINGERPRINT}" > pinned-key.gpg' \
  && printf '%s\n' "$ENG" | grep -Fq 'gpgv --status-fd 3 --keyring ./pinned-key.gpg "${deb}.sig" "${deb}"' \
  && printf '%s\n' "$ENG" | grep -Fq '$2 == "VALIDSIG" && ($3 == f || $NF == f)'; then
  ok "the signature is verified with gpgv against the pinned key only, and VALIDSIG must carry the pinned fingerprint"
else fail "the engine stage must export the pinned key into its own keyring, verify with gpgv --keyring, and check VALIDSIG for the pinned fingerprint"; fi
if printf '%s\n' "$ENG" | grep -Eq 'gpg --batch --verify'; then fail "gpg --verify trusts every key in the keyring: use gpgv with the one pinned key"; fi
if printf '%s\n' "$ENG" | grep -Eq 'dpkg-deb -x '; then ok "the package is unpacked with dpkg-deb -x"; else fail "the engine stage must unpack with dpkg-deb -x"; fi
if printf '%s\n' "$INSTR" | grep -Eiq 'dpkg -i|dpkg --install|apt(-get)? install[^&;|]*\.deb|apt-get install -y \./'; then fail "the package is installed (its install scripts would run); unpack it instead"; else ok "the package is never installed"; fi
if printf '%s\n' "$ENG" | grep -Eq '"?/rootfs/opt/aws-emulator/bin/aws-emulator"? -v'; then ok "the unpacked engine reports the pinned version"; else fail "the engine stage must run aws-emulator -v and compare the version"; fi
# the front stage vets and tests before it builds, and builds a static binary
FRONT_STAGE="$(stage front)"
if printf '%s\n' "$FRONT_STAGE" | grep -Eq 'go vet \./\.\.\. && go test'; then ok "the front is vetted and tested in the build"; else fail "the front stage must run go vet and go test before the build"; fi
if printf '%s\n' "$FRONT_STAGE" | grep -Eq 'CGO_ENABLED=0'; then ok "the front is a static binary (CGO_ENABLED=0)"; else fail "the front must be built with CGO_ENABLED=0"; fi

# the engine binary is in the image once, at its own path: no symlink in the staged root (a symlink into /opt does not resolve in a
# COPY --from) and no second copy
if printf '%s\n' "$INSTR" | grep -Eq 'ln -s|COPY --from=engine /rootfs/usr/bin'; then fail "the Containerfile links or copies the engine to a second path: the front runs it by its absolute path under /opt/aws-emulator"; else ok "the engine is in the image once (/opt/aws-emulator/bin/aws-emulator)"; fi
if grep -q 'defaultEngineBin = "/opt/aws-emulator/bin/aws-emulator"' "$FRONT/config.go" 2>/dev/null; then ok "the front's default engine path is the image's"; else fail "front/config.go defaultEngineBin must be /opt/aws-emulator/bin/aws-emulator"; fi

# the front is built with a Go release that has the standard-library security fixes: 1.26.9 or newer (older 1.24.x and 1.26.x
# releases carry GO-2026-6612, a critical finding, and about twenty highs)
gov="$(printf '%s\n' "$INSTR" | sed -n 's|^FROM docker.io/library/golang:\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)-bookworm@sha256:[a-f0-9]\{64\} AS front$|\1|p' | head -1)"
if [[ "$gov" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] && { [ "${BASH_REMATCH[1]}" -gt 1 ] || [ "${BASH_REMATCH[2]}" -gt 26 ] || { [ "${BASH_REMATCH[2]}" -eq 26 ] && [ "${BASH_REMATCH[3]}" -ge 9 ]; }; }; then ok "the front is built with Go $gov (1.26.9 or newer)"; else fail "the front stage must use golang:<1.26.9 or newer>-bookworm pinned by digest; found '${gov:-none}'"; fi

# the scripts of the engine image never signal processes by name or pattern: only the PIDs they started themselves
for f in "$ROOT"/scripts/front-prove.sh "$ROOT"/scripts/front-query-prove.sh "$ROOT"/scripts/front-image-prove.sh "$ROOT"/scripts/image-build-test.sh; do
  if [ -f "$f" ] && grep -Eq '(^|[^[:alnum:]_])(pkill|killall)([^[:alnum:]_]|$)' "$f"; then fail "$(basename "$f") uses pkill or killall: kill only the PIDs the script started"; fi
done

# 4. no ENV/ARG carrying a token, secret, password or key
envs="$(printf '%s\n' "$INSTR" | grep -Ei '^[[:space:]]*(ENV|ARG)[[:space:]]' || true)"
if printf '%s\n' "$envs" | grep -Eiq '(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)'; then
  fail "an ENV or ARG names a token, secret, password or key: $(printf '%s\n' "$envs" | grep -Ei '(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)' | head -3 | tr '\n' ';')"
else ok "no ENV or ARG carries a token, secret, password or key"; fi

# 5. no docker socket, volume, DOCKER_HOST or engine client (registry names such as docker.io/library/... are fine)
if printf '%s\n' "$INSTR" | grep -Eiq 'docker\.sock|/var/run/docker|DOCKER_HOST|podman\.sock|containerd\.sock|^[[:space:]]*VOLUME[[:space:]]|docker-ce|docker-cli|apt-get install[^&;]*docker|podman|nerdctl|kubectl'; then
  fail "the Containerfile mentions a docker socket, a volume, DOCKER_HOST or a container-engine client"
else ok "no docker socket, volume, DOCKER_HOST or engine client"; fi

# 6. labels
for l in org.opencontainers.image.source org.opencontainers.image.revision org.opencontainers.image.licenses; do
  if printf '%s\n' "$FINAL" | grep -q "$l"; then ok "label $l"; else fail "missing label $l"; fi
done
if printf '%s\n' "$FINAL" | grep -q 'io.rovara.run.health-path="/_rovara/health"'; then ok "health path label /_rovara/health"; else fail "health-path label must be /_rovara/health"; fi
if printf '%s\n' "$INSTR" | grep -q '/__rovara/'; then fail "the double-underscore health path does not exist: the front serves /_rovara/health"; fi

# 7. licence files
copies="$(printf '%s\n' "$FINAL" | grep -Ei '^[[:space:]]*COPY[[:space:]]' || true)"
LIC=/usr/share/licenses/rovara-local-aws
if printf '%s\n' "$copies" | grep -Eq "COPY[[:space:]]+image/engine-licenses/[[:space:]]+$LIC/[[:space:]]*\$"; then ok "image/engine-licenses/ copied to $LIC/"; else fail "image/engine-licenses/ must be copied to $LIC/"; fi
if printf '%s\n' "$copies" | grep -Eq "THIRD_PARTY_LICENSES[[:space:]]+$LIC/THIRD_PARTY_LICENSES"; then ok "AWS Emulator's THIRD_PARTY_LICENSES copied"; else fail "AWS Emulator's THIRD_PARTY_LICENSES must be copied to $LIC/"; fi
if printf '%s\n' "$copies" | grep -Eq "GO-LICENSE[[:space:]]+$LIC/GO-LICENSE"; then ok "the Go licence copied"; else fail "the Go licence (GO-LICENSE) must be copied to $LIC/"; fi
for f in NOTICE CC0-1.0.txt Apache-2.0.txt; do
  if [ -s "$LICDIR/$f" ]; then ok "image/engine-licenses/$f"; else fail "image/engine-licenses/$f is missing or empty"; fi
done
if ! { [ -s "$LICDIR/CC0-1.0.txt" ] && grep -q 'CC0 1.0 Universal' "$LICDIR/CC0-1.0.txt"; }; then fail "CC0-1.0.txt is not the CC0 1.0 Universal text"; fi
if ! { [ -s "$LICDIR/Apache-2.0.txt" ] && grep -q 'Apache License' "$LICDIR/Apache-2.0.txt"; }; then fail "Apache-2.0.txt is not the Apache License"; fi
if [ -s "$LICDIR/NOTICE" ] && grep -qi 'not endorsed' "$LICDIR/NOTICE"; then ok "NOTICE says the image is not endorsed by AWS"; else fail "NOTICE must say the image is built on AWS Emulator and not endorsed by AWS"; fi

# 8. key-shaped strings (assembled so this file does not contain them), em dashes
FILES=("$CF" "$CE" "$LICDIR/NOTICE" "$ROOT/scripts/image-check-engine.sh" "$ROOT/scripts/front-prove.sh" "$ROOT/scripts/engine-library-sbom.sh" "$ROOT/scripts/image-build-test.sh" "$ROOT/scripts/engine-library-sbom-test.sh" "$ROOT/scripts/front-query-prove.sh" "$ROOT/scripts/front-image-prove.sh")
existing=(); for f in "${FILES[@]}"; do [ -f "$f" ] && existing+=("$f"); done
[ -d "$FRONT" ] && while IFS= read -r f; do existing+=("$f"); done < <(find "$FRONT" -type f \( -name '*.go' -o -name go.mod \))
KEYPAT="$(printf 'AKI%s|A3T%s|sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIV%s|xox[baprs]-[A-Za-z0-9-]{10,}' 'A[0-9A-Z]{16}' '[A-Z0-9]{17}' 'ATE KEY')"
if grep -Eqs -- "$KEYPAT" "${existing[@]}"; then fail "a key-shaped string in the image or front files"; else ok "no key-shaped string"; fi
if grep -qs $'\xe2\x80\x94' "${existing[@]}"; then fail "an em dash in the image or front files (use a hyphen)"; else ok "no em dash"; fi

# 9. the catalog entry agrees with the Containerfile
if [ -f "$CE" ] && command -v jq >/dev/null 2>&1; then
  jq -e . "$CE" >/dev/null 2>&1 || fail "$CE is not JSON"
  if eu="$(jq -r '.run.user' "$CE")"; [ "$eu" = "$user" ]; then ok "catalog user $eu = Containerfile USER"; else fail "catalog run.user $eu != Containerfile USER $user"; fi
  if [ "$(jq -c '.run.ports' "$CE")" = "[4566]" ]; then ok "catalog ports [4566]"; else fail "catalog run.ports must be [4566]"; fi
  if [ "$(jq -r '.health.kind + " " + (.health.port|tostring) + " " + .health.path' "$CE")" = "http 4566 /_rovara/health" ]; then ok "catalog health http 4566 /_rovara/health"; else fail "catalog health must be http 4566 /_rovara/health"; fi
  if [ "$(jq -r '.run.readOnlyRoot' "$CE")" = true ]; then ok "catalog readOnlyRoot true"; else fail "catalog run.readOnlyRoot must be true"; fi
  if [ "$(jq -r '[.run.tmpfs[].path] | sort | join(",")' "$CE")" = "/tmp" ]; then ok "catalog tmpfs is /tmp only"; else fail "catalog tmpfs must be /tmp only (the image's one writable path)"; fi
  if [ "$(jq -r '.image.platforms | sort | join(",")' "$CE")" = "linux/arm64" ]; then ok "catalog platforms: linux/arm64 only"; else fail "catalog platforms must be linux/arm64 (the engine package is the arm64 one)"; fi
  if [ "$(jq -r '.resources.memMiB' "$CE")" = 512 ]; then ok "catalog memMiB 512 (decision 106)"; else fail "catalog resources.memMiB must be 512"; fi
  if [ "$(jq -r '.id + " " + .image.repository' "$CE")" = "local-aws@r1 svc/local-aws" ]; then ok "catalog id local-aws@r1, repository svc/local-aws"; else fail "catalog id/repository must be local-aws@r1 and svc/local-aws"; fi
  for v in ROVARA_AWS_CONTROL_TOKEN QUARKUS_HTTP_HOST ROVARA_AWS_BASE_URL ROVARA_AWS_AUTH_PRESIGN_SECRET ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET; do
    jq -e --arg v "$v" '._notes.runEnv | has($v)' "$CE" >/dev/null 2>&1 || fail "catalog-entry.engine.json _notes.runEnv must document $v"
  done
  for k in '.image.digest' '.sbomRef' '.scan.scannedAt' '.scan.highOpen'; do
    jq -r "$k" "$CE" | grep -q '^PLACEHOLDER-' || fail "catalog $k must be an explicit PLACEHOLDER- value"
  done
  if [ "$(jq -r '.scan.criticalOpen' "$CE")" = 0 ]; then ok "catalog placeholders for digest, SBOM and scan"; else fail "catalog scan.criticalOpen must be 0"; fi
  printf '%s\n' "$INSTR" | grep -q "ENGINE_VERSION=$ver" || fail "version mismatch"
else
  fail "image/catalog-entry.engine.json is missing or jq is not installed"
fi

# 10. the front: standard library only, the engine locked down, one dial site
if [ -d "$FRONT" ]; then
  if grep -Eq '^[[:space:]]*require' "$FRONT/go.mod" || [ -e "$FRONT/go.sum" ]; then fail "front/ has a dependency (go.mod require or go.sum): the front is standard library only"; else ok "front/ is standard library only (no require, no go.sum)"; fi
  bad="$(cat "$FRONT"/*.go | awk '/^import \(/ {on=1; next} on && /^\)/ {on=0} on {print} /^import "/ {print}' | grep -Eo '"[^"]+"' | tr -d '"' | awk -F/ '$1 ~ /\./' | head -3)"
  if [ -z "$bad" ]; then ok "no import outside the standard library"; else fail "an import outside the standard library: $bad"; fi
  eng="$FRONT/engine.go"
  if grep -q '"EMULATOR_TELEMETRY=off"' "$eng" && grep -q '"-t", "off"' "$eng" && grep -q 'EMULATOR_CONFIG=' "$eng" && grep -q 'enabled = false' "$eng"; then ok "the engine starts with telemetry off three ways (-t off, EMULATOR_TELEMETRY=off, EMULATOR_CONFIG with enabled = false)"; else fail "front/engine.go must turn the engine's telemetry off three ways"; fi
  if grep -q '"-a", "off"' "$eng" && grep -q '"-b", "127.0.0.1"' "$eng"; then ok "the engine binds 127.0.0.1 with signature checks off"; else fail "front/engine.go must start the engine with -b 127.0.0.1 -a off"; fi
  if grep -rq 'InsecureSkipVerify' "$FRONT"/*.go; then fail "InsecureSkipVerify in the front"; else ok "no InsecureSkipVerify"; fi
  dials="$(grep -h 'DialContext\|net.Dial\|tls.Dial' "$FRONT"/*.go | grep -v '^[[:space:]]*//' | grep -vc '_test')"
  if [ "$dials" = 2 ]; then ok "one dial site (engine.go: the loopback port; a Dialer line plus its DialContext hook)"; else fail "expected exactly the engine client's dial hook, found $dials dial lines"; fi
  if grep -q 'RootCAs: pool' "$eng"; then ok "the front trusts only the engine's own CA"; else fail "the engine client must set RootCAs to the engine's CA pool"; fi
  if grep -q 'tcp4", target' "$eng"; then ok "every dial goes to 127.0.0.1:<engine port>"; else fail "the dial hook must always dial the engine's loopback port"; fi
else fail "front/ is missing"; fi

# 11. the workflow builds this image too, with the same artifact layout and the same log line
WF="$ROOT/.github/workflows/image.yml"
if [ -f "$WF" ]; then
  if grep -Eq '^      image:' "$WF" && awk '/^      image:/ {j=1} j && /- engine/ {f=1; exit} END {exit !f}' "$WF"; then ok "workflow: input image (fork or engine)"; else fail "the workflow needs an input 'image' with the options fork and engine"; fi
  if grep -q 'scripts/image-build.sh --engine --registry-ref' "$WF"; then ok "workflow: the engine build is image-build.sh --engine"; else fail "the workflow must build the engine image with scripts/image-build.sh --engine"; fi
  if grep -q 'scripts/image-check-engine.sh' "$WF"; then ok "workflow: the engine's static gates run"; else fail "the workflow must run scripts/image-check-engine.sh for the engine image"; fi
  if grep -Eq "^  measure-engine:" "$WF" && grep -q "inputs.image == 'engine'" "$WF" && grep -q 'front/tools/measure_front.py' "$WF" && grep -q 'image-extract-binary.sh --engine' "$WF"; then ok "workflow: measure-engine job (front and engine taken out of the layout, measure_front.py)"; else fail "the workflow needs a measure-engine job that extracts the front and engine and runs front/tools/measure_front.py"; fi
  if grep -q 'scripts/engine-library-sbom.sh' "$WF" && grep -q '"sbom:sbom-$a/sbom.spdx.json" --fail-on critical -o json --file "scan-library-$a.json"' "$WF"; then ok "workflow: one SBOM (image plus Rust crates) and the grype report over exactly it, under the names Cloud reads"; else fail "the workflow must merge the crate list into the image SBOM and scan that file with grype --fail-on critical as scan-library-<arch>.json"; fi
  if grep -q -- '"oci-dir:oci" --platform "$p" --fail-on critical' "$WF" && grep -q 'spdx-json=sbom-' "$WF"; then ok "workflow: image SBOM and scan are kept for the engine image too"; else fail "the workflow must keep the image SBOM and scan"; fi
  if grep -q 'sbom-\*/sbom.spdx.json' "$WF"; then ok "workflow: the library SBOM is uploaded"; else fail "the workflow must upload sbom-*/sbom.spdx.json"; fi
  if [ "$(grep -c 'echo "index digest: ' "$WF")" = 1 ]; then ok "workflow: one 'index digest:' log line"; else fail "the workflow must print the 'index digest:' line exactly once"; fi
  if grep -q 'engine image is linux/arm64 only' "$WF"; then ok "workflow: the engine is arm64 only"; else fail "the plan job must refuse a platform other than linux/arm64 for the engine"; fi
  if [ "$(awk '/^on:/ {on=1; next} on && /^[a-z]/ {exit} on && /^  [a-z_]+:/ {print $1}' "$WF" | tr -d '\n')" = "workflow_dispatch:" ]; then ok "workflow: workflow_dispatch is the only trigger"; else fail "workflow_dispatch must be the only trigger"; fi
  if grep -E '^\s+(- )?uses:' "$WF" | grep -vq '@[0-9a-f]\{40\}'; then fail "an action in the workflow is not pinned by commit sha"; else ok "workflow: every action is pinned by commit sha"; fi
else fail ".github/workflows/image.yml is missing"; fi
for f in "$ROOT/scripts/image-build.sh" "$ROOT/scripts/engine-library-sbom.sh" "$ROOT/scripts/image-extract-binary.sh"; do if bash -n "$f" 2>/dev/null; then ok "$(basename "$f") parses"; else fail "$(basename "$f") does not parse"; fi; done

# 12. scripts parse; linters when present
for f in "$ROOT"/scripts/image-check-engine.sh "$ROOT"/scripts/front-prove.sh "$ROOT"/scripts/image-build-test.sh; do
  [ -f "$f" ] || continue
  if bash -n "$f"; then ok "$(basename "$f") parses"; else fail "$(basename "$f") does not parse"; fi
done
if command -v hadolint >/dev/null 2>&1; then
  if out="$(hadolint "$CF" 2>&1)"; then ok "hadolint"; else fail "hadolint reports problems"; printf '%s\n' "$out"; fi
else echo "skip: hadolint is not installed"; fi
# Lint at the severity scripts/image-check.sh uses for the older image scripts (warning), and at every severity for the
# scripts of the engine image, which are clean. The findings are printed when it fails.
if command -v shellcheck >/dev/null 2>&1; then
  old=(); new=()
  for f in "$ROOT"/scripts/image-*.sh; do
    case "$(basename "$f")" in image-check-engine.sh|image-check-engine-test.sh|image-build-test.sh) new+=("$f") ;; *) old+=("$f") ;; esac
  done
  for f in "$ROOT"/scripts/engine-library-sbom.sh "$ROOT"/scripts/engine-library-sbom-test.sh "$ROOT"/scripts/front-prove.sh "$ROOT"/scripts/front-query-prove.sh "$ROOT"/scripts/front-image-prove.sh; do [ -f "$f" ] && new+=("$f"); done
  if out="$(shellcheck -S warning "${old[@]}" 2>&1)"; then ok "shellcheck -S warning on the image scripts"; else fail "shellcheck reports findings (warning level) on the image scripts"; printf '%s\n' "$out"; fi
  if out="$(shellcheck "${new[@]}" 2>&1)"; then ok "shellcheck (all severities) on the engine image's scripts"; else fail "shellcheck reports findings on the engine image's scripts"; printf '%s\n' "$out"; fi
else echo "skip: shellcheck is not installed"; fi

[ "$FAIL" = 0 ] && echo "image-check-engine: all checks passed" || echo "image-check-engine: FAILED"
exit "$FAIL"
