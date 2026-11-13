#!/usr/bin/env bash
# Static gates for the two small Go images of catalog revision 7 (0.5.19): the function agent and the model stand-in. They read files only: no container
# engine, no network, no build. The same spirit as scripts/image-check-engine.sh.
#
#   scripts/image-check-go.sh function-agent|model-stand-in
#   IMAGE_CHECK_ROOT=<dir> scripts/image-check-go.sh <target>   checks another tree with the same layout (the test uses this)
#
# Checks
#   Containerfile  every FROM pinned by digest (FROM scratch and an earlier stage alias excepted); the Go build image is golang:<x.y.z> at 1.26.9 or newer
#                  (GO-2026-6612 is fixed there) with GOTOOLCHAIN=local; the build stage vets and tests the program; the final stage has no RUN, a numeric
#                  non-zero USER, an exec-form ENTRYPOINT, no ADD; no token, secret or password in ENV or ARG; no docker socket or engine client
#   context        go.mod has no requirement and there is no go.sum (standard library only; no import path with a dot in its first element)
#   target         function-agent: the final stage is FROM scratch and copies exactly /agent (and the Go licence), one FROM scratch stage
#                  model-stand-in: the final stage is the distroless static nonroot base, EXPOSE 8080, runs as 65532:65532
#   workflow       .github/workflows/image.yml builds it (input image lists the target; the build step passes --target), workflow_dispatch is the only
#                  trigger, every action is pinned by commit sha, the measure jobs do not run for it
#   files          no key-shaped string and no em dash in the files checked here; the scripts parse (bash -n)
# Exit 0 only when every check passes.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="${IMAGE_CHECK_ROOT:-$HERE}"
TARGET="${1:-}"
case "$TARGET" in
  function-agent) CTX="$ROOT/runner/agent" ;;
  model-stand-in) CTX="$ROOT/model-stand-in" ;;
  *) echo "usage: image-check-go.sh function-agent|model-stand-in" >&2; exit 2 ;;
esac
CF="$CTX/Containerfile"
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
FINAL="$(printf '%s\n' "$INSTR" | awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*FROM[[:space:]]/ { buf = "" } { buf = buf $0 "\n" } END { printf "%s", buf }')"
BUILD="$(printf '%s\n' "$INSTR" | awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*FROM[[:space:]]/ { n++ } n == 1 { print }')"

# 1. every FROM pinned by digest; two stages
aliases=" "; n=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  n=$((n + 1))
  ref="$(printf '%s' "$line" | awk '{ for (i = 2; i <= NF; i++) if ($i !~ /^--/) { print $i; exit } }')"
  alias="$(printf '%s' "$line" | awk 'BEGIN{IGNORECASE=1} { for (i = 1; i < NF; i++) if (tolower($i) == "as") print $(i+1) }')"
  if [[ "$ref" =~ @sha256:[a-f0-9]{64}$ ]]; then ok "FROM $ref"
  elif [ "$ref" = scratch ]; then ok "FROM scratch"
  elif [[ "$aliases" == *" $ref "* ]]; then ok "FROM $ref (an earlier stage)"
  else fail "FROM is not pinned by digest: $line"; fi
  [ -n "$alias" ] && aliases="$aliases$alias "
done < <(printf '%s\n' "$INSTR" | grep -Ei '^[[:space:]]*FROM[[:space:]]')
[ "$n" = 2 ] && ok "two stages (build, final)" || fail "expected two stages, found $n"

# 2. the Go floor and no toolchain download
atleast() { awk -v v="$1" 'BEGIN { split(v, a, "."); if (a[1] != 1) exit (a[1] > 1 ? 0 : 1); if (a[2] != 26) exit (a[2] > 26 ? 0 : 1); exit (a[3] >= 9 ? 0 : 1) }'; }
gover="$(printf '%s\n' "$BUILD" | sed -n 's#^FROM [^ ]*/golang:\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)-bookworm@sha256:[a-f0-9]\{64\} AS build$#\1#p' | head -1)"
if [ -n "$gover" ] && atleast "$gover"; then ok "build image is golang $gover (1.26.9 or newer)"; else fail "the build stage must be golang:<x.y.z>-bookworm by digest, x.y.z at 1.26.9 or newer (found '${gover:-none}')"; fi
printf '%s\n' "$BUILD" | grep -q 'GOTOOLCHAIN=local' && ok "GOTOOLCHAIN=local" || fail "the build stage must set GOTOOLCHAIN=local"
printf '%s\n' "$BUILD" | grep -Eq '^RUN go vet \./\.\.\. && go test -count=1 \./\.\.\.$' && ok "the build vets and tests before it builds" || fail "the build stage must RUN go vet ./... && go test -count=1 ./..."
printf '%s\n' "$BUILD" | grep -q 'CGO_ENABLED=0' && ok "no cgo (a static binary)" || fail "the build stage must set CGO_ENABLED=0"
directive="$(sed -n 's/^go \([0-9][0-9.]*\)$/\1/p' "$CTX/go.mod" | head -1)"
[ -n "$directive" ] && ok "go.mod says go $directive" || fail "go.mod has no go directive"
if grep -Eq '^[[:space:]]*require\b' "$CTX/go.mod" || [ -e "$CTX/go.sum" ]; then fail "go.mod has a requirement or there is a go.sum (standard library only)"; else ok "standard library only (no require, no go.sum)"; fi
if [ -n "$(grep -rhoE '^[[:space:]]+([A-Za-z_]+[[:space:]]+)?"[a-z][^"]*\.[^"/]*/[^"]*"$' --include=*.go "$CTX" 2>/dev/null)" ]; then fail "a Go file imports a path outside the standard library"; else ok "no import outside the standard library"; fi

# 3. the final stage
if printf '%s\n' "$FINAL" | grep -Eiq '^[[:space:]]*RUN[[:space:]]'; then fail "the final stage has a RUN instruction (it must need no shell)"; else ok "the final stage has no RUN"; fi
user="$(printf '%s\n' "$FINAL" | grep -Ei '^[[:space:]]*USER[[:space:]]' | tail -1 | awk '{print $2}')"
if [[ "$user" =~ ^([0-9]+)(:([0-9]+))?$ ]] && [ "${BASH_REMATCH[1]}" != 0 ] && { [ -z "${BASH_REMATCH[3]}" ] || [ "${BASH_REMATCH[3]}" != 0 ]; }; then ok "final stage runs as numeric non-root user $user"
else fail "the final stage must end with USER <uid>[:<gid>] (numeric, not 0); found '${user:-none}'"; fi
printf '%s\n' "$FINAL" | grep -Eq '^ENTRYPOINT \[".*"\]$' && ok "exec-form ENTRYPOINT" || fail "the final stage needs an exec-form ENTRYPOINT"
if printf '%s\n' "$INSTR" | grep -Eiq '^[[:space:]]*ADD[[:space:]]'; then fail "the Containerfile uses ADD"; else ok "no ADD"; fi
if printf '%s\n' "$INSTR" | grep -Ei '^[[:space:]]*(ENV|ARG)[[:space:]]' | grep -Eiq '(token|secret|passw|apikey|api_key|credential)'; then fail "an ENV or ARG names a token, secret or password"; else ok "no secret-looking ENV or ARG"; fi
if printf '%s\n' "$INSTR" | grep -Eiq 'docker\.sock|DOCKER_HOST|docker-cli|docker\.io/library/docker'; then fail "the Containerfile mentions a docker socket or client"; else ok "no docker socket or client"; fi

# 4. per target
case "$TARGET" in
  function-agent)
    printf '%s\n' "$FINAL" | head -1 | grep -Eiq '^FROM scratch( AS [a-z]+)?$' && ok "the final stage is FROM scratch" || fail "the function agent's final stage must be FROM scratch"
    copies="$(printf '%s\n' "$FINAL" | grep -Ei '^[[:space:]]*COPY[[:space:]]' | awk '{print $NF}' | sort | tr '\n' ' ')"
    [ "$copies" = "/agent /licenses/GO-LICENSE " ] && ok "the final stage holds /agent and the Go licence only" || fail "the final stage must COPY exactly /agent and /licenses/GO-LICENSE (found: $copies)"
    printf '%s\n' "$FINAL" | grep -q '^ENTRYPOINT \["/agent"\]$' && ok "ENTRYPOINT /agent (the boot runs docker create --entrypoint /agent)" || fail "ENTRYPOINT must be [\"/agent\"]" ;;
  model-stand-in)
    printf '%s\n' "$FINAL" | head -1 | grep -Eq '^FROM gcr\.io/distroless/static-debian12:nonroot@sha256:[a-f0-9]{64}$' && ok "the final stage is distroless static nonroot" || fail "the model stand-in's final stage must be gcr.io/distroless/static-debian12:nonroot by digest"
    [ "$user" = "65532:65532" ] && ok "user 65532:65532 (the catalog entry's run.user)" || fail "USER must be 65532:65532 (found '$user')"
    [ "$(printf '%s\n' "$FINAL" | grep -Eic '^EXPOSE[[:space:]]')" = 1 ] && printf '%s\n' "$FINAL" | grep -Eq '^EXPOSE 8080$' && ok "exactly one EXPOSE: 8080" || fail "expected exactly one 'EXPOSE 8080'"
    printf '%s\n' "$FINAL" | grep -q '^ENTRYPOINT \["/usr/local/bin/model-stand-in"\]$' && ok "ENTRYPOINT /usr/local/bin/model-stand-in" || fail "ENTRYPOINT must be the model-stand-in binary" ;;
esac

# 5. the workflow builds this image; manual only; actions pinned
if [ -f "$WF" ]; then
  awk '/^      image:/ {j=1} j && /^      sign:/ {exit} j && /^          - / {print $2}' "$WF" | grep -qx "$TARGET" && ok "workflow: input image lists $TARGET" || fail "the workflow's image input must list $TARGET"
  grep -q 'scripts/image-build.sh --target "$IMAGE"' "$WF" && grep -q 'scripts/image-check-go.sh "$IMAGE"' "$WF" && ok "workflow: build and static gates take --target" || fail "the workflow must build with scripts/image-build.sh --target \"\$IMAGE\" and run scripts/image-check-go.sh \"\$IMAGE\""
  grep -Eq "^    if: \\$\\{\\{ inputs.image == 'fork' \\}\\}" "$WF" && grep -Eq "^    if: \\$\\{\\{ inputs.image == 'engine' \\}\\}" "$WF" && ok "workflow: the fork and engine measure jobs do not run for $TARGET" || fail "the measure jobs must be limited to the fork and the engine image"
  [ "$(grep -c 'echo "index digest: ' "$WF")" = 1 ] && ok "workflow: one 'index digest:' log line" || fail "the workflow must print the 'index digest:' line exactly once"
  grep -q 'function agent image is linux/arm64 only' "$WF" && ok "workflow: the function agent is arm64 only" || fail "the plan job must refuse a platform other than linux/arm64 for the function agent"
  [ "$(awk '/^on:/ {on=1; next} on && /^[a-z]/ {exit} on && /^  [a-z_]+:/ {print $1}' "$WF" | tr -d '\n')" = "workflow_dispatch:" ] && ok "workflow: workflow_dispatch is the only trigger" || fail "workflow_dispatch must be the only trigger"
  if grep -E '^\s+(- )?uses:' "$WF" | grep -vq '@[0-9a-f]\{40\}'; then fail "an action in the workflow is not pinned by commit sha"; else ok "workflow: every action is pinned by commit sha"; fi
else fail ".github/workflows/image.yml is missing"; fi

# 6. files
for f in "$CF" "$WF" "$HERE/scripts/image-check-go.sh"; do
  [ -f "$f" ] || continue
  if grep -nF "$(printf '\342\200\224')" "$f" >/dev/null 2>&1; then fail "$f has an em dash"; fi
  if grep -nE 'AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{32}' "$f" >/dev/null 2>&1; then fail "$f has a key-shaped string"; fi
done
bash -n "$0" && bash -n "$HERE/scripts/image-build.sh" && ok "scripts parse" || fail "a script does not parse"

if [ "$FAIL" = 0 ]; then echo "image-check-go ($TARGET): all checks passed"; else echo "image-check-go ($TARGET): FAILED"; exit 1; fi
