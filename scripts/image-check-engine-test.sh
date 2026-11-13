#!/usr/bin/env bash
# Tests of scripts/image-check-engine.sh: the real tree passes, and each mutation of it below makes the check fail.
# the mutation expressions are perl programs in single quotes on purpose
# shellcheck disable=SC2016
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CHECK="$HERE/scripts/image-check-engine.sh"
FAIL=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fresh() { rm -rf "$TMP/t"; mkdir -p "$TMP/t/scripts" "$TMP/t/.github/workflows"; cp -R "$HERE/image" "$HERE/front" "$TMP/t/"; cp "$CHECK" "$HERE/scripts/image-build.sh" "$HERE/scripts/engine-library-sbom.sh" "$HERE/scripts/image-extract-binary.sh" "$HERE/scripts/front-prove.sh" "$HERE/scripts/image-build-test.sh" "$HERE/scripts/engine-library-sbom-test.sh" "$TMP/t/scripts/"; cp "$HERE/.github/workflows/image.yml" "$TMP/t/.github/workflows/"; }
expect_fail() { # name, sed expression, file (relative to the tree)
  fresh
  perl -0pi -e "$2" "$TMP/t/$3"
  if IMAGE_CHECK_ROOT="$TMP/t" bash "$CHECK" >"$TMP/out" 2>&1; then echo "FAIL: mutation '$1' was not caught"; FAIL=1; else echo "ok:   mutation '$1' is caught ($(grep -c '^FAIL' "$TMP/out") failure line(s))"; fi
}
fresh
if IMAGE_CHECK_ROOT="$TMP/t" bash "$CHECK" >"$TMP/out" 2>&1; then echo "ok:   the real tree passes"; else echo "FAIL: the real tree does not pass"; cat "$TMP/out"; FAIL=1; fi
expect_fail "an unpinned FROM" 's/(FROM gcr\.io[^\n]*?)@sha256:[a-f0-9]{64}/$1/' image/Containerfile.engine
expect_fail "latest" 's/ENGINE_BASE_URL=https:\/\/downloads\.aws\.com\/aws-emulator\/packages\/aws-emulator\/LTS/ENGINE_BASE_URL=https:\/\/downloads.aws.com\/aws-emulator\/packages\/aws-emulator\/LTS\/latest/' image/Containerfile.engine
expect_fail "root user" 's/USER 10001:10001/USER 0/' image/Containerfile.engine
expect_fail "no signature check" 's/gpgv --status-fd 3 --keyring \.\/pinned-key\.gpg "\$\{deb\}\.sig" "\$\{deb\}" 3> verify\.status; \\\n/true; \\\n/' image/Containerfile.engine
expect_fail "gpg --verify instead of gpgv" 's/gpgv --status-fd 3 --keyring \.\/pinned-key\.gpg/gpg --batch --verify --keyring .\/pinned-key.gpg/' image/Containerfile.engine
expect_fail "VALIDSIG not checked" 's/\$2 == "VALIDSIG" \&\& \(\$3 == f \|\| \$NF == f\)/1/' image/Containerfile.engine
expect_fail "no sha256 check" 's/sha256sum -c -/true/' image/Containerfile.engine
expect_fail "the package is installed" 's/dpkg-deb -x "\$\{deb\}" \/rootfs/dpkg -i "\${deb}"/' image/Containerfile.engine
expect_fail "wrong key fingerprint" 's/98BCF336A3BE53B734E967C52E5BF49BD940F624/98BCF336A3BE53B734E967C52E5BF49BD940F625/' image/Containerfile.engine
expect_fail "a RUN in the final stage" 's/(WORKDIR \/tmp\nUSER)/RUN true\n$1/' image/Containerfile.engine
expect_fail "a secret in an ENV" 's/ENV HOME=\/tmp/ENV CONTROL_TOKEN=x HOME=\/tmp/' image/Containerfile.engine
expect_fail "memory 384" 's/"memMiB": 512/"memMiB": 384/' image/catalog-entry.engine.json
expect_fail "two ports" 's/"ports": \[\s*4566\s*\]/"ports": [4566, 4567]/' image/catalog-entry.engine.json
expect_fail "a dependency in the front" 's/go 1\.22/go 1.22\n\nrequire example.com\/x v1.0.0/' front/go.mod
expect_fail "telemetry left on" 's/"EMULATOR_TELEMETRY=off",/"EMULATOR_TELEMETRY=on",/' front/engine.go
expect_fail "a TLS skip" 's/MinVersion: tls\.VersionTLS12/InsecureSkipVerify: true/' front/engine.go
expect_fail "a symlink for the engine" 's/(    test -s \/rootfs\/opt\/aws-emulator\/THIRD_PARTY_LICENSES; \\\n)/$1    ln -s \/opt\/aws-emulator\/bin\/aws-emulator \/rootfs\/usr\/bin\/aws-emulator; \\\n/' image/Containerfile.engine
expect_fail "the engine path default" 's/defaultEngineBin = "\/opt\/aws-emulator\/bin\/aws-emulator"/defaultEngineBin = "\/usr\/bin\/aws-emulator"/' front/config.go
expect_fail "an old Go" 's/golang:1\.26\.11-bookworm/golang:1.26.8-bookworm/' image/Containerfile.engine
expect_fail "Go 1.24" 's/golang:1\.26\.11-bookworm/golang:1.24.13-bookworm/' image/Containerfile.engine
expect_fail "a dial in the delivery code" 's/(func \(k \*snsSink\) deliverLoop)/var _ = net.Dial\n$1/' front/sns_deliver.go
expect_fail "the sink's dial wall removed" 's/if !n\.private\(ip\)/if false/' front/sink_net.go
expect_fail "the sink dials the caller's address" 's/"tcp4", t\.addr/"tcp4", addr/' front/sink_net.go
expect_fail "a TLS skip in the sink" 's/RootCAs: roots/InsecureSkipVerify: true/' front/sink_net.go
expect_fail "pkill in a prove script" 's/(set -uo pipefail)/$1\npkill -f something/' scripts/front-prove.sh
expect_fail "an em dash" 's/CC0 1\.0 Universal/CC0 1.0 Universal \xe2\x80\x94/' image/engine-licenses/NOTICE
expect_fail "no engine build step" 's/image-build\.sh --engine --registry-ref/image-build.sh --registry-ref/g' .github/workflows/image.yml
expect_fail "no crate scan gate" 's/sbom\.spdx\.json" --fail-on critical/sbom.spdx.json"/' .github/workflows/image.yml
expect_fail "a second digest line" 's/(echo "index digest: )/echo "index digest: x"\n          $1/' .github/workflows/image.yml
expect_fail "an unpinned action" 's/(uses: actions\/checkout)@[0-9a-f]{40}/$1\@v4/' .github/workflows/image.yml
expect_fail "engine amd64 allowed" 's/engine image is linux\/arm64 only/engine image anywhere/' .github/workflows/image.yml
expect_fail "a push trigger" 's/on:\n  workflow_dispatch:/on:\n  push:\n  workflow_dispatch:/' .github/workflows/image.yml
[ "$FAIL" = 0 ] && echo "image-check-engine-test: all passed" || echo "image-check-engine-test: FAILED"
exit "$FAIL"
