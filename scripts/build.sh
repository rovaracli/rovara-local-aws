#!/usr/bin/env bash
# Builds Rovara local AWS without Docker.
#
#   scripts/build.sh jvm       fast-jar layout in dist/jvm/ (run with: java -jar dist/jvm/quarkus-app/quarkus-run.jar)
#   scripts/build.sh native    single binary in dist/native/rovara-local-aws (needs GraalVM CE 25 as JAVA_HOME)
#
# Both modes copy LICENSE, NOTICE and THIRD-PARTY-NOTICES.txt (and licenses/) next to the output; the same
# files are also packaged inside the jar and the native binary. Set MAVEN_REPO_LOCAL to use a scratch Maven
# repository. Tests are not run here: use ./mvnw test for that.
#
# The container image is built later, from dist/: copy dist/native/* (or dist/jvm/*) into a minimal
# non-root, read-only-root image and add the same licence files at /usr/share/licenses/rovara-local-aws/.
set -euo pipefail
cd "$(dirname "$0")/.."
MODE="${1:-jvm}"
MVN=(./mvnw -B)
[ -n "${MAVEN_REPO_LOCAL:-}" ] && MVN+=("-Dmaven.repo.local=${MAVEN_REPO_LOCAL}")
export DOCKER_HOST=unix:///nonexistent   # no build step may reach a Docker engine

case "$MODE" in
  jvm)
    "${MVN[@]}" package -Dmaven.test.skip=true
    rm -rf dist/jvm; mkdir -p dist/jvm
    cp -R target/quarkus-app dist/jvm/quarkus-app
    ;;
  native)
    if ! "${JAVA_HOME:-/nonexistent}/bin/native-image" --version >/dev/null 2>&1; then
      echo "native mode needs GraalVM CE 25 with native-image in JAVA_HOME" >&2; exit 2
    fi
    # NATIVE_IMAGE_XMX (for example 5g) caps the heap of the native-image builder JVM (-J-Xmx); unset leaves its default.
    NATIVE_ARGS=()
    [ -n "${NATIVE_IMAGE_XMX:-}" ] && NATIVE_ARGS+=("-Dquarkus.native.native-image-xmx=${NATIVE_IMAGE_XMX}")
    # NATIVE_BUILD_ARGS: extra native-image options, appended to the list in application.yml (comma-separated, no commas
    # inside an option). The image build uses it for options that exist only in Mandrel (GraalVM CE rejects them).
    [ -n "${NATIVE_BUILD_ARGS:-}" ] && NATIVE_ARGS+=("-Dquarkus.native.additional-build-args-append=${NATIVE_BUILD_ARGS}")
    "${MVN[@]}" package -Dnative -Dmaven.test.skip=true ${NATIVE_ARGS[@]+"${NATIVE_ARGS[@]}"}
    rm -rf dist/native; mkdir -p dist/native
    cp target/rovara-local-aws-*-runner dist/native/rovara-local-aws
    ;;
  *) echo "usage: scripts/build.sh jvm|native" >&2; exit 2 ;;
esac

OUT="dist/$MODE"
cp LICENSE NOTICE THIRD-PARTY-NOTICES.txt "$OUT/"
mkdir -p "$OUT/licenses"; cp licenses/Apache-2.0.txt "$OUT/licenses/"
echo "built $OUT:"; ls -l "$OUT"
