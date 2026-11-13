#!/usr/bin/env bash
# Integration setup, run INSIDE the Linux VM as root (sudo): exports the AWS Lambda base images'
# root file systems (python 3.12, nodejs 22; arm64 on an arm64 host) and their image environments
# under $A1_ROOT, builds the numpy layer, and removes the images from Docker again.
# Docker is used only to pull and export public images; nothing runs in Docker.
set -euo pipefail
ROOT=${A1_ROOT:-/srv/a1}
PLATFORM=${A1_PLATFORM:-}   # e.g. linux/amd64 to fetch x86_64 images (needs a name suffix, see A1_SUFFIX)
SUFFIX=${A1_SUFFIX:-}
ONLY=${A1_ONLY:-}           # e.g. python: skip the other image
mkdir -p "$ROOT/rootfs" "$ROOT/layer-python"
for spec in "python312${SUFFIX}=public.ecr.aws/lambda/python:3.12" "nodejs22${SUFFIX}=public.ecr.aws/lambda/nodejs:22"; do
  name=${spec%%=*}; img=${spec#*=}
  [ -n "$ONLY" ] && [[ "$name" != ${ONLY}* ]] && continue
  [ -d "$ROOT/rootfs/$name/var/runtime" ] && { echo "have $name"; continue; }
  docker pull -q ${PLATFORM:+--platform $PLATFORM} "$img" >/dev/null
  cid=$(docker create ${PLATFORM:+--platform $PLATFORM} "$img")
  mkdir -p "$ROOT/rootfs/$name"
  docker export "$cid" | tar -x -C "$ROOT/rootfs/$name"
  docker inspect "$img" --format '{{range .Config.Env}}{{println .}}{{end}}' > "$ROOT/rootfs/$name.env"
  docker inspect "$img" --format '{{json .Config.Entrypoint}} {{json .Config.Cmd}}' > "$ROOT/rootfs/$name.entry"
  docker rm "$cid" >/dev/null
  docker rmi "$img" >/dev/null
  echo "exported $name"
done
if [ -z "$SUFFIX" ] && [ ! -d "$ROOT/layer-python/numpy" ]; then
  python3 -m pip install --quiet --target "$ROOT/layer-python" --only-binary=:all: numpy --break-system-packages
fi
du -sh "$ROOT"/rootfs/* "$ROOT/layer-python"
