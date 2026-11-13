#!/usr/bin/env bash
# Builds the agent and runs the gVisor integration scenarios. Run inside the Linux VM:
#   colima ssh -p aws-emu-spike -- bash -lc 'cd <repo>/runner/agent/integration && ./run.sh [scenario...]'
# Needs sudo (runsc with a root bundle), ~/s4/gv/runsc, and setup.sh done once.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=${A1_ROOT:-/srv/a1}
sudo mkdir -p "$ROOT/agent" "$ROOT/bundles"
(cd .. && CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /tmp/a1-agent-arm64 . \
  && CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o /tmp/a1-agent-amd64 .)
sudo install -m 0755 /tmp/a1-agent-arm64 "$ROOT/agent/agent"
sudo install -m 0755 /tmp/a1-agent-amd64 "$ROOT/agent/agent-amd64"
sudo chmod -R a+rX "$ROOT/agent"
exec sudo -E A1_ROOT="$ROOT" python3 run.py "$@"
