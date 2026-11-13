#!/usr/bin/env bash
# Runs Rovara's conformance kit (shape suite from the AWS service models, plus the behaviour pack) against
# an instance already listening on loopback. The kit is a separate Rovara repository.
#   KIT=/path/to/rovara-aws-conformance PYTHON=/path/to/python-with-boto3 compat/conformance.sh <name> <endpoint> [pid]
set -euo pipefail
: "${KIT:?set KIT to the conformance kit directory}"
export DOCKER_HOST=unix:///nonexistent AWS_EC2_METADATA_DISABLED=true
exec env PYTHON="${PYTHON:-python3}" "$KIT/run.sh" "$@"
