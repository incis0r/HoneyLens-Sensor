#!/usr/bin/env bash
# Phase 1 of the plan: requirements.in -> requirements.txt on 3.12 in Rocky 9, then pip-audit.
# Run INSIDE the container from ci/lock.Containerfile (make lock), not directly.
set -euo pipefail

v=$(python3.12 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
if [ "$v" != "3.12" ]; then
    echo "ERROR: container is on Python $v, expected 3.12" >&2
    exit 1
fi
echo "== interpreter: $(python3.12 -V) / $(. /etc/os-release && echo "$PRETTY_NAME")"

echo "== pip-compile requirements.in -> requirements.txt"
python3.12 -m piptools compile --strip-extras --no-header --output-file requirements.txt requirements.in

echo "== pip-audit on the pinned lock"
mkdir -p out
python3.12 -m pip_audit --no-deps --strict --requirement requirements.txt \
    --format json --output out/pip-audit-lock.json --progress-spinner off
echo "== OK: lock has no known vulnerabilities, report in out/pip-audit-lock.json"
