#!/usr/bin/env bash
# Builds honeypot images from the manifest: all of them or the named ones.
#   containers/honeypot/build.sh            # all
#   containers/honeypot/build.sh modbus ssh # selected
# Variables: CONTAINER (podman), REGISTRY (localhost), TAG (latest), HP_BIN (honeylens-hp)
set -euo pipefail
cd "$(dirname "$0")/../.."
CONTAINER=${CONTAINER:-podman}
REGISTRY=${REGISTRY:-localhost}
TAG=${TAG:-latest}
HP_BIN=${HP_BIN:-.venv/bin/honeylens-hp}

if [ $# -gt 0 ]; then
    names="$*"
else
    names=$("$HP_BIN" --list | awk 'NR>1 {print $1}')
fi
for name in $names; do
    echo "== $name"
    "$CONTAINER" build -q -f containers/honeypot/Containerfile --build-arg "HONEYPOT=$name" \
        -t "$REGISTRY/honeylens/hp-$name:$TAG" .
done
