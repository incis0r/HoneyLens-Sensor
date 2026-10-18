#!/usr/bin/env bash
# Is a sensor's honeylens package byte-identical to a commit of this repository?
#
# Read-only. Prints, per package root found on the host, how many files match, differ,
# are missing, or are present on the host and not in the commit. A host that is merely
# behind and a host someone edited in place look the same in a status table and are not
# the same thing, so this compares content, not versions or tags.
#
#   scripts/fleet_code_parity.sh <ssh-destination> [ssh args ...]
#   REF=<commit> scripts/fleet_code_parity.sh <host>
#
# Two things this works around, both learned the hard way:
#
#   * The manifest is embedded in the Python payload as a string literal, not appended
#     after it. `python3 -` reads the WHOLE of stdin as the program, so a manifest sent
#     after the code is parsed as code.
#   * It runs as root over sudo, which reads every candidate home directory without
#     needing to know which account owns the stack (they differ per host, and the homes
#     are 0700). It writes nothing anywhere.
#
# Interpreting the output: `extra` entries named `._*` are AppleDouble sidecars, macOS
# resource-fork metadata (magic 00 05 16 07) left behind by deploys from a macOS
# workstation. They are
# not importable, but they are drift. `missing=<all>` under a `site-packages` root is
# normal on an editable install: the package is imported from the tree.
set -euo pipefail
cd "$(dirname "$0")/.."
REF="${REF:-HEAD}"
[ $# -ge 1 ] || { echo "usage: $0 <ssh-destination> [ssh args ...]" >&2; exit 2; }

PKG_PREFIX="src/honeylens/"
manifest=$(
  git ls-tree -r "$REF" --name-only "$PKG_PREFIX" | while read -r f; do
    printf '%s %s\n' "$(git cat-file blob "$REF:$f" | shasum -a 256 | cut -d' ' -f1)" "${f#"$PKG_PREFIX"}"
  done
)
case "$manifest" in *'"""'*|*'\'*) echo "manifest would break the literal" >&2; exit 1;; esac
echo "# $REF ($(git rev-parse --short "$REF")): $(printf '%s\n' "$manifest" | grep -c .) files" >&2

{
  printf 'MANIFEST_TEXT = """\n%s\n"""\n' "$manifest"
  cat <<'PY'
import hashlib, os, sys

def sha(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
    except OSError as exc:
        return "ERR:%d" % exc.errno
    return h.hexdigest()

manifest = dict(
    reversed(line.split(" ", 1)) for line in MANIFEST_TEXT.strip().splitlines()
)

roots = []
# `lib` and `lib64` are the same directory on Rocky, so compare resolved paths or the
# same package gets reported twice and a reader counts one drift as two.
seen = set()
for home in sorted(os.listdir("/home")):
    for name in ("sensor-1.0", "honeylens"):
        tree = "/home/%s/%s" % (home, name)
        if not os.path.isdir(tree + "/src/honeylens"):
            continue
        for kind, path in [("tree", tree + "/src/honeylens")] + [
            ("site-packages", "%s/.venv/%s/%s/site-packages/honeylens" % (tree, libdir, py))
            for libdir in ("lib64", "lib")
            if os.path.isdir("%s/.venv/%s" % (tree, libdir))
            for py in sorted(os.listdir("%s/.venv/%s" % (tree, libdir)))
        ]:
            if not os.path.isdir(path):
                continue
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            roots.append((kind, path))

if not roots:
    print("no honeylens package found under /home")
    sys.exit(0)

for kind, pkg in roots:
    differ, missing, extra, ok = [], [], [], 0
    for rel, want in manifest.items():
        got = sha(os.path.join(pkg, rel))
        if got.startswith("ERR:"):
            missing.append(rel)
        elif got == want:
            ok += 1
        else:
            differ.append("%s host=%s" % (rel, got[:16]))
    for dirpath, dirnames, filenames in os.walk(pkg):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in filenames:
            if fn.endswith(".py"):
                rel = os.path.relpath(os.path.join(dirpath, fn), pkg)
                if rel not in manifest:
                    extra.append(rel)
    print("root=%s" % pkg)
    print("  kind=%s ok=%d differ=%d missing=%d extra=%d"
          % (kind, ok, len(differ), len(missing), len(extra)))
    for label, items in (("differ", differ), ("missing", missing), ("extra", extra)):
        for rel in sorted(items)[:60]:
            print("  %s: %s" % (label, rel))
        if len(items) > 60:
            print("  %s: ... and %d more" % (label, len(items) - 60))
PY
} | ssh -o BatchMode=yes "$@" 'sudo -n python3 -'
