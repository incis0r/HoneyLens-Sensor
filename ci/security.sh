#!/usr/bin/env bash
# Security gate of sensor 1.0 — SCA, SAST, secrets, SBOM.
#
# Invoked by a self-hosted webhook runner. These are not Gitea Actions — the runner
# clones the repository and runs this script, so everything that is to execute in CI
# must be here, not in a workflow file.
#
# What runs is the same as locally via `make security`. A divergence between what
# the developer sees and what CI sees is worse than the absence of one of them.
#
# Machine-readable outputs go to out/ and from there to a vulnerability manager. Which product each
# tier lands in is NOT hardcoded here — the runner reads `.security-pipeline.yaml` in the
# repository root (SCA and SAST/secrets deliberately split across two products). The
# earlier note here named "honeylens-honeypot", which is the telemetry/runtime-detection
# product, not a code-scanning one; the manifest is the authority.
# Reports remain even on failure — a run that only says "failed" forces you to repeat it
# by hand.
#
# Usage:  ci/security.sh [--no-fail]     (--no-fail: report, do not block)
set -uo pipefail

OUT="${OUT_DIR:-out}"
mkdir -p "$OUT"
FAIL=0
STRICT=1
[ "${1:-}" = "--no-fail" ] && STRICT=0

R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; N=$'\033[0m'

step() { printf '\n══ %s ══\n' "$1"; }
ok()   { printf '   %sOK%s   %s\n'   "$G" "$N" "$1"; }
bad()  { printf '   %sFAIL%s %s\n'   "$R" "$N" "$1"; FAIL=1; }
warn() { printf '   %sWARN%s %s\n'  "$Y" "$N" "$1"; }

# ── 1. SECRETS ──────────────────────────────────────────────────────────────
# Full history, not just the change: a secret removed by the next commit still sits
# in git objects and can still be read.
step "Secrets (gitleaks)"
if command -v gitleaks >/dev/null 2>&1; then
    if gitleaks detect --source . --config .gitleaks.toml \
            --report-format sarif --report-path "$OUT/gitleaks.sarif" --redact; then
        ok "no secrets detected"
    else
        bad "gitleaks found secrets — see $OUT/gitleaks.sarif"
    fi
else
    warn "gitleaks not installed — skipped (this is a GAP, not a success)"
    [ "$STRICT" -eq 1 ] && FAIL=1
fi

# ── 2. SCA ──────────────────────────────────────────────────────────────────
# We scan the PINNED lock file, not whatever happens to sit in the environment. This whole
# 1.0 line came about because eight CVE fixes were unreachable on Python 3.9 —
# auditing anything other than what we will actually install does not answer that question.
step "Dependencies (pip-audit)"
if command -v pip-audit >/dev/null 2>&1; then
    if [ -f requirements.txt ]; then
        # pip-audit exits with 1 both on vulnerabilities and when it cannot reach the
        # advisory database (OSV/PyPI). We tell them apart by the report: a complete JSON with a
        # dependency list is a verdict, a missing or truncated file is a scanner failure — a GAP, not
        # findings. We already caught the same bug once with semgrep.
        rm -f "$OUT/pip-audit.json"
        if pip-audit --requirement requirements.txt --strict \
                --format json --output "$OUT/pip-audit.json"; then
            ok "no known vulnerabilities in the pinned dependencies"
        elif python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if 'dependencies' in d else 1)" \
                "$OUT/pip-audit.json" 2>/dev/null; then
            bad "pip-audit reported vulnerabilities — see $OUT/pip-audit.json"
        else
            bad "pip-audit did not work (no complete report — network? OSV?) — this is a GAP, not findings"
        fi
    else
        warn "no requirements.txt — the port has not brought in dependencies yet"
    fi
else
    warn "pip-audit not installed — skipped (this is a GAP)"
    [ "$STRICT" -eq 1 ] && FAIL=1
fi

# ── 3. SAST ─────────────────────────────────────────────────────────────────
step "SAST (semgrep + bandit)"
if command -v semgrep >/dev/null 2>&1; then
    # Output in SARIF, because that is what the vulnerability manager swallows. --error makes findings
    # set the exit code; without it semgrep exits zero and blocks nothing.
    # Code 1 is findings; any other non-zero is a scanner failure. We tell them apart, because
    # a scanner that fell over did not "find" anything — and a report about findings
    # would send someone to an empty SARIF file instead of to the cause.
    semgrep --config=p/python --config=p/security-audit --config=p/secrets \
            --sarif --output "$OUT/semgrep.sarif" --error --quiet .
    rc=$?
    case "$rc" in
        0) ok "semgrep: no findings" ;;
        1) bad "semgrep reported findings — see $OUT/semgrep.sarif" ;;
        *) bad "semgrep did not work (code $rc) — this is a GAP, not findings" ;;
    esac
else
    warn "semgrep not installed locally — it must be present in CI"
fi

if command -v bandit >/dev/null 2>&1; then
    if [ -d src ] && [ -n "$(find src -name '*.py' -print -quit 2>/dev/null)" ]; then
    # bandit warns "nosec encountered, but no failed test" for every line of a multi-line
    # statement carrying the marker — noise, not signal; we filter only that.
        if bandit -q -c pyproject.toml -r src -f json -o "$OUT/bandit.json" 2> >(grep -v "nosec encountered" >&2); then
            ok "bandit: no findings"
        else
            bad "bandit reported findings — see $OUT/bandit.json"
        fi
    else
        warn "src/ still empty — nothing to scan"
    fi
else
    warn "bandit not installed — skipped (this is a GAP)"
fi

# ── 3b. CONTAINER IMAGES ────────────────────────────────────────────────────
# Since every honeypot is a container (docs/decision-containers.md), Python dependencies
# stopped being the whole dependency surface. The base image has its own CVEs and its own life
# cycle — and the honeypot is the most exposed process we have.
step "Container images (trivy)"
if command -v trivy >/dev/null 2>&1; then
    if compgen -G "containers/*/Containerfile" >/dev/null 2>&1; then
        img_fail=0
        for cf in containers/*/Containerfile; do
            name="$(basename "$(dirname "$cf")")"
            trivy config --quiet --exit-code 1 --format json \
                  --output "$OUT/trivy-config-$name.json" "$(dirname "$cf")" \
                || { bad "trivy: configuration errors in $name"; img_fail=1; }
        done
        [ "$img_fail" -eq 0 ] && ok "image configurations: no findings"
    else
        warn "no containers/*/Containerfile — honeypots not ported yet"
    fi
else
    warn "trivy not installed — skipped (this is a GAP once there are images)"
fi

# ── 4. SBOM ─────────────────────────────────────────────────────────────────
# This is not a gate — it is evidence. Without an SBOM the question "does the CVE in libX affect us"
# requires guessing instead of reading.
step "SBOM (CycloneDX)"
if command -v cyclonedx-py >/dev/null 2>&1 && [ -f requirements.txt ]; then
    cyclonedx-py requirements requirements.txt -o "$OUT/honeylens-sbom.cdx.json" 2>/dev/null \
        && ok "SBOM: $OUT/honeylens-sbom.cdx.json" \
        || warn "SBOM generation failed"
else
    warn "SBOM skipped (no cyclonedx-py or requirements.txt)"
fi

# ── summary ─────────────────────────────────────────────────────────────────
step "Result"
if [ "$FAIL" -eq 0 ]; then
    ok "security gate passed"
    exit 0
fi
if [ "$STRICT" -eq 0 ]; then
    warn "there are findings, but --no-fail — not blocking"
    exit 0
fi
bad "security gate FAILED — reports in $OUT/"
exit 1
