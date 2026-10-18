#!/bin/bash
# Read-only probe: is any HTTP decoy on this host recording a PROXY's address as the
# attacker's? Works whether the stack runs as `inci` or as `sensor`. Prints key=value
# lines; the caller tabulates.
#
# Why this exists. A decoy behind a reverse proxy sees the proxy as its TCP peer and
# gets the real client in `X-Real-IP`. It believes that header only from a peer named
# in HONEYLENS_HTTP_PROXY -- honouring it from an untrusted peer would let any attacker
# forge their own source address. With the variable unset the decoy therefore records
# the proxy, every RFC1918 filter downstream drops the rows as internal traffic, and the
# sensor looks like it lost its exposure. One sensor ran a week that way and two threat
# reviews recorded it as "external exposure lost" before anyone read the stored headers.
#
# The discriminator is the stored header against the stored source:
#   header names a client, src_ip is PRIVATE  -> our own proxy is not trusted  = GAP
#   header names a client, src_ip is PUBLIC   -> client-supplied header, ignored = SPOOF
# The second class is not a fault: it is the trust gate doing its job, and it is why the
# trust list must name an address and never `all`.
#
# A private peer that is not a proxy lands in the GAP column too -- an internal `curl`
# that sets its own X-Real-IP is indistinguishable by shape -- so read `gap_proxies` and
# then the addresses before changing a trust list. Verified against a known positive: on
# the sensor that once had this fault, a 30-day window reports gap=11020 gap_proxies=3
# and a 7-day window reports ok, the boundary being the day the trust list was fixed.
#
# Usage (the window is one argument, so it has to survive the shell on both ends):
#   ssh <host> 'bash -s' < scripts/proxy_attribution_check.sh              # 7 days
#   ssh <host> 'bash -s "30 days"' < scripts/proxy_attribution_check.sh    # explicit
# `ssh <host> 'bash -s' < script "30 days"` does NOT work: the words go to ssh, the
# remote sees `bash -s 30 days`, and `interval '30'` is thirty SECONDS, not thirty days.
export LC_ALL=C
WINDOW=${1:-7 days}

say() { printf '%s=%s\n' "$1" "$2"; }
run_as() { local u="$1"; shift
  if [ "$u" = "$(id -un)" ]; then ( cd /tmp && eval "$@" ); else
    sudo -n -u "$u" bash -c "cd /tmp && $*" 2>/dev/null; fi; }
uctl() {
  if [ "$OWNER" = "$(id -un)" ]; then systemctl --user "$@" 2>/dev/null
  else sudo -n systemctl --machine="$OWNER@.host" --user "$@" 2>/dev/null; fi; }

say host "$(hostname -s)"
say window "$WINDOW"

mine=$(podman ps -q 2>/dev/null | wc -l | tr -d ' ')
theirs=0
id sensor >/dev/null 2>&1 && theirs=$(run_as sensor 'podman ps -q' | wc -l | tr -d ' ')
if [ "${theirs:-0}" -gt "${mine:-0}" ]; then OWNER=sensor; else OWNER=$(id -un); fi
HOME_DIR=$(getent passwd "$OWNER" | cut -d: -f6)
say stack_user "$OWNER"

# ── declared trust policy, per decoy ─────────────────────────────────────────
# Read it from the running container, not from the quadlet file and not from the unit:
# quadlet passes `Environment=` to podman as `--env`, so the unit's own Environment
# property holds only PODMAN_SYSTEMD_UNIT and would report every decoy as untrusting.
for c in $(run_as "$OWNER" "podman ps --filter name=^hp- --format '{{.Names}}'"); do
  envs=$(run_as "$OWNER" "podman inspect $c --format '{{range .Config.Env}}{{println .}}{{end}}'")
  http=$(printf '%s\n' "$envs" | sed -n 's/^HONEYLENS_HTTP_PROXY=//p')
  pp=$(printf '%s\n' "$envs" | sed -n 's/^HONEYLENS_PROXY_PROTOCOL=//p')
  [ -n "$http$pp" ] || continue
  say "trust_$c" "http=${http:--} proxy_protocol=${pp:--}"
done

# ── measured effect, through the app's own config ─────────────────────────────
TREE=""
for cand in "$HOME_DIR/sensor-1.0" "$HOME_DIR/honeylens"; do
  if [ "$OWNER" = "$(id -un)" ]; then [ -x "$cand/.venv/bin/python" ] && TREE="$cand" && break
  else sudo -n test -x "$cand/.venv/bin/python" && TREE="$cand" && break; fi
done
say tree "${TREE:-not-found}"
[ -n "$TREE" ] || exit 0

# The env file comes from the unit. Without it honeylens.config falls back to the 0.9
# path and the probe dies on a PermissionError that reads like a broken deployment.
ENVF=$(uctl show -p Environment --value honeylens-ingest-honeypot | tr ' ' '\n' \
       | sed -n 's/^HONEYLENS_ENV_FILE=//p')
[ -n "$ENVF" ] || ENVF="$HOME_DIR/honeylens-state/.env"
say env_file "$ENVF"

# The query goes to the interpreter on stdin, deliberately, never through a file:
# writing it to a predictable path under /tmp and running it as another user is a local
# code-execution hole on a host whose job is to be attacked (see fleet_status.sh).
out=$(
  if [ "$OWNER" = "$(id -un)" ]; then
    HONEYLENS_ENV_FILE="$ENVF" PX_WINDOW="$WINDOW" "$TREE/.venv/bin/python" - 2>&1
  else
    sudo -n -u "$OWNER" env "HONEYLENS_ENV_FILE=$ENVF" "PX_WINDOW=$WINDOW" \
      "$TREE/.venv/bin/python" - 2>&1
  fi <<'PY'
import os
from honeylens.database import db_cursor

# Header keys are matched case-insensitively: aiohttp preserves the sender's spelling,
# so a `->>'X-Real-IP'` lookup alone silently misses `X-Real-Ip`.
HDR = """(SELECT v FROM jsonb_each_text(metadata->'headers') AS h(k, v)
          WHERE lower(k) = 'x-real-ip' LIMIT 1)"""
PRIV = """(src_ip << '10.0.0.0/8'::inet OR src_ip << '172.16.0.0/12'::inet
           OR src_ip << '192.168.0.0/16'::inet OR src_ip << '127.0.0.0/8'::inet)"""
Q = f"""
SELECT source,
       count(*)                                                   AS total,
       count(*) FILTER (WHERE metadata->>'headers' ILIKE '%%x-real-ip%%')      AS xri,
       count(*) FILTER (WHERE metadata->>'headers' ILIKE '%%x-forwarded-for%%') AS xff,
       count(*) FILTER (WHERE {HDR} IS NOT NULL AND {HDR} <> host(src_ip)
                              AND {PRIV})                         AS gap,
       count(DISTINCT src_ip) FILTER (WHERE {HDR} IS NOT NULL AND {HDR} <> host(src_ip)
                              AND {PRIV})                         AS gap_proxies,
       to_char(max(timestamp) FILTER (WHERE {HDR} IS NOT NULL AND {HDR} <> host(src_ip)
                              AND {PRIV}), 'MM-DD HH24:MI')       AS gap_last,
       count(*) FILTER (WHERE {HDR} IS NOT NULL AND {HDR} <> host(src_ip)
                              AND NOT {PRIV})                     AS spoof,
       count(DISTINCT src_ip) FILTER (WHERE {HDR} IS NOT NULL AND {HDR} <> host(src_ip)
                              AND NOT {PRIV})                     AS spoof_senders
FROM sensor_events
WHERE timestamp > now() - %s::interval AND metadata ? 'headers'
GROUP BY 1 HAVING count(*) FILTER (WHERE metadata->>'headers' ILIKE '%%x-real-ip%%') > 0
            OR count(*) FILTER (WHERE metadata->>'headers' ILIKE '%%x-forwarded-for%%') > 0
ORDER BY 2 DESC"""
try:
    with db_cursor() as c:
        c.execute(Q, (os.environ.get("PX_WINDOW", "7 days"),))
        rows = c.fetchall()
except Exception as e:
    print("probe_error=%s" % str(e).replace("\n", " ")[:120])
    raise SystemExit(0)

gaps = 0
for r in rows:
    src, total, xri, xff, gap, gap_px, gap_last, spoof, spoof_src = r
    gaps += gap
    print(
        "src=%s total=%s xri=%s xff=%s gap=%s gap_proxies=%s gap_last=%s "
        "spoof=%s spoof_senders=%s"
        % (src, total, xri, xff, gap, gap_px, gap_last or "-", spoof, spoof_src)
    )
if not rows:
    print("src_none=no decoy on this host saw a forwarding header in the window")
# A gap is a configuration fault to fix; a spoof count is the gate working.
print("verdict=%s" % ("GAP" if gaps else "ok"))
PY
)
printf '%s\n' "$out" | grep -E '^(src|src_none|verdict|probe_error)' \
  || say probe_error "no output: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-100)"
