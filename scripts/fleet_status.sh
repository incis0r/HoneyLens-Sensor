#!/bin/bash
# Read-only fleet status probe. Works whether the stack runs as `inci` or as `sensor`.
# Event counts go through the application's own config, so no credential file is read
# and no secret is printed. Prints key=value lines; the caller tabulates.
export LC_ALL=C

say() { printf '%s=%s\n' "$1" "$2"; }

say host "$(hostname -s)"
say os "$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" | tr -d '"')"
say uptime_d "$(awk '{printf "%.1f", $1/86400}' /proc/uptime 2>/dev/null)"

run_as() {  # run_as <user> <cmd string>
  local u="$1"; shift
  if [ "$u" = "$(id -un)" ]; then ( cd /tmp && eval "$@" ); else
    sudo -n -u "$u" bash -c "cd /tmp && $*" 2>/dev/null
  fi
}
uctl() {
  if [ "$OWNER" = "$(id -un)" ]; then systemctl --user "$@" 2>/dev/null
  else sudo -n systemctl --machine="$OWNER@.host" --user "$@" 2>/dev/null; fi
}

mine=$(podman ps -q 2>/dev/null | wc -l | tr -d ' ')
theirs=0
id sensor >/dev/null 2>&1 && theirs=$(run_as sensor 'podman ps -q' | wc -l | tr -d ' ')
if [ "${theirs:-0}" -gt "${mine:-0}" ]; then OWNER=sensor; else OWNER=$(id -un); fi
HOME_DIR=$(getent passwd "$OWNER" | cut -d: -f6)
say stack_user "$OWNER"
say containers_running "$(run_as "$OWNER" 'podman ps -q' | wc -l | tr -d ' ')"
say containers_not_running "$(run_as "$OWNER" "podman ps -a --format '{{.Status}}'" | grep -civ '^Up' | tr -d ' ')"

say failed_user "$(uctl list-units --state=failed --no-legend --plain | grep -c . | tr -d ' ')"
say failed_user_names "$(uctl list-units --state=failed --no-legend --plain | awk '{print $1}' | paste -sd, - | cut -c1-110)"
say failed_system "$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | grep -c . | tr -d ' ')"
say api "$(uctl is-active honeylens-api.service || echo absent)"
say linger "$(loginctl show-user "$OWNER" -p Linger --value 2>/dev/null || echo '?')"

# NRestarts is a LIFETIME counter -- it never decays. An image rollout that
# restarts 43 decoys leaves every one of them above any fixed threshold for as
# long as the host lives, so NRestarts alone reports four-day-old churn as a
# live crash loop. Measured on sensor-d 2026-10-30: 11 decoys at 55-162 restarts,
# all continuously active since the 2026-10-26 rebuild. A unit is looping only
# if it ALSO entered active recently, so pair the counter with that timestamp
# and report the old churn separately instead of as a fault.
now_us=$(awk '{printf "%d", $1*1000000}' /proc/uptime 2>/dev/null)
loops=""; churn=""
for u in $(uctl list-units 'hp-*' --no-legend --plain | awk '{print $1}'); do
  n=$(uctl show -p NRestarts --value "$u"); [ "${n:-0}" -gt 20 ] || continue
  t=$(uctl show -p ActiveEnterTimestampMonotonic --value "$u")
  age=$(( ( ${now_us:-0} - ${t:-0} ) / 1000000 ))
  if [ "${t:-0}" -gt 0 ] && [ "$age" -lt 3600 ]; then
    loops="$loops${loops:+,}${u%.service}:$n"
  else
    churn="$churn${churn:+,}${u%.service}:$n"
  fi
done
say restart_loops "$(printf '%s' "${loops:-none}" | cut -c1-140)"
say restart_churn_old "$(printf '%s' "${churn:-none}" | cut -c1-140)"

# ── events through the app's own config ───────────────────────────────────────
TREE=""
for cand in "$HOME_DIR/sensor-1.0" "$HOME_DIR/honeylens"; do
  if [ "$OWNER" = "$(id -un)" ]; then [ -x "$cand/.venv/bin/python" ] && TREE="$cand" && break
  else sudo -n test -x "$cand/.venv/bin/python" && TREE="$cand" && break; fi
done
say tree "${TREE:-not-found}"

if [ -n "$TREE" ]; then
  # The query goes to the interpreter on stdin, deliberately, and never through a file.
  # Writing it to a predictable path under /tmp and then running it as another user is a
  # local code-execution hole: /tmp is world-writable, `cat >` follows a symlink and does
  # not use O_EXCL, and anything that wins the race between the write and the run gets its
  # code executed as the stack owner — with HONEYLENS_ENV_FILE pointing at the real
  # database credentials. On a host whose job is to be attacked that is not hypothetical.
  # No file, no race, and nothing left behind to clean up.
  ev=$(
    if [ "$OWNER" = "$(id -un)" ]; then
      HONEYLENS_ENV_FILE="$HOME_DIR/honeylens-state/.env" "$TREE/.venv/bin/python" - 2>&1
    else
      sudo -n -u "$OWNER" env "HONEYLENS_ENV_FILE=$HOME_DIR/honeylens-state/.env" \
        "$TREE/.venv/bin/python" - 2>&1
    fi <<'PY'
from honeylens.database import db_cursor
Q = """SELECT
  (SELECT count(*) FROM sensor_events WHERE timestamp > now() - interval '1 hour'),
  (SELECT count(*) FROM sensor_events WHERE timestamp > now() - interval '24 hours'),
  (SELECT to_char(max(timestamp), 'MM-DD HH24:MI') FROM sensor_events),
  (SELECT count(*) FROM sensor_events)"""
try:
    with db_cursor() as c:
        c.execute(Q)
        r = c.fetchone()
    print("ev_1h=%s" % r[0]); print("ev_24h=%s" % r[1])
    print("ev_last=%s" % r[2]); print("ev_total=%s" % r[3])
except Exception as e:
    print("ev_error=%s" % str(e).replace("\n", " ")[:90])
PY
  )
  # Say so when the probe yields nothing, instead of silently printing no ev_ lines and
  # letting the reader assume the sensor is quiet.
  printf '%s\n' "$ev" | grep -E '^ev_' || say ev_error "no output: $(printf '%s' "$ev" | tr '\n' ' ' | cut -c1-80)"
fi

say disk_free_home "$(df -h /home 2>/dev/null | awk 'NR==2{print $4}')"
say disk_pct_root "$(df -h / 2>/dev/null | awk 'NR==2{print $5}')"
