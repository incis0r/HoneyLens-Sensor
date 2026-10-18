#!/usr/bin/env python3
"""
sensor_health_diag.py — Sensor Health Diagnostic Tool
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Diagnoses common production issues:
  - Runaway cron jobs (overlapping python3 processes)
  - Memory pressure / OOM risk
  - Zombie/defunct processes
  - Disk pressure
  - PostgreSQL connection leaks
  - Sensor service health

Usage:
    python sensor_health_diag.py
    python sensor_health_diag.py --fix-cron          # show cron fix recommendations
    python sensor_health_diag.py --kill-duplicates   # kill duplicate python3 cron jobs
    python sensor_health_diag.py --watch             # continuous monitoring (5s interval)
"""

import argparse
import logging
import os
import re
import subprocess
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime

# ── Helpers ──────────────────────────────────────────────────────────────


def run(cmd: str, timeout: int = 10) -> str:
    """Run a shell pipeline, return stdout (best effort).

    This helper is INTERNAL to the diagnostic script. Callers MUST pass
    a literal command string built at write-time — never a string built
    from runtime user input. shell=True is intentional and operationally
    required: every caller in this module uses pipes (``ps aux | grep``),
    redirections (``2>/dev/null``), or compound commands (``A || B``)
    that would not work with shlex-based argument vectors.

    The semgrep finding ``subprocess-shell-true`` (CWE-78) is marked
    Risk Accepted on this helper because the static-string contract is
    the security boundary, not the absence of a shell.
    """
    try:
        # nosemgrep: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)  # nosec B602
        return r.stdout.strip()
    except Exception:
        return ""


def bytes_to_human(b):
    """Convert bytes to human readable."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return "%.1f %s" % (b, unit)
        b /= 1024
    return "%.1f PB" % b


def print_header(title):
    print()
    print("=" * 70)
    print("  %s" % title)
    print("=" * 70)


def ok(msg):
    print("  [OK]   %s" % msg)


def warn(msg):
    print("  [WARN] %s" % msg)


def crit(msg):
    print("  [CRIT] %s" % msg)


def info(msg):
    print("  [INFO] %s" % msg)


# ── Check 1: Python3 Process Accumulation (OOM Root Cause) ──────────────


def check_python_processes():
    """Detect runaway python3 processes — the #1 cause of OOM on sensors."""
    print_header("CHECK 1: Python3 Process Accumulation")

    # Get all python3 processes with details
    ps_out = run("ps aux --sort=-rss | grep '[p]ython3'")
    if not ps_out:
        ok("No python3 processes running")
        return []

    lines = ps_out.strip().split("\n")
    print("  Found %d python3 processes:" % len(lines))
    print()

    processes = []
    total_rss_kb = 0
    cmd_counts = Counter()

    for line in lines:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        user, pid, cpu, mem, _vsz, rss = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        cmd = parts[10] if len(parts) > 10 else ""

        rss_kb = int(rss)
        total_rss_kb += rss_kb

        # Extract the script name from the command
        script = "unknown"
        for part in cmd.split():
            if part.endswith(".py"):
                script = os.path.basename(part)
                break
        cmd_counts[script] += 1

        processes.append(
            {
                "pid": pid,
                "user": user,
                "cpu": cpu,
                "mem": mem,
                "rss_kb": rss_kb,
                "cmd": cmd[:100],
                "script": script,
            }
        )

    # Display summary by script
    print("  %-35s  %5s  %10s" % ("Script", "Count", "Total RSS"))
    print("  " + "-" * 55)
    for script, count in cmd_counts.most_common(20):
        script_rss = sum(p["rss_kb"] for p in processes if p["script"] == script)
        flag = " ← PROBLEM!" if count > 3 else ""
        print("  %-35s  %5d  %10s%s" % (script, count, bytes_to_human(script_rss * 1024), flag))

    print()
    print(
        "  Total python3 RSS: %s (%d processes)"
        % (bytes_to_human(total_rss_kb * 1024), len(processes))
    )

    # Alert on dangerous accumulation
    if len(processes) > 10:
        crit("%d python3 processes! Likely overlapping cron jobs causing OOM" % len(processes))
    elif len(processes) > 5:
        warn("%d python3 processes — monitor for growth" % len(processes))
    else:
        ok("Process count looks normal")

    # Check for specific duplicates
    for script, count in cmd_counts.items():
        if count > 2 and script != "unknown":
            crit("'%s' has %d instances running simultaneously!" % (script, count))
            crit("  → This is the likely OOM cause. Cron spawns new instances")
            crit(
                "    before previous ones finish. Each uses ~%s RSS."
                % (
                    bytes_to_human(
                        sum(p["rss_kb"] for p in processes if p["script"] == script) // count * 1024
                    )
                )
            )

    return processes


# ── Check 2: Crontab Analysis ───────────────────────────────────────────


def check_crontab():
    """Analyse crontab for overlapping sensor jobs."""
    print_header("CHECK 2: Crontab Analysis")

    crontab = run("crontab -l 2>/dev/null")
    if not crontab:
        info("No user crontab found (checking /etc/cron.d/)")
        crontab = ""
        for f in os.listdir("/etc/cron.d/") if os.path.isdir("/etc/cron.d/") else []:
            try:
                with open("/etc/cron.d/%s" % f) as fh:
                    content = fh.read()
                    if "python" in content or "sensor" in content:
                        crontab += "\n# /etc/cron.d/%s\n%s" % (f, content)
            except Exception as _exc:  # silent: best effort crontab read, skip unreadable files
                logging.getLogger(__name__).debug("ignored: %s", _exc)

    if not crontab:
        info("No crontab entries found")
        return

    print("  Active cron jobs with python/sensor:")
    print()

    dangerous = []
    for line in crontab.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "python" in line or "sensor" in line:
            print("  %s" % line)

            # Check if it has a lock/flock mechanism
            has_lock = any(x in line for x in ("flock", "lockfile", "pidof", "pgrep"))
            if not has_lock:
                dangerous.append(line)

    if dangerous:
        print()
        warn("%d cron jobs WITHOUT lock protection:" % len(dangerous))
        for d in dangerous:
            warn("  %s" % d[:100])
        print()
        info("FIX: Wrap each cron job with flock to prevent overlapping:")
        info("  Before: */15 * * * * cd /opt/sensor && python script.py")
        info(
            "  After:  */15 * * * * flock -xn /tmp/script.lock -c 'cd /opt/sensor && source venv/bin/activate && python script.py'"
        )
        info("")
        info("  flock -xn = exclusive lock, non-blocking (skip if already running)")
    else:
        ok("All cron jobs appear to have lock protection (or none found)")


# ── Check 3: System Memory ──────────────────────────────────────────────


def check_memory():
    """Check system memory pressure."""
    print_header("CHECK 3: System Memory")

    meminfo = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = parts[1].strip().split()[0]
                    meminfo[key] = int(val)
    except Exception:
        warn("Cannot read /proc/meminfo")
        return

    total = meminfo.get("MemTotal", 0) * 1024
    free = meminfo.get("MemFree", 0) * 1024
    available = meminfo.get("MemAvailable", 0) * 1024
    buffers = meminfo.get("Buffers", 0) * 1024
    cached = meminfo.get("Cached", 0) * 1024
    swap_total = meminfo.get("SwapTotal", 0) * 1024
    swap_free = meminfo.get("SwapFree", 0) * 1024
    swap_used = swap_total - swap_free

    used = total - free - buffers - cached
    pct_used = (used / total * 100) if total else 0
    pct_available = (available / total * 100) if total else 0

    print("  Total:     %s" % bytes_to_human(total))
    print("  Used:      %s (%.1f%%)" % (bytes_to_human(used), pct_used))
    print("  Available: %s (%.1f%%)" % (bytes_to_human(available), pct_available))
    print("  Buffers:   %s" % bytes_to_human(buffers))
    print("  Cached:    %s" % bytes_to_human(cached))
    if swap_total:
        print(
            "  Swap:      %s / %s (%.1f%%)"
            % (
                bytes_to_human(swap_used),
                bytes_to_human(swap_total),
                (swap_used / swap_total * 100) if swap_total else 0,
            )
        )

    if pct_available < 5:
        crit("CRITICAL: Only %.1f%% memory available — OOM imminent!" % pct_available)
    elif pct_available < 15:
        warn("Low memory: %.1f%% available" % pct_available)
    else:
        ok("Memory looks healthy: %.1f%% available" % pct_available)

    # Check OOM killer history
    oom_count = run("dmesg | grep -c 'Out of memory' 2>/dev/null")
    if oom_count and int(oom_count) > 0:
        crit(
            "OOM killer has been triggered %s times! (check: dmesg | grep 'Out of memory')"
            % oom_count
        )

        # Show last OOM kills
        oom_last = run("dmesg | grep 'Killed process' | tail -5")
        if oom_last:
            print()
            info("Last OOM kills:")
            for line in oom_last.split("\n"):
                info("  %s" % line.strip()[:100])


# ── Check 4: Disk Space ────────────────────────────────────────────────


def check_disk():
    """Check disk usage."""
    print_header("CHECK 4: Disk Space")

    df_out = run("df -h / /opt /var /tmp 2>/dev/null | sort -u")
    if df_out:
        print("  %s" % df_out.replace("\n", "\n  "))

    # Check PostgreSQL data directory size
    pg_size = run(
        "du -sh /var/lib/pgsql/data 2>/dev/null || du -sh /var/lib/postgresql 2>/dev/null"
    )
    if pg_size:
        print()
        info("PostgreSQL data: %s" % pg_size.split()[0] if pg_size else "unknown")

    # Check sensor directory
    sensor_size = run("du -sh /opt/sensor 2>/dev/null || du -sh /home/honeypot_prod 2>/dev/null")
    if sensor_size:
        info("Sensor directory: %s" % sensor_size.split()[0] if sensor_size else "unknown")

    # Check pcap directory
    pcap_size = run(
        "du -sh /opt/sensor/pcaps 2>/dev/null || du -sh /home/honeypot_prod/pcaps 2>/dev/null"
    )
    if pcap_size:
        info("PCAP directory: %s" % pcap_size.split()[0] if pcap_size else "unknown")

    # Check for full filesystems
    df_pct = run("df --output=pcent / | tail -1")
    if df_pct:
        pct = int(df_pct.strip().rstrip("%"))
        if pct > 90:
            crit("Root filesystem %d%% full!" % pct)
        elif pct > 80:
            warn("Root filesystem %d%% full" % pct)
        else:
            ok("Root filesystem %d%% used" % pct)


# ── Check 5: PostgreSQL Connections ─────────────────────────────────────


def check_postgres():
    """Check PostgreSQL connection count and health."""
    print_header("CHECK 5: PostgreSQL Connections")

    try:
        from honeylens.database import legacy_get_db as _legacy_get_db

        conn = _legacy_get_db()
        cur = conn.cursor()

        # Active connections
        cur.execute("""
            SELECT count(*), state
            FROM pg_stat_activity
            WHERE datname = current_database()
            GROUP BY state
            ORDER BY count DESC
        """)
        rows = cur.fetchall()
        total = sum(r[0] for r in rows)
        print("  Active connections: %d" % total)
        for count, state in rows:
            print("    %s: %d" % (state or "NULL", count))

        if total > 50:
            crit("Too many connections (%d) — possible connection leak!" % total)
        elif total > 20:
            warn("High connection count: %d" % total)
        else:
            ok("Connection count normal: %d" % total)

        # Max connections
        cur.execute("SHOW max_connections")
        max_conn = cur.fetchone()[0]
        info("Max connections: %s (%.0f%% used)" % (max_conn, total / int(max_conn) * 100))

        # Long-running queries
        cur.execute("""
            SELECT pid, now() - query_start AS duration, state, query
            FROM pg_stat_activity
            WHERE state != 'idle'
              AND query NOT LIKE '%pg_stat_activity%'
              AND now() - query_start > interval '60 seconds'
            ORDER BY duration DESC
            LIMIT 5
        """)
        long_queries = cur.fetchall()
        if long_queries:
            warn("%d queries running longer than 60 seconds:" % len(long_queries))
            for pid, duration, state, query in long_queries:
                warn("  PID %s, %s, %s: %s" % (pid, duration, state, query[:80]))
        else:
            ok("No long-running queries")

        # Database size
        cur.execute("SELECT pg_size_pretty(pg_database_size(current_database()))")
        db_size = cur.fetchone()[0]
        info("Database size: %s" % db_size)

        # Table sizes
        cur.execute("""
            SELECT relname, pg_size_pretty(pg_total_relation_size(c.oid))
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'r'
            ORDER BY pg_total_relation_size(c.oid) DESC
            LIMIT 5
        """)
        print()
        info("Largest tables:")
        for name, size in cur.fetchall():
            info("  %-30s %s" % (name, size))

        conn.close()

    except ImportError:
        warn("Cannot import core.database — skipping DB checks")
    except Exception as e:
        warn("PostgreSQL check failed: %s" % str(e)[:100])


# ── Check 6: Sensor Services ───────────────────────────────────────────


def check_services():
    """Check sensor systemd services."""
    print_header("CHECK 6: Sensor Services")

    services = [
        "sensor-capture",
        "sensor-honeypot",
        "sensor-api",
        "sensor-ai",
        "sensor-profiler",
        "postgresql",
    ]

    for svc in services:
        status = run("systemctl is-active %s 2>/dev/null" % svc)
        if status == "active":
            # Get memory usage
            mem = run("systemctl show %s --property=MemoryCurrent 2>/dev/null" % svc)
            mem_val = ""
            if mem and "=" in mem:
                try:
                    mem_bytes = int(mem.split("=")[1])
                    if mem_bytes > 0:
                        mem_val = " (%s)" % bytes_to_human(mem_bytes)
                except (ValueError, IndexError):
                    pass  # silent: best effort memory usage parse
            ok("%-20s active%s" % (svc, mem_val))
        elif status == "inactive":
            info("%-20s inactive (not running)" % svc)
        elif status == "failed":
            crit("%-20s FAILED!" % svc)
            # Show last journal entries
            journal = run("journalctl -u %s -n 3 --no-pager 2>/dev/null" % svc)
            if journal:
                for line in journal.split("\n")[-3:]:
                    info("  %s" % line.strip()[:100])
        else:
            info("%-20s not found (may use different name)" % svc)


# ── Check 7: Zombie / Defunct Processes ────────────────────────────────


def check_zombies():
    """Check for zombie/defunct processes."""
    print_header("CHECK 7: Zombie Processes")

    zombies = run("ps aux | grep '[d]efunct'")
    if zombies:
        count = len(zombies.strip().split("\n"))
        warn("%d zombie processes found:" % count)
        for line in zombies.strip().split("\n")[:10]:
            warn("  %s" % line[:100])
    else:
        ok("No zombie processes")


# ── Check 8: Recent OOM Kills ──────────────────────────────────────────


def check_oom_history():
    """Analyse OOM kill history from dmesg/journal."""
    print_header("CHECK 8: OOM Kill History")

    # Try dmesg first
    oom_lines = run(
        "dmesg -T 2>/dev/null | grep -i 'out of memory\\|killed process\\|oom' | tail -20"
    )

    if not oom_lines:
        # Try journalctl
        oom_lines = run(
            "journalctl -k --no-pager 2>/dev/null | grep -i 'out of memory\\|killed process\\|oom' | tail -20"
        )

    if oom_lines:
        kills = [
            ln for ln in oom_lines.split("\n") if "Killed process" in ln or "killed process" in ln
        ]
        oom_events = [
            ln for ln in oom_lines.split("\n") if "Out of memory" in ln or "out of memory" in ln
        ]

        if oom_events:
            crit("%d OOM events detected!" % len(oom_events))

        if kills:
            crit("%d processes killed by OOM killer:" % len(kills))
            # Parse killed processes
            killed_procs = Counter()
            for line in kills:
                match = re.search(r"Killed process \d+ \(([^)]+)\)", line)
                if match:
                    killed_procs[match.group(1)] += 1

            for proc, count in killed_procs.most_common(10):
                crit("  %-20s killed %d times" % (proc, count))

            print()
            info("Last 5 OOM events:")
            for line in oom_lines.split("\n")[-5:]:
                info("  %s" % line.strip()[:120])
        else:
            ok("No OOM kills found in kernel log")
    else:
        ok("No OOM events found in dmesg/journal")


# ── Fix: Generate Safe Crontab ──────────────────────────────────────────


def show_cron_fix():
    """Show recommended crontab with flock protection."""
    print_header("RECOMMENDED CRONTAB (with flock protection)")

    print("""
  Replace your current crontab with flock-protected versions:

  # Correlation engine (every 15 min — flock prevents overlap)
  */15 * * * * flock -xn /tmp/sensor_correlation.lock -c 'cd /opt/sensor && source venv/bin/activate && python correlation_engine.py >> logs/correlation.log 2>&1'

  # Fingerprint backfill (every hour — flock prevents overlap)
  0 * * * * flock -xn /tmp/sensor_backfill.lock -c 'cd /opt/sensor && source venv/bin/activate && python backfill_fingerprints.py --limit 10000 >> logs/backfill.log 2>&1'

  # Session cleanup (every 30 min)
  */30 * * * * flock -xn /tmp/sensor_session_cleanup.lock -c 'cd /opt/sensor && source venv/bin/activate && python -c "from session_manager import cleanup_expired; cleanup_expired()" >> logs/session_cleanup.log 2>&1'

  # Blog auto-publish (if enabled, every hour)
  # 0 * * * * flock -xn /tmp/sensor_blog.lock -c 'cd /opt/sensor && source venv/bin/activate && python blog_publisher.py --auto >> logs/blog.log 2>&1'

  KEY: flock -xn /tmp/NAME.lock -c 'COMMAND'
    -x  = exclusive lock (only one instance)
    -n  = non-blocking (skip if already running, don't queue)
    /tmp/NAME.lock = lock file (unique per job)
""")


# ── Fix: Kill Duplicate Processes ───────────────────────────────────────


def kill_duplicates():
    """Kill duplicate python3 cron job processes (keep newest)."""
    print_header("KILLING DUPLICATE PYTHON3 PROCESSES")

    ps_out = run("ps -eo pid,ppid,etimes,cmd --sort=-etimes | grep '[p]ython3.*\\.py'")
    if not ps_out:
        ok("No python3 script processes found")
        return

    # Group by script name
    by_script = defaultdict(list)
    for line in ps_out.strip().split("\n"):
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        pid, ppid, elapsed, cmd = parts[0], parts[1], parts[2], parts[3]

        script = "unknown"
        for part in cmd.split():
            if part.endswith(".py"):
                script = os.path.basename(part)
                break

        by_script[script].append(
            {
                "pid": int(pid),
                "ppid": int(ppid),
                "elapsed": int(elapsed),
                "cmd": cmd[:100],
            }
        )

    killed = 0
    for script, procs in by_script.items():
        if len(procs) <= 1:
            continue

        # Sort by elapsed time (oldest first)
        procs.sort(key=lambda p: p["elapsed"], reverse=True)

        warn("'%s' has %d instances — killing %d oldest:" % (script, len(procs), len(procs) - 1))

        # Keep the newest (last in sorted list), kill the rest
        for p in procs[:-1]:
            try:
                os.kill(p["pid"], 9)  # SIGKILL
                warn("  Killed PID %d (running %ds): %s" % (p["pid"], p["elapsed"], p["cmd"][:80]))
                killed += 1
            except ProcessLookupError:
                info("  PID %d already gone" % p["pid"])
            except PermissionError:
                warn("  Cannot kill PID %d — run as root" % p["pid"])

    if killed:
        ok("Killed %d duplicate processes" % killed)
    else:
        ok("No duplicates to kill")


# ── Main ────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Sensor Health Diagnostics")
    parser.add_argument(
        "--fix-cron", action="store_true", help="Show recommended crontab with flock protection"
    )
    parser.add_argument(
        "--kill-duplicates",
        action="store_true",
        help="Kill duplicate python3 cron processes (keep newest)",
    )
    parser.add_argument("--watch", action="store_true", help="Continuous monitoring (5s interval)")
    args = parser.parse_args()

    if args.fix_cron:
        show_cron_fix()
        return

    if args.kill_duplicates:
        kill_duplicates()
        return

    if args.watch:
        print("Monitoring (Ctrl+C to stop)...")
        while True:
            ts = datetime.now(UTC).strftime("%H:%M:%S")
            py_count = run("pgrep -c python3 2>/dev/null") or "0"
            mem = run('free -m | awk \'/Mem:/{print $3"/"$2"MB ("int($3/$2*100)"%%)"}\'')
            print("[%s] python3: %s procs | mem: %s" % (ts, py_count, mem))
            time.sleep(5)
        return

    print()
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print(
        "║        SENSOR HEALTH DIAGNOSTIC — %s                    ║"
        % (datetime.now(UTC).strftime("%Y-%m-%d %H:%M"))
    )
    print("╚══════════════════════════════════════════════════════════════════════╝")

    check_python_processes()
    check_crontab()
    check_memory()
    check_disk()
    check_postgres()
    check_services()
    check_zombies()
    check_oom_history()

    print()
    print("=" * 70)
    print("  DONE — Review [CRIT] and [WARN] items above.")
    print("  Run with --fix-cron to see recommended crontab.")
    print("  Run with --kill-duplicates to clean up now.")
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
