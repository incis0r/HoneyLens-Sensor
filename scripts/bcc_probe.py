"""Phase 2a probe: does BCC under the given interpreter compile, attach and deliver events
from the 0.9 line's eBPF programs.

Run as root, identically under the system 3.9 (the reference) and under the 3.12 venv:

    sudo /usr/bin/python3  scripts/bcc_probe.py eth0 8 > probe39.json
    sudo .venv/bin/python  scripts/bcc_probe.py eth0 8 > probe312.json

Expects an ``ebpf/`` directory with the .c programs next to it (or in ``EBPF_DIR``). The output is
JSON: compile and attach status of every program, the list of event-struct fields,
the event count and the first event from each program. The two outputs are compared field by field,
skipping those that vary by nature (ip_id, source ports, sequence numbers).

Measurement on Rocky 9.8 (BCC 0.35, kernel 5.14): 3.9 and 3.12 identical.
"""

import ctypes
import json
import os
import subprocess
import sys
import time
from pathlib import Path

IFACE = sys.argv[1] if len(sys.argv) > 1 else "eth0"
SECONDS = int(sys.argv[2]) if len(sys.argv) > 2 else 8
HERE = Path(os.environ.get("EBPF_DIR", Path(__file__).resolve().parent))

out = {"python": sys.version.split()[0], "programs": {}}
import bcc  # noqa: E402
from bcc import BPF  # noqa: E402

out["bcc"] = bcc.__version__

counters = {}
first_event = {}


def make_cb(name, table):
    def cb(cpu, data, size):
        counters[name] = counters.get(name, 0) + 1
        if name not in first_event:
            ev = table.event(data)
            first_event[name] = {
                f: (
                    getattr(ev, f)
                    if not isinstance(getattr(ev, f), ctypes.Array)
                    else bytes(getattr(ev, f))[:8].hex()
                )
                for f, _ in ev._fields_
            }

    return cb


bpfs = []
for src in ("sensor_tcp.c", "sensor_udp.c", "sensor_deep.c"):
    rec = {}
    t0 = time.time()
    try:
        b = BPF(src_file=str(HERE / "ebpf" / src))
        rec["compile_s"] = round(time.time() - t0, 2)
        fn = b.load_func("packet_filter", BPF.SOCKET_FILTER)
        BPF.attach_raw_socket(fn, IFACE)
        rec["attached_fd"] = fn.sock
        tbl = b["events"]
        rec["event_fields"] = (
            [f for f, _ in tbl.event(bytes(4096))._fields_] if hasattr(tbl, "event") else None
        )
        tbl.open_perf_buffer(make_cb(src, tbl), page_cnt=64)
        rec["maps"] = sorted(b.tables.keys()) if hasattr(b, "tables") else sorted(k for k in b)
        bpfs.append((src, b))
        rec["status"] = "ok"
    except Exception as e:
        rec["status"] = f"FAIL: {type(e).__name__}: {e}"
    out["programs"][src] = rec

rec = {}
try:
    t0 = time.time()
    b = BPF(src_file=str(HERE / "ebpf" / "ebpf_ttl_deception.c"))
    rec["compile_s"] = round(time.time() - t0, 2)
    fn = b.load_func("ttl_deception", BPF.SCHED_CLS)
    rec["loaded_fd"] = fn.fd
    rec["maps"] = sorted(b.tables.keys()) if hasattr(b, "tables") else None
    rec["status"] = "ok (load_func SCHED_CLS; TC attach is done by pyroute2, independent of BCC)"
except Exception as e:
    rec["status"] = f"FAIL: {type(e).__name__}: {e}"
out["programs"]["ebpf_ttl_deception.c"] = rec

# traffic: SYN to closed ports, DNS/UDP, ICMP — all through IFACE
traffic = subprocess.Popen(  # deliberately shell: a constant command, a loop with timeouts
    "for i in 1 2 3; do (timeout 1 bash -c 'echo > /dev/tcp/1.1.1.1/81' 2>/dev/null; "
    "nc -u -z -w1 8.8.8.8 53 2>/dev/null; ping -c1 -W1 1.1.1.1 >/dev/null 2>&1; sleep 1); done",
    shell=True,
)
deadline = time.time() + SECONDS
while time.time() < deadline:
    for _, b in bpfs:
        b.perf_buffer_poll(timeout=200)
traffic.wait()
out["events"] = counters
out["first_event"] = first_event
print(json.dumps(out, indent=1, default=str))
