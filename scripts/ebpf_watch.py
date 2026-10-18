"""eBPF listener on the host: ``sensor_tcp.c`` from 0.9 attached to the interface, JSON goes to stdout
for every TCP packet to the given destination port (source address and port, flags, TTL).

The third of the three independent sources in the Phase 2c test (honeypot, Suricata, eBPF) — see
the 1.0 plan. Run as a transient unit from under /opt, not from under /home (SELinux):

    sudo systemd-run --unit=ebpf-watch --working-directory=/opt/ebpf-test \
        /opt/ebpf-test/venvA/bin/python ebpf_watch.py eth0 8888 600
    sudo journalctl -u ebpf-watch -o cat

Usage: ebpf_watch.py IFACE PORT SECONDS  (``ebpf/`` directory next to the script or in ``EBPF_DIR``).
Note: the raw socket sees the packet BEFORE DNAT — with the 80 → 8888 redirect we listen on 80.
"""

import json
import os
import socket
import struct
import sys
import time
from pathlib import Path

from bcc import BPF

iface, port, secs = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
here = Path(os.environ.get("EBPF_DIR", Path(__file__).resolve().parent))
b = BPF(src_file=str(here / "ebpf" / "sensor_tcp.c"))
fn = b.load_func("packet_filter", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(fn, iface)


def ip(n):
    return socket.inet_ntoa(struct.pack("I", n))


def cb(cpu, data, size):
    e = b["events"].event(data)
    if socket.ntohs(e.dst_port) == port:
        print(
            json.dumps(
                {
                    "t": round(time.time(), 3),
                    "src": ip(e.src_ip),
                    "sport": socket.ntohs(e.src_port),
                    "dst": ip(e.dst_ip),
                    "dport": port,
                    "flags": e.tcp_flags,
                    "ttl": e.ttl,
                }
            ),
            flush=True,
        )


b["events"].open_perf_buffer(cb, page_cnt=64)
print(
    json.dumps({"ready": True, "iface": iface, "port": port, "python": sys.version.split()[0]}),
    flush=True,
)
end = time.time() + secs
while time.time() < end:
    b.perf_buffer_poll(timeout=200)
