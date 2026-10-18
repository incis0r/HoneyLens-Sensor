# Decision: every honeypot in a container, eBPF native

**Made:** 2026-09-16 (Dariusz) · **Applies to:** layers 5 and 8 of Phase 3

We containerize all honeypots. The eBPF layer stays native.

## Why this split

**Honeypots gain the most from isolation, because they are the ones eating the attacker's
input.** They parse untrusted data from the internet in a dozen-plus protocols at once — that
is the surface where a bug costs the most. Isolating them from the rest of the sensor and
from each other is worth more than packaging convenience.

**eBPF in a container would be a container in name only.** It needs `CAP_BPF`,
`CAP_NET_ADMIN` and `CAP_SYS_ADMIN`, attaches to host interfaces and reads host kernel
structures. The container would have to get the host network, the host PID namespace and
the full set of privileges — all of the complexity with not a gram of isolation. It stays
native, as it is.

## What we checked before adopting this

Measured on sensor-a, 2026-09-16 — not assumed:

```
honeypots listen on:  2379 3080 3306 6379 6443 8001 8080 8443 8888 10250 10255 15432
DNAT in firewalld:    80 → 8888,  443 → 8443,  5432 → 15432
```

**No honeypot binds a port below 1024.** Privileged ports reach them through a firewalld
redirect. This matters because it means **rootless Podman works without bypassing
anything** — no `net.ipv4.ip_unprivileged_port_start=0`, no `CAP_NET_BIND_SERVICE`. The
existing DNAT pattern carries over unchanged.

## Runtime

**Podman + quadlet** (`.container` files read by the systemd generator). Rocky 9 ships
podman from the rolling `container-tools` stream (quadlet needs ≥ 4.4, the fleet has newer),
does not carry Docker, and quadlet gives us systemd units without generating them by script
— the same management we already have tooling for (`hl-update.sh`, unit control in
`hl-fleet-status.sh`).

## Three things that can go wrong silently

All three belong to the same class we hunt in 0.9: a failure after which the data still
*looks* fine.

### 1. The source address must survive entry into the container

**This is the most serious risk of this decision.** The whole product rests on attacker
attribution — source address, profile, correlation between sensors, evidence packages for
the CERT. If the container network mode does SNAT, **every attacker becomes the gateway
address**, and the database fills up with correct-looking events from a single IP.

We would not notice right away. Events flow, classification works, charts grow.

**Validation before the honeypot port** (Phase 2): a real connection from outside, then a
comparison of three records of the same packet — what the honeypot logged, what Suricata
saw on the host and what eBPF caught. Three independent sources must report the same
source address. A mismatch = the network mode has to change.

### 2. The honeypot's identity must not end up in the image

Every honeypot has a persistent identity — serial number, MAC, hostname — seeded from
`os.urandom` and stored on disk. The reason is plainly defensive: an identical serial
number on two hosts is a ready-made, reliable honeypot fingerprint.

A container image is by definition identical everywhere. **An identity baked into the
image means every deployment of that image has the same serial number** — exactly what
this rule was created against, only worse, because it is repeatable.

The identity goes on a **named volume**, generated on the container's first start, never in
an image layer. The test that guards this must be created together with the first
containerized honeypot — `tests/test_wago_identity.py` in 0.9 is the model.

### 3. The log contract now crosses a boundary

Honeypots write JSON lines, ingests read them and — since 2026-09-15 — truncate the
consumed prefix. That is an assumption of a shared filesystem. In containers we need
either a shared volume or a different transport.

The simplest solution preserving today's semantics: a volume mounted on both sides.
Alternatives (socket, queue) change the truncation contract and would require redesigning
`ingest/logcleanup.py` — worth considering, but not as a side effect.

## Consequence for the security gate

Python dependencies stop being the whole dependency surface. Base images have their own
CVEs and their own life cycle. `ci/security.sh` gains an **image scan (Trivy)**, and the
SBOM gains an image layer alongside the packages.

## Impact on the plan

- **Phase 2** gains an item: validation of source-address preservation in the chosen
  Podman network mode. It goes before the honeypot port, not after it.
- **Phase 3 layer 5** (`honeypots`, 19,096 lines) grows by a runtime layer: images,
  quadlets, identity and log volumes.
- **Phase 3 layer 8** (`ebpf`) unchanged — stays native.
- **Phase 4** (`tools/` at the customer) must account for the honeypot being a container:
  the diagnostic tool has to reach into it the same way it reaches a process today.
