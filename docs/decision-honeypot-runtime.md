# Decision: honeypot runtime layer in containers

**Made:** 2026-09-20 (Dariusz: "every honeypot is a container") · **Applies to:** layer 5 of Phase 3
· Extends [`decision-containers.md`](decision-containers.md) and the Phase 2c measurement.

## What we found in 0.9

Two honeypot families with different contracts with the rest of the sensor:

| Family | Modules | How they run | How events persist |
|---|---|---|---|
| **A. `hp_*` on `BaseHoneypot`** (31 modules + `ics/`) | `hp_modbus`, `hp_smb`, `hp_redis`, … | one systemd unit per honeypot, `python3-hp` with `CAP_NET_BIND_SERVICE`, user `sensor` | **straight to PostgreSQL** via `_base.log_event` (`db_cursor`), with classification, `attack_patterns`, `ics_events` and SIEM inside the honeypot process |
| **B. legacy** (the `honeypot.py` monolith, FortiGate, PAN-OS ×2, K8s, LLM, nginx) | 7 modules | systemd units, some as root | **JSON lines** to files under `HONEYPOTNG_LOG_DIR` or `/var/log/honeypot_*.json`; `ingest/honeypot.py` and per-honeypot ingests lift them into the database |

Family A has database credentials inside the process that parses untrusted input from the
internet. In a systemd unit on the host one could live with that; in a container it negates
the very reason the container exists.

## Decisions

1. **One contract: the honeypot writes JSON lines, the ingest lifts them into the database.**
   Family A moves to the JSON sink (`honeypots/sink.py`). *Change from the original
   wording:* not the same flat format as family B, but an envelope with a `schema:
   honeylens-event/1` field and the honeypot's event kept separately in `event` — the
   honeypot's keys (`protocol`, `payload`, `severity`) must not overwrite the envelope, and
   `metadata` in the database is exactly what it was. The ingest recognises both shapes in
   one place (`_normalise`) and for the new one does what `_base.log_event` used to do:
   identity `honeypot-<name>` in `source`, the honeypot's verdict without being overridden
   by the classifier, `attack_patterns` with weight and confidence, `ics_events`, request
   bytes (`raw_hex` → `full_payload` with a digest over what was stored), canaries, SIEM.
   The LLM honeypot forwards an `llm` block to its own table (migration 0008 instead of
   `CREATE TABLE` in honeypot code). **The honeypot container does not know the database**
   — guarded by the test `test_honeypots_never_import_the_database`.
2. **One image per honeypot, from a single `Containerfile`.** `containers/honeypot/Containerfile`
   with the argument `HONEYPOT=<name>` builds the image `honeylens/hp-<name>` with the
   `honeylens` package and the command `honeylens-hp <name>`. The honeypot manifest
   (`honeylens.honeypots.manifest`) is the single source of truth: name → module, class,
   internal port, transport (TCP/UDP), whether it needs TLS, identity directory.
3. **One quadlet per honeypot, rootless, pasta network, non-root process** — per the 2c
   measurement and Dariusz's decision (2026-09-20): *"ports < 1024 on the container side on
   high ports from a non-root user, ideally the honeypot should not run as root inside the
   container at all"*. The image has a user `honeylens` (uid 1000), the quadlet sets
   `UserNS=keep-id:uid=1000` (the same uid as the host user, so files on the volumes are
   theirs) and `DropCapability=ALL` with no `AddCapability` whatsoever. A protocol port
   ≥ 1024 the honeypot binds directly; < 1024 it binds as **`30000 + port`** (22 → 30022),
   the same number is published on the host, and firewalld does DNAT from the protocol
   port (`firewalld-forwards.sh` from the generator). The event carries the protocol port:
   `HONEYLENS_PORT_MAP` from the manifest translates the bound port back in one place
   (`sink.public_port`), because the classifier and the ICS context look at `dst_port` —
   502, not 30502. **The monolith has its own `40000 + port` block for all ports** (Dariusz,
   2026-09-20: "a group of high ports so they do not collide with other honeypots") and a
   service table via `HONEYPOTNG_SERVICES` (in 0.9 a constant in `config.py`, unit as root
   with `CAP_NET_RAW`, which the code does not use) — without 8080/8443, which in the
   monolith belong to Flask (`HONEYWEB_*` → 48080/48443; in 0.9 both bound those ports at
   once and Flask crashed). The `nginx` honeypot has cleartext on 8000, because 8080 stays
   for K8s. After these changes no two units want the same host port; DNAT decides who gets
   the protocol port. The sensor's UI/API is on 60443 (`API_PORT` and `API_TLS_PORT`), next
   to sshd on 62222 — 8080 is a honeypot port, not a sensor port. *Correction of the original
   `1<port>`:* 443 → 10443 collided with FortiGate, and 20000 → 120000 does not fit in 16
   bits. The generator prints port collisions between honeypots — after these changes the
   list is empty. The `honeylens` user on the host with `loginctl enable-linger`.
   TTL/TCP-window rewriting with eBPF (TC egress on the host interface, key = source port)
   **works unchanged** across this boundary — measured 2026-09-20 (plan, layer 5): pasta
   re-emits TCP from the host kernel, and TC egress sees the port after NAT reversal.
   Condition: traffic from outside enters via DNAT from the protocol port, not directly on
   30000+port.
4. **Volumes as host directories** (bind mount, not podman named volumes — the ingest on the
   host must read them by an ordinary path, and a rootless named volume lives in
   `~/.local/share/containers/...`): `<state>/hp-logs` → `/opt/logs` in every container
   (label `:z`, shared with the ingest; the defaults `HONEYPOTNG_LOG_DIR` and `HONEYWEB_LOG_DIR`
   from `config.py` land on it with no variables; FortiGate/PAN-OS vendor files in
   `vendor/`, outside the `*.json` glob) and `<state>/identity/<name>` → `/var/lib/honeylens/identity`
   (`:Z`, private) wherever the honeypot has an identity: certificate, serial number, host key
   — generated on first start, never in the image. PAN-OS HTTPS and PAN-OS SSH share one
   identity (it is one device). The container is `ReadOnly` with `Tmpfs=/tmp`, with no
   privileges at all.
5. **`TZ=UTC` in every container and the zone in the timestamp** — after the 2c measurement,
   where the same packet was at 12:00 in the honeypot and at 14:00 in Suricata.
6. **Family B systemd units** move to the same quadlets; the `honeypot.py` monolith stays a
   single container with many ports (it is one process) until it is broken up into `hp_*`
   — that is a separate task.

## Order of execution

- 5a — code port as in the previous layers (copy, imports, 0.9 tests first).
- 5b — JSON sink in `_base` instead of `db_cursor`; equivalence test: the same JSON line
  that the ingest loads into the same columns as the old `log_event`.
- 5c — manifest, `honeylens-hp`, `Containerfile`, quadlet generator, volumes.
- 5d — measurement: image, three honeypots (TCP, UDP, TLS), ingest on the host,
  source address across the boundary, identity after restart, log on both sides of the
  volume.
