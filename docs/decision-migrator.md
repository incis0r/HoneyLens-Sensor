# Decision: migrator 0.9 -> 1.0 (Phase 5, design)

**Settled:** 2026-09-21 · **Status:** design + scaffold; full implementation only once
1.0 is stable (per the plan). Dariusz chose the "design + scaffold" path.

## What we found

The 0.9 line sits on the host as files copied into `/opt/sensor`, with system-level
systemd units (`sensor-hp-*.service`, `sensor-honeypot*.service`) as root, and
PostgreSQL 13 on the same host. The 1.0 line is an installable `honeylens` package, honeypots
in rootless containers (quadlets from the manifest), API on 60443, the same PostgreSQL 13.

Key observation: **this is an in-place upgrade, not a move to a new host.** The fleet
already sits on these hosts. So the migrator does not copy data between machines — it
changes the shape of the installation next to live data.

## Decisions

1. **The database stays in place.** The same PostgreSQL 13, schema descended from 0.9. The
   migrator runs `honeylens-migrate` (idempotent migrations 0001–0009) to add what 0.9 did
   not have (e.g. `llm_honeypot_events`, `full_payload`, FK cascade). Events, archive tables
   and attacker profiles are **not copied** — they are already there. This strikes out most
   of the "data transfer" in the original description of Phase 5.

2. **Honeypot identities are the core of the migration — they must survive bit for bit.**
   A changed serial number, MAC, host key or certificate is a ready-made honeypot
   fingerprint. 0.9 keeps them under flat paths; 1.0 in identity volumes
   (`<state>/identity/<name>`). The migrator **copies** (does not regenerate), preserving
   contents:

   | Honeypot | 0.9 | 1.0 (identity volume) |
   |---|---|---|
   | nginx | `/opt/sensor/certs/nginx.{crt,key}` | `identity/nginx/` |
   | llm | `/opt/sensor/certs/llm.{crt,key}` | `identity/llm/` |
   | wago | `WAGO_IDENTITY_DIR` (`/opt/sensor/data/wago`) | `identity/wago/` |
   | paloalto | `/opt/sensor/data/paloalto` (serial, host key, templates) | `identity/paloalto/` |
   | fortigate | `/opt/sensor/certs/fortigate.{crt,key}` | `identity/fortigate/` |
   | monolith | `TLS_CERT_DIR` (`honey.{crt,key}`) | `identity/honeypot/` |

   A honeypot without an `identity` entry in the manifest (banner honeypots, e.g. `hp_ssh`)
   has nothing to migrate. PAN-OS HTTPS and PAN-OS SSH share one identity (one device).

3. **`.env` is translated, not copied.** `/opt/sensor/.env` -> `/opt/honeylens/.env` with a
   map of changes: `API_PORT` to 60443 (WebUI/API), new `WEBUI_NEW_SHELL`, `DB_ARCHIVE_*`,
   `BACKUP_PASSWORD`, `LDAP_ALLOW_INSECURE_TLS`. Secret values are carried over 1:1
   (`.env` never goes into the repo). The 0.9 honeypot port variables are moot — ports come
   from the manifest; the migrator skips them and reports that it skipped them. Unknown 0.9
   variables are reported, not silently deleted.

4. **Units: system systemd (root) -> rootless quadlets.** The migrator disables the old
   `sensor-hp-*`/`sensor-honeypot*`, generates quadlets from the manifest
   (`honeylens-hp --quadlets`), enables linger for the `honeylens` user. Switching the
   units is the last step — after copying identities and translating the config.

5. **Run safety.** Dry-run is the default (`plan`); mutations only behind `--apply`.
   Order: stop the old units (so as not to copy identities mid-write) -> copy identities ->
   verify (serial number / certificate fingerprint unchanged) -> schema migration ->
   `.env` -> quadlets -> start 1.0. The identity step is reversible (a copy, not a move);
   stopping the fleet is the only irreversible moment and requires confirmation.

## Out of scope for the scaffold (to finish once 1.0 is stable)

Actually switching the live fleet (steps 4/5 with `--apply` in production), rollback after
a failed 1.0 start, and validation on real sensor data. The scaffold implements the plan
(dry-run), identity copy and `.env` translation as real functions behind `--apply`; schema
and quadlets are delegated to the existing `honeylens-migrate` / `honeylens-hp`.
