# NGINX Honeypot

A standalone, low-interaction Python honeypot that emulates a vulnerable nginx
server across a **catalog of tracked CVEs**. It classifies inbound exploit
attempts, emits structured JSON events, and requires nothing beyond the Python
standard library.

## What it does

- Presents a realistic `nginx/1.31.2` HTTP `Server` banner (a version inside
  CVE-2026-42533's vulnerable range) to draw version-specific probes.
- Classifies every request against a **CVE signature catalog** (`signatures.py`):
  - **CVE-2026-42533** — script-engine regex-map capture heap overflow
    (heuristic; over-long capture-like tokens in the URI / host-family headers).
  - **CVE-2026-42945** "NGINX Rift" — rewrite-module `/api/` escape-flood (DoS)
    + `ngx_pool_cleanup_s` heap-spray POST (RCE) + `X-Delay` supporting header.
  - **CVE-2013-2028** — chunked `Transfer-Encoding` stack overflow.
  - **CVE-2017-7529** — range filter integer overflow (cache info leak).
  - **CVE-2022-41741/41742** — `ngx_http_mp4_module` probe.
  - **CVE-2021-23017** — resolver off-by-one (banner-draw only; not
    inbound-HTTP-triggerable, so tracked for documentation, never matched).
- Correlates per-request indicators from the same source IP across a time
  window (`SourceTracker`) — a CVE-2026-42945 flood followed by a spray is
  escalated to a full RCE verdict.
- Drops the connection (**fake-crash oracle**) on any overflow-class trigger,
  so an attacker's success check behaves as it would against a crashed worker.
- Writes one JSON event per request to a JSON-lines log file (see `LOG_SCHEMA.md`).

CVE-2026-49975 "HTTP/2 Bomb" is handled on the TLS ALPN-h2 path by the HoneyLens
wrapper's `h2bomb` inspector, not by this cleartext HTTP catalog.

## Run

```bash
python3 -m honeypots.nginx --bind 0.0.0.0 --port 8080 --log /var/log/nginx-honeypot.json
```

Use `--help` for all options. In the HoneyLens sensor it runs as
`sensor-hp-nginx` (TLS 8443 + cleartext HTTP) via `honeypots/hp_nginx.py`.

## Package layout

```
honeypots/nginx/
  __init__.py        # import root
  signatures.py      # the CVE catalog (one CveSignature per tracked CVE)
  detector.py        # catalog-driven classify() + SourceTracker
  eventlog.py        # EventLog + build_event()
  server.py          # make_handler() + serve() (banner + fake-crash oracle)
  __main__.py        # standalone CLI
  LOG_SCHEMA.md      # JSON event schema
  INTEGRATION.md     # how to adopt this into a honeypot framework
  README.md          # this file
```

Tests live at `tests/test_nginx_signatures.py` (byte-exact per signature +
`SourceTracker` correlation + banner).

## Adding a CVE

Append a `CveSignature` to `CATALOG` in `signatures.py` with a small,
exception-safe `match(method, raw_path, headers, body, http_version)` returning
a `Match(indicators, confidence)` or `None`. Set `is_overflow=True` to arm the
fake-crash oracle for memory-corruption CVEs. Add a test.

## Notes

- No external Python dependencies (stdlib only; pytest for tests).
- Every signature `match()` is wrapped so a malformed request can never crash a
  worker — the only connection drop is the deliberate fake-crash oracle.
- The `SourceTracker` correlation window defaults to 120 seconds.
