# NGINX Honeypot — Integration Guide

This document describes how to adopt the `nginx` package into the
HoneyLens honeypot framework (or any other framework). The package has
**no external dependencies** beyond the Python standard library — pytest is
only required for running tests.

There is **no coupling** to the `.134` host, the his-sensor agent, or any
other lab-specific component. All integration points are defined below.

---

## Standalone operation

Run the honeypot without any framework integration:

```bash
python3 -m honeypots.nginx --bind 0.0.0.0 --port 8080 --log /var/log/nginx-honeypot.json
```

Options:
- `--bind` — listen address (default `0.0.0.0`)
- `--port` — listen port (default `8080`)
- `--log`  — path for the JSON-lines event log (default `nginx-honeypot.json`)
- `--quiet` — suppress echoing events to stdout

---

## Integration hook 1 — `EventLog` sink

`EventLog` (`eventlog.py`) is the event delivery mechanism. By default it
appends JSON lines to a file and/or echoes to stdout. To deliver events to a
framework callback instead, subclass or wrap `EventLog`:

```python
from honeypot.eventlog import EventLog


class FrameworkEventLog(EventLog):
    def emit(self, event: dict) -> None:
        # deliver to your framework pipeline instead of (or in addition to) a file
        your_framework.ingest(event)
```

Then pass your subclass to `serve()`:

```python
from honeypot.server import serve

httpd = serve("0.0.0.0", 8080, FrameworkEventLog())
httpd.serve_forever()
```

---

## Integration hook 2 — `classify()` and `SourceTracker`

If your framework already has an HTTP server and only needs the detection
logic, import the detector directly:

```python
from honeypot.detector import classify, SourceTracker

tracker = SourceTracker(window_seconds=120.0)

# For each incoming request:
detection = classify(method, raw_path_bytes, headers_dict, body_bytes)
attack_class = tracker.observe(src_ip, detection, now=time.time())
# detection.matched, detection.attack_class, detection.confidence, detection.indicators
# attack_class is the tracker-correlated verdict (may escalate to rce when flood+spray seen)
```

No HTTP server is needed — these two functions are fully stateless (except for
the per-source correlation window inside `SourceTracker`).

---

## Integration hook 3 — `make_handler()` for custom server wiring

`server.py:make_handler(event_log, tracker)` accepts your own `EventLog` and
`SourceTracker` instances. This lets the framework own the lifecycle of both:

```python
from honeypot.server import make_handler
from honeypot.eventlog import EventLog
from honeypot.detector import SourceTracker
from http.server import ThreadingHTTPServer

event_log = EventLog(path="/var/log/hp.json", also_stdout=False)
tracker = SourceTracker(window_seconds=300.0)
handler_class = make_handler(event_log, tracker)
httpd = ThreadingHTTPServer(("0.0.0.0", 8080), handler_class)
httpd.serve_forever()
```

---

## API summary

```
classify(method: str, raw_path: bytes, headers: dict, body: bytes) -> Detection
    Stateless per-request classifier. Returns a Detection dataclass.

Detection.matched: bool
Detection.attack_class: str  # "cve-2026-42945-dos" | "cve-2026-42945-rce" | "none"
Detection.confidence: str    # "high" | "medium" | "low" | "none"
Detection.indicators: list   # list of indicator strings

SourceTracker(window_seconds=120.0)
SourceTracker.observe(src_ip: str, detection: Detection, now: float) -> str
    Correlates detections from one source; returns the correlated attack_class.

EventLog(path: str | None = None, also_stdout: bool = True)
EventLog.emit(event: dict) -> None
    Thread-safe JSON-lines sink.

build_event(src_ip, method, raw_path, headers, body, detection, attack_class) -> dict
    Assembles one event dict matching LOG_SCHEMA.md.

serve(bind: str, port: int, event_log: EventLog) -> ThreadingHTTPServer
    Creates and returns a ready-to-serve honeypot server.

make_handler(event_log: EventLog, tracker: SourceTracker) -> type
    Returns the handler class for use with any BaseHTTPServer-compatible server.
```

---

## Dependencies

- **Runtime:** Python 3.9+ standard library only (`http.server`, `threading`,
  `json`, `re`, `dataclasses`, `datetime`).
- **Tests:** `pytest` (version 8+). Run from `lab/`: `python3 -m pytest honeypot/ -q`.
- **No external packages required.** No `.134`/his-sensor coupling.

See `LOG_SCHEMA.md` for the full event schema.
