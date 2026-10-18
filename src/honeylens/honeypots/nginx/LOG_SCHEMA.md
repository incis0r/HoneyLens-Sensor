# NGINX Honeypot — Log Schema

Every event emitted by `build_event()` (see `eventlog.py`) is a single JSON
object written as one line to the event log file (JSON-lines format). This
document defines every field, its type, and its semantics.

---

## Top-level fields

| Field    | Type   | Description |
|----------|--------|-------------|
| `ts`     | string | ISO 8601 UTC timestamp of when the request was classified (e.g. `2026-05-22T14:32:01.123456+00:00`). |
| `sensor` | string | Always `"nginx-honeypot"`. Identifies this emitter to downstream consumers. |
| `cve`    | string | The CVE this request matched (e.g. `"CVE-2026-42533"`), or `""` on no match. |
| `src_ip` | string | Source IP address of the HTTP client. |
| `http`   | object | Per-request HTTP fields (see below). |
| `detection` | object | Classification result for this request (see below). |

---

## `http` object fields

| Field        | Type    | Description |
|--------------|---------|-------------|
| `method`     | string  | HTTP method as received (`GET`, `POST`, `HEAD`, …). |
| `path`       | string  | Raw request path (decoded from `latin-1`; percent-encoding preserved as sent by the client). |
| `headers`    | object  | Dictionary of all request headers; keys and values are strings. |
| `body_len`   | integer | Number of bytes in the request body (capped at 1 MiB internally). |

---

## `detection` object fields

| Field          | Type    | Description |
|----------------|---------|-------------|
| `matched`      | boolean | `true` if any exploit indicator was found, `false` for benign traffic. |
| `attack_class` | string  | Short class key, e.g. `cve-2026-42945-rce`, `cve-2026-42533`, or `none`. |
| `attack_type`  | string  | Emitted label, e.g. `NGINX_CVE_2026_42533` or `cve_2026_42945_rce`. |
| `cve_id`       | string  | The matched CVE id (e.g. `CVE-2013-2028`), or `""`. |
| `is_overflow`  | boolean | `true` for memory-corruption CVEs — these arm the fake-crash oracle. |
| `confidence`   | string  | One of `"high"`, `"medium"`, `"low"`, `"none"`. |
| `indicators`   | array   | List of indicator strings fired for this request (see indicator vocabulary below). |

Note: `indicators` are observations collected from the individual request and may be non-empty even when `matched` is `false`. For example, a request carrying an `X-Delay` header but no flood or spray will produce `["slow_backend_delay_header"]` with `matched=false` — because `slow_backend_delay_header` is a context indicator, not an attack-class trigger on its own. `matched` reflects whether an attack class was assigned to the request, not whether any indicator was present.

---

## Attack-class vocabulary

| Value                   | Meaning |
|-------------------------|---------|
| `cve-2026-42945-dos`    | Overflow trigger detected in an `/api/` URI — heap overflow that crashes a worker (DoS). |
| `cve-2026-42945-rce`    | Pool-spray POST body detected, possibly combined with the overflow trigger — full RCE attempt. |
| `none`                  | No exploit indicator matched; request appears benign. |

Note: `SourceTracker.observe()` may escalate a per-request `attack_class` to
`cve-2026-42945-rce` when a flood and a spray from the same source are observed
within the correlation window.

---

## Indicator vocabulary

| Indicator                    | Meaning |
|------------------------------|---------|
| `api_escape_flood:<n>`       | An `/api/` URI contained a run of `<n>` escapable characters (`+` or `%2B`/`%2b`) meeting or exceeding the flood threshold (8). `<n>` is the integer count. |
| `pool_spray_body`            | A POST body with length >= 256 bytes contained both a NUL byte and the 0x41-padding pattern used by the depthfirst PoC to fill the fake `ngx_pool_cleanup_s` spray body. |
| `slow_backend_delay_header`  | The request carried an `X-Delay` header (case-insensitive), which the depthfirst PoC uses to hold a slow-backend connection open across the overflow window. |

---

## Example events

### DoS event (overflow trigger in `/api/` URI)

```json
{
  "ts": "2026-05-22T14:32:01.123456+00:00",
  "sensor": "nginx-honeypot",
  "cve": "CVE-2026-42945",
  "src_ip": "192.0.2.44",
  "http": {
    "method": "GET",
    "path": "/api/AAAA+++++++++++++++++++++++++++++++++++++++",
    "headers": {"Host": "192.0.2.78:19321", "Connection": "close"},
    "body_len": 0
  },
  "detection": {
    "matched": true,
    "attack_class": "cve-2026-42945-dos",
    "confidence": "medium",
    "indicators": ["api_escape_flood:40"]
  }
}
```

### RCE event (heap-spray POST body)

```json
{
  "ts": "2026-05-22T14:32:02.456789+00:00",
  "sensor": "nginx-honeypot",
  "cve": "CVE-2026-42945",
  "src_ip": "192.0.2.44",
  "http": {
    "method": "POST",
    "path": "/spray",
    "headers": {
      "Host": "192.0.2.78:19321",
      "Content-Length": "4008",
      "X-Delay": "60",
      "Connection": "close"
    },
    "body_len": 4008
  },
  "detection": {
    "matched": true,
    "attack_class": "cve-2026-42945-rce",
    "confidence": "medium",
    "indicators": ["pool_spray_body", "slow_backend_delay_header"]
  }
}
```

### Benign event

```json
{
  "ts": "2026-05-22T14:30:00.000000+00:00",
  "sensor": "nginx-honeypot",
  "cve": "CVE-2026-42945",
  "src_ip": "192.0.2.10",
  "http": {
    "method": "GET",
    "path": "/",
    "headers": {"Host": "192.0.2.78:19321", "Connection": "close"},
    "body_len": 0
  },
  "detection": {
    "matched": false,
    "attack_class": "none",
    "confidence": "none",
    "indicators": []
  }
}
```
