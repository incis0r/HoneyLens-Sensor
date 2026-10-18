# Honeypot read API

A read-only HTTP API for pulling decoy events off a sensor: per attack, per source
address, per CVE, per decoy. It exists so a SIEM, a partner, or a research script can
have the events of **one** decoy without having an operator account on the sensor.

Every key is read-only, scoped to one decoy, time-limited, and revocable from
`/sensor_admin`.

## Getting started

Five steps, from nothing to events.

1. **An operator issues you a key.** In `/sensor_admin` → *Honeypot Read API Keys* →
   **Generate API Key**: pick the decoy your key is for, a label so it can be recognised
   later, and a validity (30/60/90 days; 365 needs an explicit risk acknowledgment).
2. **Save the three values shown once.** The Basic Auth pair, the ready-made
   `Authorization: Basic …` header, and the `X-API-Key`. They are not recoverable — the
   sensor keeps only an Argon2id hash and a SHA-256 digest. If you lose them, the operator
   revokes the key and issues another.
3. **Check the key works and see what it is scoped to:**

   ```bash
   curl -s -H "$AUTH" -H "$KEY" "$BASE/key-info"
   ```

4. **Find out what you can filter on.** Your `attack` and `cve` terms are resolved against
   the labels *your* decoy has actually produced:

   ```bash
   curl -s -H "$AUTH" -H "$KEY" "$BASE/labels"
   ```

5. **Read events.** Start broad, then narrow:

   ```bash
   curl -s -H "$AUTH" -H "$KEY" "$BASE/events?since=24h&limit=100"
   ```

Where `BASE` is `https://<sensor>:60443/api/v1/honeypot`, `AUTH` is
`Authorization: Basic <the base64 string>` and `KEY` is `X-API-Key: hlk_<token>`.

## What a key holder gets, and what they do not

A key scoped to `fortigate` reads the FortiGate decoy's events. It does not read the
NetScaler decoy's, the monolith's, or the SharePoint decoy's, and it cannot read them by
asking for them — a scoped key naming another decoy gets `403`.

Two things are never in a response, whatever the scope:

* **Our own traffic.** Rows whose `source_class` is set (`own_infra`, `validation`,
  `internal`) are our infrastructure, our scanners and the operator's own address. On one
  sensor that was 1.66M of 13.3M rows. Two filters are applied, not one: `source_class IS
  NULL`, which is migration 0013's "a real actor", **and** an exclusion of the configured
  own, validation and internal networks. The first alone would fail open, because NULL is
  also what a row written before 0013 and never backfilled carries — on those rows it means
  "not computed", not "a real actor".
* **Anything that is not a decoy event.** Suricata alerts and the other non-decoy sources
  are outside the API, including for a `*`-scoped key.

A key cannot write, and cannot reach any path outside `/api/v1/honeypot/`. Both are
enforced in the authentication middleware, before the route runs.

## Credentials

Two things are required on every request, and they are issued together:

| Part | Header | Shape |
|---|---|---|
| HTTP Basic Auth | `Authorization: Basic <base64>` | `apiaccess<N>:<password>` |
| API key | `X-API-Key` | `hlk_<token>` |

Both are shown **once**, when the key is generated. The sensor stores the Basic Auth
password as an Argon2id hash and the API key as a SHA-256 digest, so neither can be
recovered — a lost credential is replaced, not read back.

**The API key goes in the `X-API-Key` header and nowhere else.** It is deliberately not
accepted as a query parameter: this service logs full request lines, so a key in a query
string would be written to the journal in cleartext on every call, and again to the access
log of any proxy in front of it.

## Validity and rotation

* Standard maximum age is **90 days**.
* A key valid for up to **365 days** can be issued, but only with an explicit risk
  acknowledgment from the operator who creates it. The acknowledgment is recorded on the
  key and in the admin audit log.
* `/sensor_admin` raises a rotation banner once a key is within **14 days** of expiry, and
  again once it has expired.
* An expired or revoked key fails authentication immediately, with a reason.
* `GET /api/v1/honeypot/key-info` returns the key's own status and days remaining, so a
  client can alert on its own rotation.

## Endpoints

All are `GET`, all live under `/api/v1/honeypot/`.

| Endpoint | Returns |
|---|---|
| `/labels` | the verdict labels **this key's decoy** has produced — build `attack` and `cve` from these |
| `/key-info` | this key's scope, expiry, days remaining, rotation status |
| `/events` | combined filters: `honeypot`, `attack`, `ip`, `cve`, `since`, `until`, `limit`, `page` |
| `/events/by-attack/{attack}` | events carrying a verdict label matching `{attack}` |
| `/events/by-ip/{ip}` | events from an address or CIDR block |
| `/events/by-cve/{cve}` | events carrying a verdict label naming `{cve}` |
| `/events/by-honeypot/{honeypot}` | events of one decoy (must be within the key's scope) |

### How `attack` and `cve` are matched

Your term is resolved against the labels **your own decoy** has produced — the same list
`/labels` returns, in the same 30-day window, with our own traffic already excluded — and the
query then asks for those labels by equality. It is scoped for the same reason the events
are: a sensor-wide list would tell you which verdicts the other decoys on the box had
produced. The response tells you what your term resolved to:

```json
"matched_labels": { "attack": ["FORTI_CVE", "FORTI_CVE_2022_40684"], "cve": [] }
```

So `attack=FORTI_CVE` finds `FORTI_CVE_2022_40684` as well, and you can see that it did.
A term that matches no label on this sensor is not an error and is not ignored: you get an
empty page, `matched_labels` empty, and a line in `warnings` saying so. A CVE this sensor
has not seen yet therefore behaves like a CVE with no events, which is what it is.

There is no wildcard. `%` and `_` are ordinary characters here, not pattern syntax.

### Time window

Every query has a lower time bound. If you do not pass `since`, it defaults to the last
**30 days**. `since` accepts ISO-8601 (`2026-11-01T00:00:00Z`) or a relative shorthand
(`30m`, `24h`, `7d`, `2w`).

### Limits

* `limit` is capped at 1000 rows per page.
* Paging deeper than offset 100,000 is refused — narrow the window instead.
* Each query runs under a 20-second statement timeout. If it is hit, you get `503` with a
  message naming what to narrow.
* `total` is counted through a capped subquery and is exact up to **100,000**. At the cap
  you get `total: 100000, total_exact: false`, meaning "at least this many" — an exact count
  for a `*`-scoped key took 10.5 s against 4 ms for the page itself.
* The page is fetched before the total is counted, so a count too expensive to finish
  costs you `total` (`null`, `total_exact: false`), not your events.
* `/labels` is cached for 15 minutes per scope. A label appearing on your decoy for the
  first time therefore becomes filterable within that window; the events themselves are
  returned by every other filter in the meantime.

## Examples

```bash
AUTH='Authorization: Basic <the base64 string shown at creation>'
KEY='X-API-Key: hlk_<the token shown at creation>'
BASE='https://sensor.example:60443/api/v1/honeypot'

# which labels exist here
curl -s -H "$AUTH" -H "$KEY" "$BASE/labels"

# this key's own rotation status
curl -s -H "$AUTH" -H "$KEY" "$BASE/key-info"

# everything this key may see, last 24 hours
curl -s -H "$AUTH" -H "$KEY" "$BASE/events?since=24h&limit=200"

# one attacker, last 7 days
curl -s -H "$AUTH" -H "$KEY" "$BASE/events/by-ip/203.0.113.4?since=7d"

# a whole block
curl -s -H "$AUTH" -H "$KEY" "$BASE/events/by-ip/203.0.113.0/24?since=7d"

# per CVE
curl -s -H "$AUTH" -H "$KEY" "$BASE/events/by-cve/CVE-2024-21762?since=30d"

# per attack label
curl -s -H "$AUTH" -H "$KEY" "$BASE/events/by-attack/SSH_BRUTE?since=24h"
```

## Response shape

```json
{
  "honeypot_scope": "fortigate",
  "filters": { "honeypot": "fortigate", "attack": null, "ip": null,
               "cve": "CVE-2024-21762", "since": "...", "until": null },
  "matched_labels": { "attack": [], "cve": ["forti_cve_2024_21762"] },
  "warnings": [],
  "total": 12, "total_exact": true, "page": 1, "limit": 100, "count": 12,
  "events": [ { "event_id": "...", "timestamp": "...", "src_ip": "...",
                "src_port": 0, "dst_ip": "...", "dst_port": 0,
                "protocol": "...", "source": "...", "attack_types": "...",
                "payload": "...", "metadata": {} } ],
  "api_key_meta": { "basic_username": "apiaccess1", "honeypot": "fortigate",
                    "expires_at": "...", "days_remaining": 88,
                    "status": "active", "needs_rotation": false }
}
```

## Status codes

| Code | Meaning |
|---|---|
| `200` | fine — check `warnings` and `matched_labels` |
| `400` | a malformed filter: not an IP or CIDR, not a CVE identifier, unknown decoy name, a filter with no searchable characters, a page too deep |
| `401` | missing or invalid credentials; both parts are required, and both must belong to the same key |
| `403` | the key is scoped to another decoy, or the request is not a `GET`/`HEAD` under `/api/v1/honeypot/` |
| `503` | the query hit the statement timeout; narrow it |

## A client that holds up

Three things a long-running integration has to get right: page through results instead of
asking for one huge page, notice when its own key is about to expire, and tell the three
failure kinds apart. This does all three.

```python
import time
import requests

BASE = "https://sensor.example:60443/api/v1/honeypot"
SESSION = requests.Session()
SESSION.headers.update(
    {
        "Authorization": "Basic <the base64 string shown at creation>",
        "X-API-Key": "hlk_<the token shown at creation>",
    }
)
# The sensor's decoy certificates are per-deployment; point this at your copy of the CA
# rather than turning verification off.
VERIFY = "/etc/pki/tls/certs/honeylens-sensor.pem"


def pages(path, **params):
    """Yield every event matching `params`, one page at a time."""
    params.setdefault("since", "24h")
    params.setdefault("limit", 500)
    page = 1
    while True:
        params["page"] = page
        r = SESSION.get(f"{BASE}{path}", params=params, timeout=90, verify=VERIFY)

        if r.status_code == 503:
            # The query hit the sensor's 20s budget. Narrowing beats retrying.
            raise RuntimeError(f"too expensive, narrow it: {r.json()['detail']}")
        if r.status_code == 403:
            raise RuntimeError(f"outside this key's scope: {r.json()['detail']}")
        if r.status_code == 401:
            raise RuntimeError("key rejected — expired, revoked, or one half missing")
        r.raise_for_status()

        body = r.json()
        for line in body.get("warnings", []):
            print("warning:", line)  # e.g. a term no label here matches

        meta = body.get("api_key_meta") or {}
        if meta.get("needs_rotation"):
            print(f"rotate this key: {meta['status']}, {meta['days_remaining']}d left")

        yield from body["events"]

        if body["count"] < body["limit"]:
            return  # last page
        page += 1
        time.sleep(0.2)  # be kind to a sensor that is also ingesting


for event in pages("/events", attack="SSH_BRUTE", since="7d"):
    print(event["timestamp"], event["src_ip"], event["attack_types"])
```

Two habits worth keeping:

* **Read `matched_labels` the first time you use a new filter.** It says exactly which
  labels your term resolved to. `attack=FORTI_CVE` matching `FORTI_CVE_2022_40684` as well
  is usually what you wanted; if the list is empty, `warnings` tells you why and nothing
  will match.
* **Page by `since`, not by `page`, for a feed.** Keep the newest `timestamp` you have seen
  and ask for `since=<that>` next time. Deep paging is refused past offset 100,000, and a
  moving window is cheaper for the sensor than walking back through pages.

## When something does not work

| What you see | What it means | What to do |
|---|---|---|
| `401` on every call | one half of the credentials is missing, or the key is expired or revoked | both headers are required; `key-info` with a working key shows expiry. A key in the query string is ignored by design |
| `403` naming your scope | you asked for another decoy's events | drop the `honeypot` parameter; a scoped key defaults to its own decoy |
| `403` about read-only | you used something other than `GET`/`HEAD`, or a path outside `/api/v1/honeypot/` | these keys cannot write and cannot reach the rest of the API |
| `400` *contains no searchable characters* | the filter was punctuation only, e.g. `attack=%` | there are no wildcards; use a label from `/labels` |
| `400` *too deep* | paging past offset 100,000 | narrow `since` instead, or follow the newest timestamp |
| `503` naming the budget | the query did not finish in 20s | add `since`, or a more specific filter |
| `503` naming migration 0013 | the sensor cannot tell our own traffic from an actor's | an operator must apply the migration; the API will not guess |
| `200` but `events` empty and a `warnings` line | your term matches no label this decoy has produced | check `/labels`; the decoy may simply never have seen it |
| `total_exact: false` | the count hit the 100,000 cap, or timed out and `total` is `null` | treat `total` as a floor; the events themselves are complete |

## Operating it

* The table comes from migration `0014_honeypot_api_keys.sql`; the index the label lookup
  needs comes from `0015_attack_patterns_rule_name.sql`. Apply both with
  `honeylens-migrate`, with `HONEYLENS_ENV_FILE` pointing at the sensor's env file. The
  code does not create its own schema, so an unmigrated sensor says so instead of quietly
  building the table in the wrong database. Migration `0013_sensor_events_source_class.sql`
  is required too: without `source_class` the API cannot tell our own traffic from an
  actor's and returns `503` rather than guess.
* 0015 builds its index `CONCURRENTLY`, because the migration runner sets a 3-second
  `lock_timeout` and records a migration as applied even when a statement was deferred — a
  plain `CREATE INDEX` on a 13M-row `attack_patterns` would lose the lock to the live ingest
  and leave the index silently absent. After applying, confirm it is valid:

  ```sql
  SELECT indisvalid FROM pg_index
   WHERE indexrelid = 'idx_attack_patterns_rule_name'::regclass;
  ```

  `false` means the concurrent build failed; drop the index and re-run the migration.
* Generating and revoking keys is in `/sensor_admin`. Both are written to the admin audit
  log with the operator, the scope, the validity and the risk acknowledgment. A key created
  or revoked programmatically rather than by an operator is recorded with a NULL actor, not
  dropped — `admin_audit_log.admin_user_id` is nullable for exactly that. If the audit write
  itself fails it is reported in the service journal as "Failed to log admin action".
* A decoy whose `source` shape is not known to `honeypot_scope_sql` returns no rows for its
  scope. That is the intended direction: an operator who expects rows and sees none will
  say so, whereas over-matching would silently hand one key holder another decoy's traffic.
  The same applies to a decoy the monolith serves that is not in `_MONOLITH_SERVES`.
* The scope is an equality test on `source` alone so that it can use `idx_se_source_time`.
  That is what makes a quiet decoy affordable: one page for a decoy with three events in the
  window measured 0.002 s this way against 30.3 s when the predicate also offered
  `metadata->>'honeypot'` and `protocol` as alternatives and the planner had to walk the
  timestamp index instead.
* `SOURCE_CLASS_OWN_INFRA` and `SOURCE_CLASS_VALIDATION` in the sensor's env file are what
  the second own-traffic filter is built from. A sensor with them unset falls back to
  `source_class` plus the RFC1918 and loopback ranges only.
