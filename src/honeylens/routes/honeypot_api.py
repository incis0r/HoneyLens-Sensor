"""
routes/honeypot_api.py — Read-Only Honeypot Event Query API (Basic Auth + API Key)
===================================================================================
Provides remote read-only endpoints for fetching honeypot events filtered by:
  - attack (`per attack`: `/api/v1/honeypot/events/by-attack/{attack}`)
  - IP (`per IP`: `/api/v1/honeypot/events/by-ip/{ip}`)
  - CVE (`per CVE`: `/api/v1/honeypot/events/by-cve/{cve}`)
  - honeypot (`per honeypot`: `/api/v1/honeypot/events/by-honeypot/{honeypot}`)
  - combined filters (`/api/v1/honeypot/events`)

  - the verdict labels this sensor carries (`/api/v1/honeypot/labels`), which is where
    the `attack` and `cve` terms above come from

Authentication:
  - Requires BOTH HTTP Basic Auth (`Authorization: Basic base64(apiaccessN:randompass)`)
    AND the API key in the `X-API-Key` header -- never in the query string -- OR an active
    authenticated operator session.
  - Enforces per-honeypot scope: an API key generated for `ssh` can ONLY read events
    from `ssh` (`403 Forbidden` if querying another honeypot).

What never leaves this API:
  - our own traffic. Only rows with `source_class IS NULL` are served, which is migration
    0013's "a real actor"; `own_infra`, `validation` and `internal` rows stay here.
  - anything that is not a decoy event. Suricata and the other non-decoy sources are out
    of scope even for a `*` key.

See docs/honeypot-read-api.md for the contract a key holder is given.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from psycopg2.errors import QueryCanceled

from honeylens.auth.api_key_manager import (
    HoneypotApiKey,
    authenticate_api_key,
    honeypot_scope_sql,
    normalize_honeypot_name,
)
from honeylens.database import db_cursor
from honeylens.intelligence.source_class import excluded_networks
from honeylens.routes._helpers import external_only, strip_cidr

router = APIRouter(prefix="/api/v1/honeypot", tags=["Honeypot Read API"])

_CVE_RE = re.compile(r"^(?:CVE[-_])?(\d{4})[-_](\d{4,7})$", re.IGNORECASE)
_REL_TIME_RE = re.compile(r"^(\d+)\s*([smhdw])$", re.IGNORECASE)

# Every query this router runs is bounded by three things: an indexed scope predicate, a
# time window, and a statement timeout. Without them the per-CVE endpoint was unusable on a
# real sensor -- measured 2026-11-07 on a 13.3M-event store, its substring search over
# `payload` and `metadata::text` did not finish inside 45 s, and the endpoint ran it twice,
# once to count and once to fetch.
_STATEMENT_TIMEOUT_MS = 20_000
_DEFAULT_WINDOW_DAYS = 30
_MAX_OFFSET = 100_000

# `total` is counted through a capped subquery rather than over the whole match. An exact
# count for a `*`-scoped key took 10.54 s against 0.004 s for the page itself, and no caller
# needs to be told "6,530,222" to the unit. Up to the cap the number is exact and
# `total_exact` says so; above it the caller knows there are at least this many.
_COUNT_CAP = 100_000

# Resolving a caller's term to exact labels needs the label vocabulary, not the events.
# `SELECT <col>, COUNT(*) ... GROUP BY 1` over 13.1M attack_patterns rows takes about one
# second because both columns are indexed; the result is small (145 attack types, 1198 rule
# names) and changes rarely, so it is cached per process.
_LABEL_COLUMNS = ("attack_type", "rule_name")
# Long enough that the vocabulary is almost always a cache hit: a miss costs 0.01 s for a
# quiet decoy but 14.26 s for a `*` key. The cost of the TTL is that a label appearing on a
# decoy for the first time becomes filterable up to this long afterwards; the events
# themselves are returned by every other filter in the meantime.
_LABEL_CACHE_TTL_SECONDS = 900.0
_label_cache: dict[tuple[str, str], tuple[float, tuple[str, ...]]] = {}
_label_cache_lock = Lock()


def _normalise_label(value: str) -> str:
    """Fold a label or search term to comparable form: `CVE-2024-21762` -> `cve202421762`."""
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def _own_traffic_exclusion() -> tuple[str, list[Any]]:
    """The two filters that keep our own traffic out of every answer this router gives.

    The first is `external_only()` from `routes/_helpers`, the Phase C provenance predicate
    the nine dashboard queries use: `source_class IS NULL`, written by the ingest that saw
    the event. Sharing it is deliberate -- this API must not drift from what the dashboards
    call "from outside".

    On its own it fails open. NULL is also what a row written before migration 0013 and
    never backfilled carries, so on those rows it means "not computed", not "a real actor".
    For a reader whose output leaves this project that is the expensive direction, so the
    configured own, validation and internal networks are excluded at query time as well,
    from `honeylens.intelligence.source_class` -- the same authority the ingest classifies
    with.

    Where the dashboards degrade to TRUE on an un-migrated sensor so the panels keep
    working, this API refuses to answer. A dashboard showing our own traffic to the operator
    is a cosmetic defect; handing it to a key holder is not.

    A row with no source address has nothing to leak and stays visible, which is the rule
    0013 already states for an address it cannot parse.
    """
    provenance = external_only("se")
    if provenance == "TRUE":
        raise HTTPException(
            status_code=503,
            detail=(
                "This sensor has no source_class column, so the API cannot tell our own "
                "traffic from an actor's and will not serve events. Apply migration "
                "0013_sensor_events_source_class.sql."
            ),
        )
    clauses = [provenance]
    params: list[Any] = []
    networks = excluded_networks()
    if networks:
        clauses.append("(se.src_ip IS NULL OR NOT (se.src_ip <<= ANY(%s::inet[])))")
        params.append(list(networks))
    return " AND ".join(clauses), params


def _label_vocabulary(column: str, scope: str) -> tuple[str, ...]:
    """Distinct `attack_patterns.<column>` values **within `scope`**, cached per scope.

    Scoped deliberately. Served sensor-wide, this told a key holder which verdicts every
    other decoy on the box had produced -- not the events, but their existence, which is
    the same cross-scope disclosure the scope predicate exists to prevent. It is also what
    `attack` and `cve` resolve against, so an unscoped vocabulary would have leaked the
    same thing through `matched_labels`.
    """
    if column not in _LABEL_COLUMNS:
        raise ValueError(f"not a label column: {column}")
    key = (column, scope)
    now = datetime.now(UTC).timestamp()
    with _label_cache_lock:
        cached = _label_cache.get(key)
        if cached and now - cached[0] < _LABEL_CACHE_TTL_SECONDS:
            return cached[1]

    scope_sql, scope_params = honeypot_scope_sql(scope)
    own_sql, own_params = _own_traffic_exclusion()
    since = datetime.now(UTC) - timedelta(days=_DEFAULT_WINDOW_DAYS)
    with db_cursor() as cur:
        cur.execute(f"SET LOCAL statement_timeout = '{_STATEMENT_TIMEOUT_MS}ms'")
        # `column` is one of _LABEL_COLUMNS or the ValueError above has already fired, so
        # the only thing interpolated here is a literal from this module; the scope and the
        # exclusion travel as %s parameters.
        cur.execute(
            f"""
            SELECT DISTINCT ap.{column}
            FROM attack_patterns ap
            JOIN sensor_events se ON se.event_id = ap.event_id
            WHERE {own_sql} AND {scope_sql} AND se.timestamp >= %s
              AND ap.{column} IS NOT NULL
            """,  # noqa: S608 # nosec B608
            (*own_params, *scope_params, since),
        )
        values = tuple(sorted(r[0] for r in cur.fetchall() if r[0]))
    with _label_cache_lock:
        _label_cache[key] = (now, values)
    return values


def reset_label_cache() -> None:
    """Drop the cached label vocabulary (tests, and after a rule import)."""
    with _label_cache_lock:
        _label_cache.clear()


def resolve_labels(term: str, scope: str) -> tuple[list[str], list[str]]:
    """Resolve a search term to the exact `(attack_types, rule_names)` it names.

    The caller's term is matched against the labels this sensor actually carries, and the
    query then asks for those labels by equality. The previous version built an
    `ILIKE '%term%'` pattern instead, which had three problems at once: it could not use the
    index on either column, it let the caller's `%` and `_` act as wildcards (`attack=%`
    matched every event), and it never told the caller what it had matched.
    """
    needle = _normalise_label(term)
    if not needle:
        return [], []
    attack_types = [
        v for v in _label_vocabulary("attack_type", scope) if needle in _normalise_label(v)
    ]
    rule_names = [v for v in _label_vocabulary("rule_name", scope) if needle in _normalise_label(v)]
    return attack_types, rule_names


def _extract_basic_credentials(request: Request) -> tuple[str | None, str | None]:
    """Decode HTTP Basic Auth `username:password` from `Authorization: Basic ...`."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return None, None
    try:
        decoded = base64.b64decode(auth_header[6:].strip()).decode("utf-8")
        if ":" not in decoded:
            return None, None
        username, password = decoded.split(":", 1)
        return username, password
    except Exception:
        return None, None


def _extract_raw_api_key(request: Request) -> str | None:
    """Extract the API key from the `X-API-Key` header.

    Deliberately header-only. The key used to be accepted as an `api_key` query parameter
    as well, and this service logs the full request line: the journal on a live sensor
    carries entries like `"GET /ai/analyzed_ips HTTP/1.1" 200 OK`, so a key in the query
    string would have been written to the journal in cleartext on every call, and again to
    the access log of the proxy every request arrives through. Query strings also end up in
    browser history and `Referer` headers.
    """
    header_key = (
        request.headers.get("X-API-Key")
        or request.headers.get("X-Api-Key")
        or request.headers.get("x-api-key")
    )
    if header_key:
        return header_key.strip()
    return None


def resolve_honeypot_api_access(request: Request) -> HoneypotApiKey | None:
    """Ensure the request is authorized via Honeypot API Key + Basic Auth (or operator session).

    Returns:
        `HoneypotApiKey` when authenticated via API key + Basic Auth, or `None` when
        authenticated via an interactive operator session.
    Raises:
        `HTTPException(401)` or `HTTPException(403)` on invalid/expired/revoked credentials.
    """
    # Check if already validated by AuthMiddleware
    api_key_obj: HoneypotApiKey | None = getattr(request.state, "honeypot_api_key", None)
    if api_key_obj is not None:
        return api_key_obj

    # Check if request carries an API key or apiaccessN Basic Auth
    raw_key = _extract_raw_api_key(request)
    basic_user, basic_pass = _extract_basic_credentials(request)

    if raw_key or (basic_user and basic_user.startswith("apiaccess")):
        if not raw_key or not basic_user or not basic_pass:
            raise HTTPException(
                status_code=401,
                detail="Both HTTP Basic Auth (Authorization: Basic base64(apiaccessN:password)) and X-API-Key header are required.",
                headers={"WWW-Authenticate": 'Basic realm="HoneyLens Honeypot API"'},
            )
        client_ip = request.client.host if request.client else None
        key_obj, err = authenticate_api_key(
            basic_username=basic_user,
            basic_password=basic_pass,
            raw_api_key=raw_key,
            client_ip=client_ip,
        )
        if not key_obj:
            raise HTTPException(
                status_code=401,
                detail=err or "Invalid API key or Basic Auth credentials",
                headers={"WWW-Authenticate": 'Basic realm="HoneyLens Honeypot API"'},
            )
        request.state.honeypot_api_key = key_obj
        return key_obj

    # Otherwise allow if authenticated via interactive user session
    if getattr(request.state, "user", None) is not None or getattr(
        request.state, "is_admin", False
    ):
        return None

    raise HTTPException(
        status_code=401,
        detail="Authentication required: provide Authorization: Basic <base64(apiaccessN:pass)> and X-API-Key header.",
        headers={"WWW-Authenticate": 'Basic realm="HoneyLens Honeypot API"'},
    )


def _resolve_effective_honeypot(
    api_key: HoneypotApiKey | None,
    requested_honeypot: str | None,
) -> str:
    """Validate requested honeypot against the API key's scope and return canonical honeypot filter."""
    req_norm = "*"
    if requested_honeypot and requested_honeypot.strip():
        try:
            req_norm = normalize_honeypot_name(requested_honeypot)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    if api_key is not None and api_key.honeypot != "*":
        key_scope = api_key.honeypot
        if req_norm != "*" and req_norm != key_scope:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"API key '{api_key.basic_username}' is scoped exclusively to honeypot "
                    f"'{key_scope}' and cannot read events for '{req_norm}'."
                ),
            )
        return key_scope

    return req_norm


def _parse_timestamp_param(val: str | None, param_name: str) -> datetime | None:
    """Parse ISO-8601 timestamp or relative shorthand (`24h`, `7d`, `30m`)."""
    if not val or not val.strip():
        return None
    raw = val.strip()
    m = _REL_TIME_RE.match(raw)
    if m:
        amount = int(m.group(1))
        unit = m.group(2).lower()
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
        return datetime.now(UTC) - timedelta(seconds=amount * mult)
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {param_name} timestamp '{val}'. Use ISO-8601 or relative format (e.g. '24h', '7d').",
        ) from exc


def _normalize_cve(cve_raw: str) -> tuple[str, str]:
    """Validate and normalize a CVE identifier into `('CVE-YYYY-NNNN', 'CVE_YYYY_NNNN')`."""
    cleaned = (cve_raw or "").strip()
    m = _CVE_RE.match(cleaned)
    if not m:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid CVE identifier '{cve_raw}'. Expected format: CVE-YYYY-NNNNN.",
        )
    year, num = m.group(1), m.group(2)
    return f"CVE-{year}-{num}", f"CVE_{year}_{num}"


def _validate_ip_or_cidr(ip_raw: str) -> tuple[str, bool]:
    """Validate IP address or CIDR network. Returns `(normalized_str, is_cidr)`."""
    cleaned = (ip_raw or "").strip()
    if "/" in cleaned:
        try:
            net = ipaddress.ip_network(cleaned, strict=False)
            return str(net), True
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid IP or CIDR network: '{ip_raw}'",
            ) from exc
    try:
        addr = ipaddress.ip_address(cleaned)
        return str(addr), False
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid IP address: '{ip_raw}'",
        ) from exc


def _label_filter(
    term: str, param_name: str, scope: str
) -> tuple[str, list[Any], list[str], str | None]:
    """Build the `attack_patterns` clause for `term`.

    Returns `(clause, params, matched_labels, warning)`.

    A term that matches no label on this sensor is not an error and is not ignored either.
    It is answered with a clause that matches nothing, an empty `matched_labels`, and a
    warning that says so -- a SIEM polling for a CVE this sensor has not seen yet must get
    an empty page rather than a 400 it can never clear, and a typo must not quietly widen
    the query to everything.
    """
    if len(term) > 128:
        raise HTTPException(
            status_code=400, detail=f"{param_name} filter is too long (max 128 chars)"
        )
    if not _normalise_label(term):
        raise HTTPException(
            status_code=400, detail=f"{param_name} filter contains no searchable characters"
        )

    attack_types, rule_names = resolve_labels(term, scope)
    warning = None
    if not attack_types and not rule_names:
        warning = (
            f"{param_name} '{term}' matches no verdict label on this sensor, so no event can "
            "match it. GET /api/v1/honeypot/labels lists the labels that exist here."
        )
    clause = """EXISTS (
                SELECT 1 FROM attack_patterns ap
                WHERE ap.event_id = se.event_id
                  AND (ap.attack_type = ANY(%s) OR ap.rule_name = ANY(%s))
            )"""
    matched = sorted(set(attack_types) | set(rule_names))
    return clause, [attack_types, rule_names], matched, warning


def _query_honeypot_events(
    *,
    effective_honeypot: str,
    attack: str | None = None,
    ip: str | None = None,
    cve: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 100,
    page: int = 1,
    api_key: HoneypotApiKey | None = None,
) -> dict[str, Any]:
    """Execute the read-only query on `sensor_events` (+ `attack_patterns`)."""
    limit = min(max(int(limit), 1), 1000)
    page = max(int(page), 1)
    offset = (page - 1) * limit
    if offset > _MAX_OFFSET:
        raise HTTPException(
            status_code=400,
            detail=f"page is too deep (offset {offset} > {_MAX_OFFSET}); narrow the time window instead",
        )

    conditions: list[str] = []
    params: list[Any] = []

    # 1. Only a real actor's traffic leaves this API. 1,663,283 of one sensor's 13.3M rows
    #    were our own when this was measured, and the standing rule for anything that leaves
    #    this project is that our infrastructure is not in it -- a read key handed to a SIEM
    #    or a partner must not return our jump hosts or the operator's own address.
    own_sql, own_params = _own_traffic_exclusion()
    conditions.append(own_sql)
    params.extend(own_params)

    # 2. Honeypot scope.
    scope_sql, scope_params = honeypot_scope_sql(effective_honeypot)
    conditions.append(scope_sql)
    params.extend(scope_params)

    # 3. Attack filter (`per attack`).
    matched_attack_labels: list[str] = []
    warnings: list[str] = []
    if attack and attack.strip():
        clause, clause_params, matched_attack_labels, warning = _label_filter(
            attack.strip(), "attack", effective_honeypot
        )
        conditions.append(clause)
        params.extend(clause_params)
        if warning:
            warnings.append(warning)

    # 4. IP filter (`per IP`).
    if ip and ip.strip():
        norm_ip, is_cidr = _validate_ip_or_cidr(ip)
        conditions.append("se.src_ip <<= %s::inet" if is_cidr else "se.src_ip = %s::inet")
        params.append(norm_ip)

    # 5. CVE filter (`per CVE`).
    normalized_cve: str | None = None
    matched_cve_labels: list[str] = []
    if cve and cve.strip():
        cve_dash, _cve_under = _normalize_cve(cve)
        normalized_cve = cve_dash
        clause, clause_params, matched_cve_labels, warning = _label_filter(
            cve_dash, "cve", effective_honeypot
        )
        conditions.append(clause)
        params.extend(clause_params)
        if warning:
            warnings.append(warning)

    # 6. Time window. A lower bound is always present: without one the scan is the whole
    #    table, and `ORDER BY timestamp DESC` on an unbounded set is what made the old
    #    per-CVE query time out.
    since_dt = _parse_timestamp_param(since, "since")
    until_dt = _parse_timestamp_param(until, "until")
    if since_dt is None:
        since_dt = datetime.now(UTC) - timedelta(days=_DEFAULT_WINDOW_DAYS)
    conditions.append("se.timestamp >= %s")
    params.append(since_dt)
    if until_dt is not None:
        conditions.append("se.timestamp <= %s")
        params.append(until_dt)

    where_sql = " AND ".join(conditions)

    with db_cursor() as cur:
        cur.execute(f"SET LOCAL statement_timeout = '{_STATEMENT_TIMEOUT_MS}ms'")

        data_sql = f"""
            SELECT se.event_id,
                   se.timestamp,
                   se.src_ip::text,
                   se.src_port,
                   se.dst_ip::text,
                   se.dst_port,
                   se.protocol,
                   se.source,
                   se.attack_types,
                   se.payload,
                   se.metadata
            FROM sensor_events se
            WHERE {where_sql}
            ORDER BY se.timestamp DESC
            LIMIT %s OFFSET %s
        """  # noqa: S608 # nosec B608 -- where_sql is assembled from the literal clauses
        # above; every caller-supplied value travels as a %s parameter.
        try:
            cur.execute(data_sql, (*params, limit, offset))
            rows = cur.fetchall()
        except QueryCanceled as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    f"Query exceeded the {_STATEMENT_TIMEOUT_MS // 1000}s budget on this sensor. "
                    "Narrow it with `since`, a honeypot scope, or a more specific filter."
                ),
            ) from exc

        # The page comes first and the count second, so a count too expensive to finish
        # costs the caller the total, not the events.
        total: int | None
        try:
            count_sql = f"""
                SELECT COUNT(*) FROM (
                    SELECT 1 FROM sensor_events se WHERE {where_sql} LIMIT {_COUNT_CAP}
                ) capped
            """  # noqa: S608 # nosec B608
            cur.execute(count_sql, tuple(params))
            total_row = cur.fetchone()
            total = int(total_row[0]) if total_row else 0
        except QueryCanceled:
            total = None

    events: list[dict[str, Any]] = [
        {
            "event_id": r[0],
            "timestamp": r[1].isoformat() if r[1] else None,
            "src_ip": strip_cidr(r[2]),
            "src_port": r[3],
            "dst_ip": strip_cidr(r[4]) if r[4] else None,
            "dst_port": r[5],
            "protocol": r[6],
            "source": r[7],
            "attack_types": r[8],
            "payload": r[9],
            "metadata": r[10] if isinstance(r[10], dict) else {},
        }
        for r in rows
    ]

    response: dict[str, Any] = {
        "honeypot_scope": effective_honeypot,
        "filters": {
            "honeypot": effective_honeypot,
            "attack": attack,
            "ip": ip,
            "cve": normalized_cve or cve,
            "since": since_dt.isoformat(),
            "until": until_dt.isoformat() if until_dt else None,
        },
        # What the terms above actually resolved to, so the caller can see whether their
        # filter meant what they thought it meant.
        "matched_labels": {
            "attack": matched_attack_labels,
            "cve": matched_cve_labels,
        },
        "warnings": warnings,
        # `total_exact` is false when the count hit the cap (there are at least `total`) or
        # when the count itself timed out (`total` is null).
        "total": total,
        "total_exact": total is not None and total < _COUNT_CAP,
        "page": page,
        "limit": limit,
        "count": len(events),
        "events": events,
    }

    if api_key is not None:
        response["api_key_meta"] = {
            "basic_username": api_key.basic_username,
            "honeypot": api_key.honeypot,
            "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
            "days_remaining": api_key.days_remaining,
            "status": api_key.status,
            "needs_rotation": api_key.needs_rotation,
        }

    return response


@router.get("/key-info")
def get_honeypot_api_key_info(request: Request) -> dict[str, Any]:
    """Return status and expiration details for the authenticated Honeypot API key."""
    api_key = resolve_honeypot_api_access(request)
    if api_key is None:
        return {
            "auth_mode": "session",
            "honeypot_scope": "*",
            "status": "active",
        }
    return {
        "auth_mode": "api_key",
        "key": api_key.to_dict(),
    }


@router.get("/labels")
def list_honeypot_labels(request: Request) -> dict[str, Any]:
    """List the verdict labels this sensor carries, for building `attack` and `cve` filters.

    The list is the labels **this key's decoy** has produced, in the same time window the
    event endpoints default to, and with our own traffic excluded. `attack` and `cve` are
    resolved against exactly this list, so a term that appears nowhere here can match no
    event and says so in `warnings`.
    """
    api_key = resolve_honeypot_api_access(request)
    scope = _resolve_effective_honeypot(api_key, None)
    return {
        "honeypot_scope": scope,
        "attack_types": list(_label_vocabulary("attack_type", scope)),
        "rule_names": list(_label_vocabulary("rule_name", scope)),
    }


@router.get("/events")
def read_honeypot_events(
    request: Request,
    honeypot: str | None = None,
    attack: str | None = None,
    ip: str | None = None,
    cve: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 100,
    page: int = 1,
) -> dict[str, Any]:
    """Read honeypot events with optional filters (`honeypot`, `attack`, `ip`, `cve`)."""
    api_key = resolve_honeypot_api_access(request)
    effective_hp = _resolve_effective_honeypot(api_key, honeypot)
    return _query_honeypot_events(
        effective_honeypot=effective_hp,
        attack=attack,
        ip=ip,
        cve=cve,
        since=since,
        until=until,
        limit=limit,
        page=page,
        api_key=api_key,
    )


@router.get("/events/by-attack/{attack}")
def read_honeypot_events_by_attack(
    attack: str,
    request: Request,
    honeypot: str | None = None,
    ip: str | None = None,
    cve: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 100,
    page: int = 1,
) -> dict[str, Any]:
    """Read honeypot events filtered by attack type or rule name (`per attack`)."""
    api_key = resolve_honeypot_api_access(request)
    effective_hp = _resolve_effective_honeypot(api_key, honeypot)
    return _query_honeypot_events(
        effective_honeypot=effective_hp,
        attack=attack,
        ip=ip,
        cve=cve,
        since=since,
        until=until,
        limit=limit,
        page=page,
        api_key=api_key,
    )


@router.get("/events/by-ip/{ip:path}")
def read_honeypot_events_by_ip(
    ip: str,
    request: Request,
    honeypot: str | None = None,
    attack: str | None = None,
    cve: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 100,
    page: int = 1,
) -> dict[str, Any]:
    """Read honeypot events filtered by source IP or CIDR (`per IP`)."""
    api_key = resolve_honeypot_api_access(request)
    effective_hp = _resolve_effective_honeypot(api_key, honeypot)
    return _query_honeypot_events(
        effective_honeypot=effective_hp,
        attack=attack,
        ip=ip,
        cve=cve,
        since=since,
        until=until,
        limit=limit,
        page=page,
        api_key=api_key,
    )


@router.get("/events/by-cve/{cve}")
def read_honeypot_events_by_cve(
    cve: str,
    request: Request,
    honeypot: str | None = None,
    attack: str | None = None,
    ip: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 100,
    page: int = 1,
) -> dict[str, Any]:
    """Read honeypot events filtered by CVE ID (`per CVE`, e.g. CVE-2024-3400)."""
    api_key = resolve_honeypot_api_access(request)
    effective_hp = _resolve_effective_honeypot(api_key, honeypot)
    return _query_honeypot_events(
        effective_honeypot=effective_hp,
        attack=attack,
        ip=ip,
        cve=cve,
        since=since,
        until=until,
        limit=limit,
        page=page,
        api_key=api_key,
    )


@router.get("/events/by-honeypot/{honeypot}")
def read_honeypot_events_by_honeypot(
    honeypot: str,
    request: Request,
    attack: str | None = None,
    ip: str | None = None,
    cve: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 100,
    page: int = 1,
) -> dict[str, Any]:
    """Read honeypot events filtered by honeypot name (`per honeypot`)."""
    api_key = resolve_honeypot_api_access(request)
    effective_hp = _resolve_effective_honeypot(api_key, honeypot)
    return _query_honeypot_events(
        effective_honeypot=effective_hp,
        attack=attack,
        ip=ip,
        cve=cve,
        since=since,
        until=until,
        limit=limit,
        page=page,
        api_key=api_key,
    )
