"""
honeypots/hp_elasticsearch.py — Modular Elasticsearch honeypot service
=======================================================================
Emulates an exposed Elasticsearch node. Returns realistic JSON for
common discovery endpoints that attackers and bots probe.

Run standalone:
    python -m honeypots.hp_elasticsearch
    HP_ELASTICSEARCH_PORT=9200 python -m honeypots.hp_elasticsearch
"""

from __future__ import annotations

import asyncio
import json
import uuid

from honeylens.honeypots._base import BaseHoneypot, log_event
from honeylens.honeypots.body_capture import (
    MAX_RAW_EVENT_BYTES,
    read_http_request,
)
from honeylens.honeypots.body_capture import (
    capture as _capture_body,
)


class ElasticsearchHoneypot(BaseHoneypot):
    """Low-interaction Elasticsearch honeypot.

    Handles HTTP requests on the ES port and returns convincing JSON
    responses for /, /_cluster/health, and /_cat/indices.
    """

    PROTOCOL = "elasticsearch"
    DEFAULT_PORT = 9200
    TTL_PROFILE = "linux"
    CONNECTION_TIMEOUT = 60

    def __init__(self):
        super().__init__()
        self._cluster_name = self.profile.get("cluster_name", "production-cluster")
        self._node_name = self.profile.get("node_name", "es-node-01")
        self._version = self.profile.get("version", "7.17.9")
        self._node_id = uuid.uuid4().hex[:20]

    # ---- response builders --------------------------------------------------

    def _root_response(self) -> dict:
        return {
            "name": self._node_name,
            "cluster_name": self._cluster_name,
            "cluster_uuid": uuid.uuid4().hex[:22],
            "version": {
                "number": self._version,
                "build_flavor": "default",
                "build_type": "deb",
                "build_hash": "ef48eb35cf30adf4db14086e8aabd07ef6fb113f",
                "build_date": "2023-01-23T09:04:44.452191Z",
                "build_snapshot": False,
                "lucene_version": "8.11.1",
                "minimum_wire_compatibility_version": "6.8.0",
                "minimum_index_compatibility_version": "6.0.0-beta1",
            },
            "tagline": "You Know, for Search",
        }

    def _cluster_health(self) -> dict:
        return {
            "cluster_name": self._cluster_name,
            "status": "green",
            "timed_out": False,
            "number_of_nodes": 3,
            "number_of_data_nodes": 3,
            "active_primary_shards": 42,
            "active_shards": 84,
            "relocating_shards": 0,
            "initializing_shards": 0,
            "unassigned_shards": 0,
            "delayed_unassigned_shards": 0,
            "number_of_pending_tasks": 0,
            "number_of_in_flight_fetch": 0,
            "task_max_waiting_in_queue_millis": 0,
            "active_shards_percent_as_number": 100.0,
        }

    def _cat_indices(self) -> str:
        lines = [
            "health status index            uuid                   pri rep docs.count docs.deleted store.size pri.store.size",
            "green  open   customers        dGhpcyBpcyBhIH         5   1     125000            0     85.2mb         42.6mb",
            "green  open   orders           ZmFrZSB1dWlkIH         5   1      98200            0     62.1mb         31.0mb",
            "green  open   products         aG9uZXlwb3QgZG         3   1      45000            0     28.4mb         14.2mb",
            "green  open   logs-2024.01     bG9ncyBmYWtlIH         1   1    1250000            0    512.8mb        256.4mb",
            "green  open   .kibana_1        a2liYW5hIGZha2         1   1          8            0     48.5kb         24.2kb",
        ]
        return "\n".join(lines) + "\n"

    # ---- HTTP helpers -------------------------------------------------------

    @staticmethod
    def _http_response(status: int, body: str, content_type: str = "application/json") -> bytes:
        phrases = {200: "OK", 400: "Bad Request", 404: "Not Found"}
        resp = f"HTTP/1.1 {status} {phrases.get(status, 'OK')}\r\n"
        resp += f"Content-Type: {content_type}; charset=UTF-8\r\n"
        resp += f"Content-Length: {len(body.encode())}\r\n"
        resp += "X-elastic-product: Elasticsearch\r\n"
        resp += "\r\n"
        resp += body
        return resp.encode()

    @staticmethod
    def _parse_request(raw: str) -> tuple[str, str]:
        """Return (method, path) from the first line of an HTTP request."""
        lines = raw.split("\r\n")
        if not lines:
            return "", ""
        parts = lines[0].split(" ")
        if len(parts) >= 2:
            return parts[0].upper(), parts[1]
        return "", ""

    # ---- connection handler -------------------------------------------------

    async def handle_connection(self, reader, writer, peer):
        try:
            # Read the body too, not just whatever shared the first segment with the
            # headers: a _search POST *is* the request, and the 5 POSTs this decoy took
            # in the week to 2026-10-25 were stored with no body and no body length.
            raw = await asyncio.wait_for(read_http_request(reader), timeout=30)
        except (TimeoutError, ConnectionError):
            return
        if not raw:
            return

        request_text = raw.decode(errors="replace")
        method, path = self._parse_request(request_text)

        # A _search POST *is* the request — an injected script or a stored-field probe
        # lives in the body and nowhere else, so it is captured rather than summarised.
        _head, _, body_bytes = raw.partition(b"\r\n\r\n")
        content_type = ""
        for line in _head.split(b"\r\n")[1:]:
            name, _sep, value = line.partition(b":")
            if name.strip().lower() == b"content-type":
                content_type = value.strip().decode(errors="replace")
        fields = _capture_body(body_bytes, path, content_type)

        # `payload` stays a bare summary and `raw` carries the whole request: `log_event`
        # appends the body to the payload itself once capture fields are present, and an
        # explicit `raw=` wins over the body-only bytes it would otherwise derive. Doing
        # either by hand here put the body in `payload` twice.
        log_event(
            self.PROTOCOL,
            peer,
            {
                "phase": "request",
                "method": method,
                "path": path,
                "payload": f"{method} {path}",
                "dst_port": self.port,
                **fields,
            },
            attack_type="ES_SCAN",
            severity="LOW",
            raw=raw[:MAX_RAW_EVENT_BYTES] or None,
        )

        self.logger.info("[ES] %s %s %s", peer[0], method, path)

        # Route to appropriate response
        if path == "/" or path == "":
            body = json.dumps(self._root_response(), indent=2)
            writer.write(self._http_response(200, body))

        elif path.startswith("/_cluster/health"):
            body = json.dumps(self._cluster_health(), indent=2)
            writer.write(self._http_response(200, body))

        elif path.startswith("/_cat/indices"):
            writer.write(self._http_response(200, self._cat_indices(), content_type="text/plain"))

        elif path.startswith("/_search") or path.endswith("/_search"):
            # Common attack vector: data exfiltration queries
            # This is the higher-severity verdict of the two, so it carries the evidence
            # too. It used to log `request_text[:2000]` with no capture fields at all,
            # which meant the MEDIUM event a hunt actually looks at had no `full_payload`.
            log_event(
                self.PROTOCOL,
                peer,
                {
                    "phase": "search_query",
                    "method": method,
                    "path": path,
                    "payload": f"{method} {path}",
                    "dst_port": self.port,
                    **fields,
                },
                attack_type="ES_DATA_ACCESS",
                severity="MEDIUM",
                raw=raw[:MAX_RAW_EVENT_BYTES] or None,
            )
            body = json.dumps({"hits": {"total": {"value": 0}, "hits": []}})
            writer.write(self._http_response(200, body))

        else:
            body = json.dumps(
                {
                    "error": {
                        "root_cause": [
                            {
                                "type": "index_not_found_exception",
                                "reason": f"no such index [{path.strip('/')}]",
                            }
                        ],
                        "type": "index_not_found_exception",
                        "reason": f"no such index [{path.strip('/')}]",
                        "index": path.strip("/"),
                    },
                    "status": 404,
                },
                indent=2,
            )
            writer.write(self._http_response(404, body))

        await writer.drain()


if __name__ == "__main__":
    ElasticsearchHoneypot().run()
