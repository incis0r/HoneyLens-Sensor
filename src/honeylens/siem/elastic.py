"""Elasticsearch / OpenSearch — API ``_bulk``.

Endpoint: ``POST <base_url>/_bulk`` (NDJSON). Elastic 7+ and OpenSearch 1+/2+ accept
the same format.

Configuration::

    {"type": "elastic", "name": "elastic-prod", "base_url": "https://es.internal:9200",
     "index": "honeylens-events-{yyyy.mm.dd}",   # supports a date placeholder
     "username": "honeylens", "password_env": "ELASTIC_PASSWORD",
     "api_key_env": "ELASTIC_API_KEY",           # alternative to user/pass
     "tls_verify": true, "enabled": true}

Either basic auth (username + password_env), or an API key (api_key_env) — not both.
"""

import json
import os
import time
from typing import Any

from honeylens.siem.base import HttpForwarder, SiemError, SiemEvent


class ElasticForwarder(HttpForwarder):
    TYPE = "elastic"

    def __init__(self, name: str, config: dict[str, Any]):
        super().__init__(name, config)
        self.index_template = str(config.get("index") or "honeylens-events-{yyyy.mm.dd}")
        self.username = config.get("username") or None
        self.password = os.environ.get(str(config.get("password_env") or "")) or None
        self.api_key = os.environ.get(str(config.get("api_key_env") or "")) or None
        if self.api_key and (self.username or self.password):
            raise ValueError("elastic: use api_key_env OR username+password_env, not both")
        if self.username and not self.password:
            raise ValueError("elastic: username set but password_env unset/missing")

    def _resolve_index(self) -> str:
        if "{yyyy.mm.dd}" in self.index_template:
            return self.index_template.replace(
                "{yyyy.mm.dd}", time.strftime("%Y.%m.%d", time.gmtime())
            )
        return self.index_template

    def _send_one(self, event: SiemEvent) -> None:
        action = json.dumps({"index": {"_index": self._resolve_index(), "_id": event.event_id}})
        body = (action + "\n" + event.to_json() + "\n").encode("utf-8", "replace")
        headers = {"Content-Type": "application/x-ndjson"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        auth = (self.username, self.password) if self.username and self.password else None
        resp = self._request(
            "POST", f"{self.base_url}/_bulk", data=body, headers=headers, auth=auth
        )
        # _bulk returns 200 even when individual items failed — you must look at 'errors'.
        try:
            data = resp.json()
        except ValueError:
            return
        if data.get("errors"):
            first_err = next(
                (
                    item.get("index", {}).get("error")
                    for item in data.get("items", [])
                    if "error" in item.get("index", {})
                ),
                None,
            )
            raise SiemError(f"elastic _bulk indexing error: {first_err}")

    def status(self) -> dict[str, Any]:
        s = super().status()
        auth = "api_key" if self.api_key else ("basic" if self.username else "none")
        s.update(
            {
                "base_url": self.base_url,
                "index_pattern": self.index_template,
                "auth": auth,
                "tls_verify": self.tls_verify,
            }
        )
        return s
