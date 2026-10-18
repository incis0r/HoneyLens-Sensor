"""The AI candidate table renders model output, so it has to escape it.

CodeQL's `Py/Reflective-Xss` flagged seven sites; six were escaping already and this was
the one that was not. The path is worth stating because it is not the usual one: the
attacker's payload goes into the AI analyzer's prompt, the model writes
`suggested_rule_name`, `known_cve` and `triage_class`, `store_deep_result` stores
`result.get(...)` verbatim with no validation, and this table interpolated those columns
straight into the analyst's page. Attacker → model → database → analyst's browser.

The CSP does not cover this. `script-src` carries `'unsafe-inline'` for the dashboards'
inline handlers, which is exactly what an injected inline `<script>` needs.

Note on the payloads: they are strings in a dict handed to a renderer. Nothing here runs
them — a scanner matching `<script>` in this file is matching the thing being tested for.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "</td></tr><script>fetch('/sensor_admin')</script>",
    "<svg/onload=alert(1)>",
]

# The columns the AI analyzer writes from the model's parsed response.
MODEL_WRITTEN = ("suggested_rule_name", "known_cve", "triage_class")


def _render(row: dict) -> str:
    from honeylens.routes.ai._common import _render_candidate_table

    request = SimpleNamespace(url=SimpleNamespace(path="/ai/zero-days"), headers={})
    response = _render_candidate_table(
        request,
        [row],
        active="zero-days",
        subnav_key="zero-days",
        title="0-Day Candidates",
        subtitle="test",
        headline="zd",
    )
    body = getattr(response, "body", response)
    return body.decode() if isinstance(body, bytes) else str(body)


def _base_row() -> dict:
    return {
        "novelty_score": 7,
        "zero_day_score": 55,
        "timestamp": "2026-10-19T12:00:00",
        "src_ip": "203.0.113.9",
        "event_id": "evt-1",
        "triage_class": "SUSPICIOUS",
        "known_cve": "CVE-2026-0322",
        "triage_reasoning": "because",
        "suggested_rule_name": "rule_x",
        "protocol": "http",
        "dst_port": 80,
    }


@pytest.mark.parametrize("column", MODEL_WRITTEN)
@pytest.mark.parametrize("payload", PAYLOADS)
def test_model_written_columns_cannot_inject_markup(column, payload):
    row = _base_row()
    row[column] = payload
    import html as _h

    page = _render(row)
    # Two assertions, and both matter. The payload must not survive verbatim — that is
    # what "no tag was created" means. And its escaped form must be present, or a fix
    # that simply dropped the column would pass.
    #
    # Deliberately not asserting on substrings like "onerror=alert": once `<` is escaped
    # those characters are inert text, and the page carries its own legitimate `<img>`
    # and `<script>`, so scanning the whole document for tag openers fails on safe output.
    assert payload not in page, f"{column} reached the page unescaped"
    assert _h.escape(payload) in page, f"{column} was dropped instead of escaped"


@pytest.mark.parametrize("column", ["src_ip", "event_id", "protocol", "timestamp"])
def test_event_store_columns_are_escaped_too(column):
    """These come from the event store, which is filled by whoever is attacking us."""
    row = _base_row()
    row[column] = '"><script>alert(1)</script>'
    html = _render(row)
    assert "<script>alert(1)</script>" not in html


def test_the_page_still_renders_its_content():
    """Escaping must not blank the table — guards against a fix that passes by emitting nothing."""
    html = _render(_base_row())
    assert "CVE-2026-0322" in html
    assert "rule_x" in html
    assert "203.0.113.9" in html
    assert "SUSPICIOUS" in html
    assert "<table>" in html
