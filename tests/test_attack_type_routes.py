"""WebUI drill-downs must find an attack type whatever case it is stored in.

The drill-down no longer guesses the case. It used to upper-case anything without a
hyphen, which made every lowercase underscore tag unreachable: /attack/types lists the
stored spelling verbatim, so the dropdown offered `ics_recon_function_code`, the
drill-down asked for `ICS_RECON_FUNCTION_CODE`, and the exact match found nothing. The
query now matches a candidate set (as-typed, upper, lower), which keeps the comparison an
equality so the (attack_type, created_at) index is still usable.
"""

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from honeylens.routes import classifier


@pytest.fixture
def client(monkeypatch):
    conn = MagicMock()
    conn.cursor.return_value.fetchall.return_value = [
        (
            "a" * 64,
            "netscaler",
            "8.8.8.8",
            12345,
            "https",
            443,
            123.0,
            0,
            0,
            "request",
            "ns-citrixbleed2-login-shape",
        )
    ]
    monkeypatch.setattr(classifier, "db", lambda: conn)
    monkeypatch.setattr(classifier, "_get_country", lambda ip: "US")
    monkeypatch.setattr(classifier, "html_response", lambda title, rows, request, kind: rows)
    app = FastAPI()
    app.include_router(classifier.router)
    return TestClient(app), conn


@pytest.mark.parametrize("suffix", ["", "/http"])
@pytest.mark.parametrize("uppercase", [False, True])
def test_netscaler_drilldown_preserves_stored_slug(client, suffix, uppercase):
    http, conn = client
    slug = "ns-citrixbleed2-login-shape"
    label = slug.upper() if uppercase else slug
    response = http.get("/attack/type/" + label + suffix + "?limit=50")
    assert response.status_code == 200
    assert response.json()[0]["source"] == "netscaler"
    # The stored lowercase slug must be among the candidates whichever case was clicked.
    assert slug in conn.cursor.return_value.execute.call_args.args[1][0]
    conn.close.assert_called_once()


@pytest.mark.parametrize("suffix", ["", "/http"])
def test_uppercase_category_is_still_reachable_from_a_lowercase_label(client, suffix):
    # The old behaviour - upper-casing an underscore label - stays covered, because the
    # upper-case spelling is one of the candidates.
    http, conn = client
    assert http.get("/attack/type/sql_injection" + suffix).status_code == 200
    assert "SQL_INJECTION" in conn.cursor.return_value.execute.call_args.args[1][0]


@pytest.mark.parametrize("suffix", ["", "/http"])
def test_lowercase_underscore_tag_is_queried_verbatim(client, suffix):
    """The regression itself: these were unreachable, e.g. info_disclosure (2,284 events on
    one sensor), wordpress_scan, ics_enumeration, ics_recon_function_code,
    path_traversal, xss."""
    http, conn = client
    assert http.get("/attack/type/ics_recon_function_code" + suffix).status_code == 200
    sent = conn.cursor.return_value.execute.call_args.args[1][0]
    assert "ics_recon_function_code" in sent, "the stored lowercase spelling must be asked for"


def test_candidates_cover_the_three_stored_conventions():
    assert classifier._attack_type_candidates("ics_recon") == ["ics_recon", "ICS_RECON"]
    assert classifier._attack_type_candidates("CREDENTIAL") == ["CREDENTIAL", "credential"]
    assert classifier._attack_type_candidates("ns-path-traversal") == [
        "ns-path-traversal",
        "NS-PATH-TRAVERSAL",
    ]


def test_candidates_are_deduplicated_and_trimmed():
    # A single-case name must not be sent three times, and whitespace must not leak into SQL.
    assert classifier._attack_type_candidates("  RCE  ") == ["RCE", "rce"]
    assert classifier._attack_type_candidates("123_456") == ["123_456"]
    assert classifier._attack_type_candidates("") == []


@pytest.mark.parametrize("name", ["ab\n", "../etc", "x' OR 1=1", "<script>", "x" * 65, "a"])
def test_invalid_attack_type_is_rejected(name):
    assert not classifier._valid_attack_type(name)


@pytest.mark.parametrize("name", ["ns-citrixbleed2-login-shape", "SQL_INJECTION", "a" * 64])
def test_stored_identifier_formats_are_valid(name):
    assert classifier._valid_attack_type(name)
