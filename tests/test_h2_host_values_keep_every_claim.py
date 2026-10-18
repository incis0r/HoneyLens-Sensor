"""An HTTP/2 stream's second ``host`` header must reach the guard, not replace the first.

`host_claims` exists because the foreign-host guard was bypassed four times in four
rounds, each time by a legal spelling of the same claim, and its own docstring records
the HTTP/1.1 version of this exact defect: "Taking only the last served the full page
to a request whose FIRST Host named a stranger." That is why `_parse_request` keeps
``host_values: list[str]`` (`hp_http.py`) and hands the whole list to the union.

The HTTP/2 arm did not. ``H2Stream.headers`` is a last-duplicate-wins dict, so
``host: victim.example`` followed by ``host: decoy.invalid`` reached
`shell_bait.host_claims` as our own name alone and the stranger's never entered the
union.

**Today h2 closes this at the wire** — ``validate_inbound_headers`` defaults to True
and h2 raises ``ProtocolError`` on a duplicate ``Host`` before ``RequestReceived``
exists, which `test_the_wire_is_closed_by_h2_itself` pins. These tests therefore drive
`_record_request` and the guard directly, one layer below the wire, because the one
thing that would reopen the path is a single flag — and a decoy whose stated philosophy
is that "input a parser refuses is exactly the input worth keeping" has a standing
reason to reach for it. The symmetry costs a list; relying on another library's
validation to hold our guard closed does not.
"""

from __future__ import annotations

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import pytest

from honeylens.honeypots import h2_capture, hp_http

_DOUBLE_HOST = [
    (b":method", b"GET"),
    (b":path", b"/"),
    (b":scheme", b"http"),
    (b"host", b"victim.example"),
    (b"host", b"decoy.invalid"),
]


def _received(headers) -> h2.events.RequestReceived:
    return h2.events.RequestReceived(
        stream_id=1, headers=headers, stream_ended=h2.events.StreamEnded(stream_id=1)
    )


def _record(headers) -> h2_capture.H2Stream:
    obs = h2_capture.H2Observation(entry="preface")
    kept: dict[int, h2_capture.H2Stream] = {}
    h2_capture._record_request(
        _received(headers), obs=obs, kept=kept, budgets=h2_capture.H2Budgets()
    )
    return kept[1]


def test_the_wire_is_closed_by_h2_itself():
    """Pins WHY the tests below work one layer down: with the shipped configuration a
    duplicate Host never becomes a RequestReceived, so a wire-level test would be
    asserting h2 4.4.1's validation and would pass with the defect still in place."""
    client = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True, validate_outbound_headers=False)
    )
    client.initiate_connection()
    client.send_headers(1, _DOUBLE_HOST, end_stream=True)
    wire = client.data_to_send()

    server = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
    server.initiate_connection()
    with pytest.raises(h2.exceptions.ProtocolError):
        server.receive_data(wire)


def test_every_host_value_on_a_stream_is_kept_in_order():
    record = _record(_DOUBLE_HOST)
    assert record.host_values == ["victim.example", "decoy.invalid"]
    # The dict keeps its documented last-wins meaning; the list is what the union reads.
    assert record.headers["host"] == "decoy.invalid"


def test_a_stream_whose_first_host_names_a_stranger_is_refused(monkeypatch):
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    decoy = hp_http.HTTPHoneypot()
    obs = h2_capture.H2Observation(entry="preface")
    served: list[tuple[str, int]] = []
    headers, body = decoy._h2_response_for(_record(_DOUBLE_HOST), obs, served)

    assert (":status", "421") in headers
    assert body == b""
    assert [mode for mode, _ in served] == ["misdirected"]


def test_two_host_values_under_our_own_name_are_still_served(monkeypatch):
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    decoy = hp_http.HTTPHoneypot()
    obs = h2_capture.H2Observation(entry="preface")
    served: list[tuple[str, int]] = []
    headers, body = decoy._h2_response_for(
        _record(
            [
                (b":method", b"GET"),
                (b":path", b"/"),
                (b":scheme", b"http"),
                (b"host", b"decoy.invalid"),
                (b"host", b"decoy.invalid"),
            ]
        ),
        obs,
        served,
    )
    assert (":status", "200") in headers
    assert body  # the page itself, not the fail-closed bodyless 200
    assert [mode for mode, _ in served] == ["page"]


def test_a_stream_with_one_host_header_behaves_exactly_as_before():
    record = _record(
        [
            (b":method", b"GET"),
            (b":path", b"/"),
            (b":scheme", b"http"),
            (b"host", b"decoy.invalid"),
        ]
    )
    assert record.host_values == ["decoy.invalid"]
    assert record.headers["host"] == "decoy.invalid"
