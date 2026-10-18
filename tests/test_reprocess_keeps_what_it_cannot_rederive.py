"""The authoritative pass must not delete a label it cannot re-derive.

Phase Z preflight, 2026-11-05. `backfill_attacks --replace-patterns` purges each batch's
registry-owned `attack_patterns` rows and re-inserts whatever the classifier finds. That is
correct only when the classifier can see what the ingest saw. Measured on four sensors before
running it:

| sensor | eligible rows | NULL metadata | registry patterns at risk |
|---|---|---|---|
| `sensor-a` | 7,731,304 | 30,693 | 25,076 |
| `sensor-f` | 29,860 | 29,843 | 23,204 |
| `prod` | 4,541,845 | 20,990 | 18,727 |
| `sensor-b` | 182,742 | 4,654 | 2,141 |

**Every row with NULL metadata is on an encrypted protocol** — the numbers are identical on all
four — and they all come from the vendor decoys: `fortigate-honeypot/https`,
`paloalto-honeypot/https`, `paloalto-captive-honeypot/https`, `paloalto-ssh-honeypot/ssh`. Those
ingests never wrote the `metadata` column.

For such a row the classifier has nothing: `protocol='https'` takes the encrypted-protocol gate,
and `_sensor_decrypted_this` needs a method plus a path or a body from the metadata to know the
sensor terminated TLS itself. Verified by value on sensor-f with the deployed code: 200 rows
fetched, **0 updates and 0 patterns**. The pass would have deleted roughly 69,000 correct
registry rows fleet-wide and re-inserted none of them.

So the fetch skips them. Not re-derivable means not touched: their labels stand, and because the
pass never fetches the row it never deletes the row's patterns either. This is the same rule as
B1 — *a writer that re-derives a verdict must pass the ingest's context* — carried to its
conclusion: **when the context is gone, do not pretend to re-derive it.**

The other half is that the hole stops growing: `ingest/fortigate.py` and `ingest/paloalto.py`
now store the decoy's event as `metadata`, so rows written from here on ARE re-derivable and the
exclusion applies only to the backlog.
"""

from __future__ import annotations

import inspect

import pytest

from honeylens.classification.text_rules import _ENCRYPTED_PROTOCOLS
from honeylens.tools import backfill_attacks as bf


def test_the_encrypted_protocol_list_is_bound_as_a_parameter():
    """Not interpolated: these reach Postgres as a text[] and a templated WHERE clause reads
    the same as an injected one."""
    assert "encrypted_protocols" in bf._SOURCE_PARAMS
    assert isinstance(bf._SOURCE_PARAMS["encrypted_protocols"], list)


def test_the_list_carries_every_case_the_column_may_hold():
    """`protocol` is free text written by whichever decoy or ingest filled it — `https`, `HTTPS`
    and `TLS` all occur — so the comparison cannot rely on one spelling."""
    bound = set(bf._SOURCE_PARAMS["encrypted_protocols"])

    for proto in _ENCRYPTED_PROTOCOLS:
        assert proto in bound or proto.lower() in bound or proto.upper() in bound
    assert "https" in bound and "HTTPS" in bound


@pytest.mark.parametrize(
    "fn", [bf.fetch_event_batch_cursor, bf.get_total_count], ids=["fetch", "count"]
)
def test_both_the_fetch_and_the_count_skip_what_cannot_be_rederived(fn):
    """They must agree, or the progress total and the work diverge — which is how a run that
    did nothing reported `Events: 29858`."""
    src = inspect.getsource(fn)
    guards = src.count("metadata IS NULL")

    assert guards, f"{fn.__name__} has no guard for an unrecoverable context"
    assert src.count("encrypted_protocols") == guards


def test_every_select_in_the_fetch_carries_the_guard():
    """Four branches — reprocess or not, first page or later — and a guard missing from one of
    them is a guard missing from a quarter of the store."""
    src = inspect.getsource(bf.fetch_event_batch_cursor)

    assert src.count("FROM sensor_events") == src.count("metadata IS NULL") == 4


def test_the_guard_only_excludes_rows_that_are_both_blind_and_encrypted():
    """A NULL metadata on a PLAINTEXT protocol is still re-derivable — the text rules read the
    payload — so excluding on metadata alone would skip work the pass should do."""
    src = inspect.getsource(bf.fetch_event_batch_cursor)

    assert "metadata IS NULL AND protocol = ANY(%(encrypted_protocols)s)" in src
    assert "NOT (metadata IS NULL" in src


def test_the_pass_deletes_only_within_the_batch_it_fetched():
    """The structural reason the exclusion is sufficient: patterns are purged per batch, by the
    ids the fetch returned. A row that is never fetched is never purged."""
    src = inspect.getsource(bf.backfill_sequential)

    assert "batch_ids = [e[0] for e in events]" in src
    assert "delete_patterns_for_events(batch_ids)" in src


# ---------------------------------------------------------------------------
# The other half: the vendor ingests stop writing blind rows
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", ["fortigate", "paloalto"])
def test_the_vendor_ingests_store_the_decoy_event_as_metadata(module):
    """Without this, every row they write is one the pass can never re-derive — 23,200 of
    sensor-f's 23,204 at-risk patterns are fortigate's, and 16,922 of prod's are the PAN-OS ssh
    decoy's."""
    import importlib
    import re

    src = inspect.getsource(importlib.import_module(f"honeylens.ingest.{module}"))
    column_lists = re.findall(r"INSERT INTO sensor_events\s*\(([^)]*)\)", src)

    assert column_lists, f"no event insert found in {module}"
    for columns in column_lists:
        assert "metadata" in columns, f"{module}: {columns}"


@pytest.mark.parametrize("module", ["fortigate", "paloalto"])
def test_the_metadata_is_the_decoy_event_serialised_safely(module):
    """`safe_json_dumps` and not `json.dumps`: these events carry attacker-controlled strings,
    and a NUL byte in one of them aborts the INSERT — which on this path loses the event."""
    import importlib

    src = inspect.getsource(importlib.import_module(f"honeylens.ingest.{module}"))

    assert "safe_json_dumps(event)" in src
