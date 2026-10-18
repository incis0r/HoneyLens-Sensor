"""The ICS API serves ics_events.metadata to clients on all seven sensors.

Defect guarded against: MQTT decoy metadata carries the attacker-supplied
username and password, and the API handed the column out verbatim.
"""

import inspect
import re

from honeylens.routes import ics

# Lines that name the column without handing its value to a client: SQL select-lists
# ("severity, confidence, metadata, acknowledged") and the bare "metadata", entries of the
# cols lists that dict(zip(cols, row)) uses. Anything else mentioning metadata is a
# serving site and must redact. Exemptions are deliberately narrow: a bare identifier
# list, so `return metadata` or `x["metadata"]` is never exempt.
_COLUMN_LIST_LINE = re.compile(r'^["\s]*(\w+\s*,\s*)*metadata(\s*,\s*\w+)*[,"\s]*$')


def test_every_metadata_site_is_redacted():
    """MQTT metadata holds username and password, and the ICS API is on all seven sensors.

    Fails closed: any line in the module that mentions metadata and is not a column
    list must call redact_structure (directly, or through ics.servable_metadata, which masks hex
    then calls it), whatever the variable is named.
    """
    src = inspect.getsource(ics)
    sites = [
        line
        for line in src.splitlines()
        if "metadata" in line and not _COLUMN_LIST_LINE.match(line)
    ]
    assert sites, "no metadata serving site found; the filter has gone stale"
    unredacted = [
        line.strip()
        for line in sites
        # _decoded_block masks the frame itself before decoding and emits no dict.
        if not any(t in line for t in ("redact_structure", "servable_metadata(", "_decoded_block("))
    ]
    assert not unredacted, f"metadata served without redact_structure: {unredacted}"


def test_served_metadata_masks_password_but_keeps_topic():
    """A fake MQTT row, shaped the way the route shapes it, must not leak the password."""
    row = {"metadata": {"username": "admin", "password": "hunter2", "topic": "plant/pump"}}
    row["metadata"] = ics.redact_structure(row["metadata"])
    assert row["metadata"]["password"] == "<redacted:7>"
    assert row["metadata"]["username"] == "<redacted:5>"
    assert row["metadata"]["topic"] == "plant/pump"
