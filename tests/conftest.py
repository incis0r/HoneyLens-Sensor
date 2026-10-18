"""Honeypot log directories for the duration of the tests.

The ``honeypots/honeypot.py`` monolith creates its log directories at import time (debt
from 0.9, to be moved into ``main()``), so without this the import would fail with
``PermissionError`` under a user with no rights to ``/opt/logs``. ``setdefault`` leaves a
real override from the environment alone — the 0.9 conftest did the same.
"""

import os
import tempfile
from pathlib import Path

_HP_TEST_LOGS = Path(tempfile.gettempdir()) / "honeylens-test-logs"
os.environ.setdefault("HONEYWEB_LOG_DIR", str(_HP_TEST_LOGS / "honeyweb"))
os.environ.setdefault("HONEYPOTNG_LOG_DIR", str(_HP_TEST_LOGS / "honeypotng"))
os.environ.setdefault("HONEYPOT_DATA_DIR", str(_HP_TEST_LOGS / "data"))

# Vendor decoys persist their identity (cert, hostname, honeytoken) next to the TLS cert path.
# Point that at a temp dir so importing/running them in tests never writes ns_hostname /
# sp_* into the repository root (A5).
_HP_TEST_ID = _HP_TEST_LOGS / "identity"
os.environ.setdefault("NETSCALER_TLS_CERT", str(_HP_TEST_ID / "netscaler.crt"))
os.environ.setdefault("SHAREPOINT_TLS_CERT", str(_HP_TEST_ID / "sharepoint.crt"))
os.environ.setdefault("SHAREPOINT_DATA_DIR", str(_HP_TEST_ID))
