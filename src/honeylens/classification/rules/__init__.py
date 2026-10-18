"""Text-rule registry (Phase 2 / T8).

Each group module exposes `register(add)`; `register_all` feeds them the
`_add` sink from classification/text_rules.py, rebuilding `_RULES`.
"""

from . import (
    ai,
    api_auth,
    appliance,
    cloud_container,
    database,
    ics,
    iot,
    messaging,
    scanners,
    serialization,
    smb,
    wago,
    web_injection,
)

_GROUPS = [
    web_injection,
    scanners,
    api_auth,
    serialization,
    ai,
    cloud_container,
    database,
    messaging,
    smb,
    ics,
    iot,
    appliance,
    wago,
]


def register_all(add):
    for group in _GROUPS:
        group.register(add)
