"""A start timeout below the measured start time is a restart loop with no exit.

`UserNS=keep-id` makes podman re-own every image layer and every volume when it creates the
container. On `sensor-h` that takes minutes: the h2 rollout measured **3 min 32 s** for
`hp-http` on 2026-11-14 and wrote it down, and the generator still emitted
`TimeoutStartSec=120`.

What that combination does, from the host's journal on 2026-11-18:

    13:42:50  image pull localhost/honeylens/hp-http:main-c298131
    13:46:20  Found incomplete layer "29a59f…", deleting it
    13:46:27  image pull localhost/honeylens/hp-http:main-c298131
    13:49:58  Found incomplete layer "a62db9…", deleting it
    13:50:05  image pull localhost/honeylens/hp-http:main-c298131

systemd SIGTERMs the create at 120 s, podman leaves a half-written layer, the next attempt
deletes it and starts from zero, and `Restart=always` makes that forever. Three decoys on an
internet-exposed sensor stayed down through seven cycles, and **`systemctl --state=failed`
never listed them** — the state is `deactivating`/`stop-sigterm`, not `failed`, so the fleet
status probe reported a healthy host.

600 s is not a guess at the slowest possible host; it is four times the slowest start this
fleet has measured, on the understanding that a start which overruns is a slow host and a start
that never finishes is a loop.
"""

from __future__ import annotations

import re

from honeylens.honeypots import manifest
from honeylens.honeypots.cli import quadlet


def _quadlet_for(name: str = "http") -> str:
    return quadlet(
        manifest.BY_NAME[name], state_dir="/var/lib/x", image_tag="t", registry="localhost"
    )


def test_the_start_timeout_accommodates_the_slowest_measured_start():
    m = re.search(r"^TimeoutStartSec=(\d+)$", _quadlet_for(), re.MULTILINE)
    assert m, "the quadlet must state a start timeout; the systemd default is 90 s"
    assert int(m.group(1)) >= 600, (
        "a timeout at or under the measured 212 s start on sensor-h is a restart loop"
    )


def test_the_unit_still_restarts_on_a_real_failure():
    """Raising the timeout must not turn a crash into a hang: `Restart=always` stays."""
    q = _quadlet_for()
    assert "Restart=always" in q
    assert "RestartSec=5" in q
