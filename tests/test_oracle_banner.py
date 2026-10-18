"""Oracle TNS listener banner realism.

nmap reported the decoy as `Oracle TNS listener 0.0.0.0.0`. VSNNUM is the listener's
version packed into 32 bits and scanners decode and print it, so VSNNUM=0 produced a
version string that has never shipped — a reliable tell that the service is not Oracle.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeylens.honeypots.hp_oracle import OracleHoneypot


def _decode(vsnnum):
    return (
        f"{vsnnum >> 24}.{(vsnnum >> 20) & 0xF}.{(vsnnum >> 12) & 0xFF}."
        f"{(vsnnum >> 8) & 0xF}.{vsnnum & 0xFF}"
    )


def test_vsnnum_is_not_zero():
    assert OracleHoneypot.VSNNUM != 0


def test_vsnnum_decodes_to_a_release_that_exists():
    major = OracleHoneypot.VSNNUM >> 24
    assert 9 <= major <= 23, _decode(OracleHoneypot.VSNNUM)
    assert _decode(OracleHoneypot.VSNNUM) == "19.3.0.0.0"


def test_refusal_carries_the_version_and_the_error():
    data = OracleHoneypot.refuse_data.fget(OracleHoneypot())
    assert b"VSNNUM=321912832" in data
    assert b"ERR=12505" in data
    assert b"ERROR_STACK" in data
    assert b"VSNNUM=0)" not in data


def test_refusal_shape_matches_a_real_listener():
    """A real 19c listener includes an empty TMP field before VSNNUM."""
    data = OracleHoneypot.refuse_data.fget(OracleHoneypot())
    assert data.startswith(b"(DESCRIPTION=(TMP=)(VSNNUM=")
