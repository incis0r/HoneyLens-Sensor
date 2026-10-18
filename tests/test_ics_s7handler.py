from honeylens.honeypots.honeypots_config import get_profile
from honeylens.honeypots.hp_s7comm import handle_s7_dt


def test_s7_setup_communication_recon():
    # S7 ROSCTR=Job (0x01), function Setup Communication (0xF0)
    payload = b"\x32\x01\x00\x00\x00\x00\x00\x08\x00\x00\xf0\x00\x00\x01\x00\x01\x01\xe0"
    resp, kind = handle_s7_dt(payload, get_profile("s7comm"))
    assert resp and resp[0] == 0x32 and kind in ("enumeration", "recon")


def test_s7_write_var_is_write():
    # S7 Job, function Write Var (0x05)
    payload = b"\x32\x01\x00\x00\x00\x00\x00\x0e\x00\x00\x05\x01" + b"\x00" * 8
    _resp, kind = handle_s7_dt(payload, get_profile("s7comm"))
    assert kind == "write"
