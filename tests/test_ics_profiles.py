# tests/test_ics_profiles.py
from honeylens.honeypots.honeypots_config import get_profile


def test_ics_profiles_present():
    assert get_profile("fox")["niagara_version"]
    assert get_profile("fox")["brand_id"] == "vykon"
    assert get_profile("profinet")["vendor_id"] == "0x002A"
    assert get_profile("mms")["vendor"] == "SIEMENS"
