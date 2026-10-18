"""Suricata signature-aware attack_type classification (ingest/suricata.py).

Guards against the coarse category->attack_type mislabels: SSH brute-force
tagged RCE, reputation-list hits tagged EXPLOIT, ET SCAN scattered across
INFO_DISCLOSURE/ANOMALY/RCE.
"""

from honeylens.ingest.suricata import classify_attack


def test_libssh_bruteforce_is_bruteforce_not_rce():
    # The reported bug: classtype attempted-admin -> category RCE, but it's brute-force.
    sig = "ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack"
    assert classify_attack(sig, "Attempted Administrator Privilege Gain") == "BRUTE_FORCE"


def test_reputation_lists_are_reputation_not_exploit():
    for sig in (
        "ET DROP Dshield Block Listed Source group 1",
        "ET CINS Active Threat Intelligence Poor Reputation IP group 254",
        "ET DROP Spamhaus DROP Listed Traffic Inbound group 10",
    ):
        assert classify_attack(sig, "Misc Attack") == "REPUTATION", sig


def test_et_scan_family_is_scanner():
    for sig, cat in (
        ("ET SCAN Potential SSH Scan", "Attempted Information Leak"),
        ("ET SCAN Suspicious inbound to mySQL port 3306", "Potentially Bad Traffic"),
        ("ET SCAN NMAP OS Detection Probe", "Attempted Information Leak"),
        ("ET SCAN Sipvicious Scan", "Attempted Information Leak"),
        ("ET SCAN Zmap User-Agent (Inbound)", "Misc activity"),
    ):
        assert classify_attack(sig, cat) == "SCANNER", sig


def test_tor_node_traffic_is_tor_not_exploit():
    for sig in (
        "ET TOR Known Tor Exit Node Traffic group 99",
        "ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 24",
    ):
        assert classify_attack(sig, "Misc Attack") == "TOR", sig


def test_genuine_rce_still_rce():
    # No scan/brute/reputation keyword -> falls through to the category map.
    sig = "ET EXPLOIT Possible Apache Struts OGNL Remote Code Execution"
    assert classify_attack(sig, "Attempted Administrator Privilege Gain") == "RCE"


def test_web_app_attack_falls_back_to_category():
    sig = "ET WEB_SPECIFIC_APPS Possible SQL Injection"
    assert classify_attack(sig, "Web Application Attack") == "WEB_EXPLOIT"


def test_dos_and_malware_and_unknown():
    assert (
        classify_attack("ET DOS Possible Denial Of Service", "Attempted Denial of Service") == "DOS"
    )
    assert (
        classify_attack("ET MALWARE Win32/Trojan CnC Checkin", "A Network Trojan was Detected")
        == "MALWARE"
    )
    assert classify_attack("Totally novel thing", "Nonexistent Category") == "SURICATA_ALERT"


# ---------------------------------------------------------------------------------------------
# A HUNTING rule's declared CVE is not a CVE finding.
#
# Measured on sensor-a 2026-10-30: six sources sent a byte-identical 302-byte probe whose body is
# `PHP_SESSION_UPLOAD_PROGRESS=internet-census` with `filename="internet-census.txt"` and the
# content `1`. It carries no code. All six were stored as `EXPLOIT,CVE_2026_109619` and were
# counted as PHP2Shell operators in three successive threat reviews, because
# `ET HUNTING PHP Generic Upload Progress Session Manipulation` (sid 2072555) declares that CVE
# in its metadata. The ET feed is third party, so a local rule edit is overwritten on update.


class _CapturingConn:
    """Enough of a psycopg2 connection to read back what would have been inserted."""

    def __init__(self):
        self.rows = []
        self._self = self

    def cursor(self):
        return self

    def execute(self, sql, params=None):
        if params is not None and "INSERT INTO sensor_events" in sql:
            self.rows.append(params)

    def close(self):
        pass

    def commit(self):
        pass


def _alert(sid: int, signature: str) -> dict:
    return {
        "event_type": "alert",
        "timestamp": "2026-10-30T17:45:36.513704+0100",
        "src_ip": "185.226.197.77",
        "src_port": 54321,
        "dest_port": 80,
        "proto": "tcp",
        "alert": {
            "signature_id": sid,
            "signature": signature,
            "category": "Misc Attack",
            "severity": 2,
            "metadata": {"cve": ["CVE_2026_109619"], "confidence": ["Low"]},
        },
    }


_HUNT = "ET HUNTING PHP Generic Upload Progress Session Manipulation"
_EXPLOIT = "ET EXPLOIT PHP php2shell Code Injection in Filename (CVE-2026-109619)"


def _attack_types_for(sid: int, signature: str) -> str:
    from honeylens.ingest.suricata import process_alert

    conn = _CapturingConn()
    assert process_alert(conn, _alert(sid, signature)) is True
    assert conn.rows, "nothing was inserted"
    return conn.rows[0][8]  # attack_types, 9th bound parameter


def test_a_hunting_rule_does_not_assert_the_cve_it_names():
    types = _attack_types_for(2072555, _HUNT)
    assert "CVE_2026_109619" not in types, types
    assert types, "the attack_type itself must still land"


def test_the_paired_exploit_rule_still_asserts_the_cve():
    """The fix must not disarm the rule that does make the claim -- that one is the finding."""
    types = _attack_types_for(2072554, _EXPLOIT)
    assert "CVE_2026_109619" in types, types


def test_the_hunting_hit_still_records_what_the_rule_declared():
    """Withholding the verdict must not destroy the evidence: the declared CVE and the signature
    text stay in the payload so the hunt is still possible, it is just not a positive claim."""
    import json

    from honeylens.ingest.suricata import process_alert

    conn = _CapturingConn()
    process_alert(conn, _alert(2072555, _HUNT))
    payload = json.loads(conn.rows[0][7])
    assert payload["cve_declared"] == ["CVE_2026_109619"]
    assert payload["hunting"] is True
    assert payload["suricata_sid"] == 2072555
