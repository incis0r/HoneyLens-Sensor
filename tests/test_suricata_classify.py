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
