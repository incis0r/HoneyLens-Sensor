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


# ---------------------------------------------------------------------------
# The label must have an attack_patterns row behind it.
#
# A reprocess rebuilds sensor_events.attack_types from the union of an event's attack_patterns,
# so a label with no row behind it is a label the next backfill deletes. The ingest's companion
# insert carried `ON CONFLICT (event_id, attack_type, rule_name)` while no unique index matched
# those columns, so Postgres rejected the statement outright, the error was logged at debug level,
# and the pipeline reported success. Measured on sensor-a 2026-11-01: zero rows with
# `rule_name LIKE 'suricata_sid_%'` against 2.19M Suricata events, and 1,991,772 labels erased.


class _RecordingConn(_CapturingConn):
    """Records every statement, not just the event insert."""

    def __init__(self, fail_on: str | None = None):
        super().__init__()
        self.statements: list[tuple[str, object]] = []
        self._fail_on = fail_on

    def execute(self, sql, params=None):
        self.statements.append((sql, params))
        if self._fail_on and self._fail_on in sql:
            import psycopg2

            raise psycopg2.ProgrammingError(
                "there is no unique or exclusion constraint matching the ON CONFLICT specification"
            )
        super().execute(sql, params)

    def pattern_inserts(self) -> list[tuple[str, object]]:
        return [(s, p) for s, p in self.statements if "INSERT INTO attack_patterns" in s]


def test_the_ingest_writes_an_attack_patterns_row_for_every_alert():
    """Without this row the label survives only until the next reprocess."""
    from honeylens.ingest.suricata import process_alert

    conn = _RecordingConn()
    assert process_alert(conn, _alert(2072555, _HUNT)) is True
    inserts = conn.pattern_inserts()
    assert len(inserts) == 1, f"expected one attack_patterns insert, got {len(inserts)}"
    params = inserts[0][1]
    assert params[0] == conn.rows[0][0], "the pattern must reference the event just written"
    assert params[2] == "suricata_sid_2072555", params


def test_a_failed_pattern_insert_is_loud_and_does_not_fail_the_event(caplog):
    """The event is already committed (the ingest runs autocommit), so it must not be reported
    as failed -- but the failure has to be visible, which is exactly what did not happen."""
    import logging

    from honeylens.ingest.suricata import process_alert

    conn = _RecordingConn(fail_on="INSERT INTO attack_patterns")
    with caplog.at_level(logging.WARNING, logger="honeylens.ingest.suricata"):
        assert process_alert(conn, _alert(2072555, _HUNT)) is True
    assert conn.rows, "the event itself must still be written"
    assert any("attack_patterns row NOT written" in r.message for r in caplog.records), [
        r.message for r in caplog.records
    ]


def test_a_unique_index_covers_the_conflict_target_the_ingest_relies_on():
    """The ON CONFLICT column list is only legal while some migration declares a matching unique
    index. This is the assertion the original bug would have failed for a month."""
    from honeylens.db.migrate import MIGRATIONS_DIR

    sql = "\n".join(p.read_text() for p in sorted(MIGRATIONS_DIR.glob("*.sql")))
    normalised = " ".join(sql.split()).lower()
    assert "unique index if not exists idx_ap_event_type_rule on attack_patterns" in normalised
    assert "(event_id, attack_type, rule_name)" in normalised


# ---------------------------------------------------------------------------
# A CVE claim also needs the port to run the affected software.
#
# Measured fleet-wide 2026-11-04 (the 4 Oct-4 Nov fleet review §5.6): our nginx rule 9026731
# put CVE-2026-42533 on 402 rows of which three were on the nginx decoy -- 287 on :80 (the Apache
# bait on sensor-a/prod, the NetScaler decoy on sensor-b), 66 on etcd's :2379 -- and our Apache
# mod_http2 rule 9026500 put CVE-2026-23918 on 575 rows across 28 ports, telnet, SMTP, MySQL,
# RDP, VNC, OPC UA and EtherNet/IP among them. Separately, ET sid 2019526 ("WEB-PHP phpinfo
# access") declares CVE-2002-1149, turning 393 reconnaissance requests into an exploit finding.
# ---------------------------------------------------------------------------


def _alert_on(sid: int, signature: str, cve: str, dest_port: int) -> dict:
    a = _alert(sid, signature)
    a["dest_port"] = dest_port
    a["alert"]["metadata"] = {"cve": [cve]}
    return a


def _types_for_alert(alert: dict) -> str:
    from honeylens.ingest.suricata import process_alert

    conn = _CapturingConn()
    assert process_alert(conn, alert) is True
    assert conn.rows, "nothing was inserted"
    return conn.rows[0][8]


_NGINX_RULE = "HONEYLENS CVE-2026-42533 NGINX script-engine — over-long POST body capture"
_APACHE_RULE = "HONEYLENS CVE-2026-23918 Apache mod_http2 — cleartext h2c upgrade attempt"
_PHPINFO_RULE = "ET WEB_SERVER WEB-PHP phpinfo access"


def test_the_nginx_cve_still_lands_on_the_nginx_decoy():
    types = _types_for_alert(_alert_on(9026731, _NGINX_RULE, "CVE_2026_42533", 8000))
    assert "CVE_2026_42533" in types, types


def test_the_nginx_cve_does_not_land_on_etcd():
    """The row the operator flagged: an over-long POST body to :2379 is not an nginx RCE."""
    types = _types_for_alert(_alert_on(9026731, _NGINX_RULE, "CVE_2026_42533", 2379))
    assert "CVE_2026_42533" not in types, types
    assert types, "the base verdict must still land"


def test_the_nginx_cve_does_not_land_on_the_apache_bait():
    # 287 of its 402 rows were here.
    types = _types_for_alert(_alert_on(9026731, _NGINX_RULE, "CVE_2026_42533", 80))
    assert "CVE_2026_42533" not in types, types


def test_the_apache_cve_does_not_land_on_telnet_or_mysql():
    for port in (23, 3306, 5900, 44818):
        types = _types_for_alert(_alert_on(9026500, _APACHE_RULE, "CVE_2026_23918", port))
        assert "CVE_2026_23918" not in types, (port, types)


def test_a_phpinfo_access_does_not_assert_a_2002_cve():
    types = _types_for_alert(_alert_on(2019526, _PHPINFO_RULE, "CVE_2002_1149", 8080))
    assert "CVE_2002_1149" not in types, types
    assert types, "the base verdict must still land"


def test_a_withheld_cve_is_still_recorded_as_declared():
    """Same contract as the hunting gate: the claim is withheld, the evidence is not destroyed."""
    import json

    from honeylens.ingest.suricata import process_alert

    conn = _CapturingConn()
    process_alert(conn, _alert_on(9026731, _NGINX_RULE, "CVE_2026_42533", 2379))
    payload = json.loads(conn.rows[0][7])
    assert payload["cve_declared"] == ["CVE_2026_42533"]
    assert payload["cve"] == ""
    assert payload["suricata_sid"] == 9026731


def test_a_third_party_cve_for_a_product_we_do_not_impersonate_is_untouched():
    """~1,500 rows are legitimate attempts against web products on our HTTP decoy ports."""
    types = _types_for_alert(
        _alert_on(2061339, "ET WEB_SPECIFIC_APPS Vite Arbitrary File Read", "CVE_2025_30208", 8080)
    )
    assert "CVE_2025_30208" in types, types
