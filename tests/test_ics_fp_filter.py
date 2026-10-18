"""ICS false-positive filter — the sensor's own outbound traffic (e.g. to the
Ollama API on :11434) must not be recorded as an ICS attack.

Regression for the bug where the payload-only binary detectors classified
outbound sensor->Ollama / sensor->internal flows as modbus/iec104/enip/opcua.
"""

from honeylens.ingest.ics_helpers import ICS_PROTO_PORTS, ics_port_consistent

# ── False positives: sensor's own outbound traffic, no ICS service port ──────


def test_ollama_modbus_is_rejected():
    # sensor:ephemeral -> Ollama 192.168.0.50:11434, payload misread as Modbus
    assert ics_port_consistent("modbus", 38158, 11434) is False


def test_ollama_iec104_is_rejected():
    assert ics_port_consistent("iec104", 44694, 11434) is False


def test_internal_3100_enip_is_rejected():
    assert ics_port_consistent("enip", 37622, 3100) is False


def test_ollama_opcua_is_rejected():
    assert ics_port_consistent("opcua", 42442, 11434) is False


def test_generic_ics_without_ics_port_is_rejected():
    assert ics_port_consistent("ics-generic", 50000, 11434) is False


# ── True positives: real ICS sessions on their service port ──────────────────


def test_inbound_modbus_probe_is_kept():
    # attacker:ephemeral -> honeypot:502
    assert ics_port_consistent("modbus", 11440, 502) is True


def test_honeypot_modbus_reply_is_kept():
    # honeypot reply: src_port 502 -> attacker:ephemeral
    assert ics_port_consistent("modbus", 502, 40000) is True


def test_inbound_s7comm_is_kept():
    assert ics_port_consistent("s7comm", 44598, 102) is True


def test_inbound_enip_is_kept():
    assert ics_port_consistent("enip", 37253, 44818) is True


def test_generic_ics_on_real_port_is_kept():
    assert ics_port_consistent("ics-generic", 50000, 502) is True


# ── Robustness ───────────────────────────────────────────────────────────────


def test_protocol_port_mismatch_is_rejected():
    # modbus payload claimed, but the only ICS-ish port is OPC-UA's 4840
    assert ics_port_consistent("modbus", 50000, 4840) is False


def test_non_numeric_ports_do_not_crash():
    assert ics_port_consistent("modbus", None, "502") is True
    assert ics_port_consistent("modbus", None, None) is False


def test_every_protocol_has_a_known_port():
    for proto, ports in ICS_PROTO_PORTS.items():
        assert ports, proto
        # the protocol's own port round-trips as consistent
        assert ics_port_consistent(proto, 55000, next(iter(ports))) is True
