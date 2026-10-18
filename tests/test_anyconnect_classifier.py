"""Classification of the Cisco AnyConnect tunnel-group enumeration campaign.

Observed on sensor1 from 2026-08-08: unsolicited AnyConnect `auth-init` POSTs to `/`
on :8443, ~25 000 events on alternating days from 200-400 source IPs, and **every one
of them classified as nothing**. Capturing request bodies (2026-08-21) is what finally
showed what they were; the traffic itself had been arriving for two weeks.

The kit randomises three fields per request — `computer-name`, `unique-id` and the MAC
— and leaves the rest constant. Two of those choices are what these rules key on:

* It generates the MAC as six random bytes with no masking, so ~half the addresses have
  the **multicast bit set** in the first octet. No physical NIC can carry such an
  address, which makes it a statement about the sender rather than a guess.
* It claims AnyConnect **4.5.04029 on Windows Server 2022 hardware** — a 2018 client
  build reporting rack-server models (PowerEdge, ProLiant, UCS). Internally consistent,
  but not a shape a real endpoint has.

Deliberately NOT a rule: `POST / body_len≈700`. Matching a request's *shape* rather than
its content is what made the K8s port-only rules inflate 853 events into K8S_ATTACK.
Bodies are the evidence; length is not.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row

# A real captured body, verbatim apart from the target address.
AUTH_INIT = """<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
  <version who="vpn">4.5.04029</version>
  <device-id computer-name="ukovlpudod" device-type="Dell PowerEdge R640" \
platform-version="10.0.20348 " unique-id="EA14B0B6E876F894DF6914D2792783E5">win</device-id>
  <mac-address-list>
    <mac-address public-interface="true">%s</mac-address>
  </mac-address-list>
  <group-access>https://198.51.100.10:8443</group-access>
<group-select>telecommuters</group-select>
  <capabilities>
    <auth-method>single-sign-on</auth-method>
  </capabilities>
</config-auth>"""


def _classify(body, **meta):
    md = {"dst_port": 8443, "method": "POST", "path": "/", "body_sample": body}
    md.update(meta)
    return classify_event_row(payload=f"POST / body_len={len(body)}", protocol="HTTPS", metadata=md)


def _rules(hits):
    return {h[1] for h in hits}


# ------------------------------------------------- the gate that hid all of it
#
# The missing rule was only half the story. `HTTPS` is in `_ENCRYPTED_PROTOCOLS`,
# so GATE 1 returned [] for every event the TLS listener produced — no text rule
# could fire on :8443 at all, whatever it said. That gate is right about a packet
# capture, where TLS really is opaque, and wrong about a honeypot, which holds the
# server key, terminates the connection and parses the request itself.


def test_text_rules_run_on_a_request_the_sensor_decrypted_itself():
    """A honeypot that reports a method and a path has plaintext in hand."""
    hits = classify_event_row(
        payload="POST /wp-login.php body_len=40",
        protocol="HTTPS",
        metadata={
            "dst_port": 8443,
            "method": "POST",
            "path": "/wp-login.php",
            "body_sample": "file=../../../../etc/passwd",
        },
    )
    assert hits, "text rules still skipped on a decrypted HTTPS request"
    assert any(h[0] == "LFI" for h in hits)


def test_opaque_tls_is_still_skipped():
    """Without parsed HTTP structure the payload really is ciphertext, and the
    original reason for the gate still holds."""
    assert (
        classify_event_row(
            payload="\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03 union select",
            protocol="TLS",
            metadata={"dst_port": 443},
        )
        == []
    )


def test_a_method_alone_does_not_open_the_gate():
    """`method` without any parsed request detail could come from anywhere; the
    exception has to stay narrow or it is not an exception."""
    assert (
        classify_event_row(
            payload="union select 1,2,3",
            protocol="HTTPS",
            metadata={"dst_port": 8443, "method": "POST"},
        )
        == []
    )


def test_ssh_banner_exception_still_works():
    """The pre-existing carve-out must survive the new one."""
    hits = classify_event_row(
        payload="SSH-2.0-libssh_0.7.0", protocol="SSH", metadata={"dst_port": 22}
    )
    assert isinstance(hits, list)


# --------------------------------------------------------------- the campaign


def test_anyconnect_auth_init_is_classified_at_all():
    """The baseline failure: 145 000 events over 14 days carried no attack_type."""
    hits = _classify(AUTH_INIT % "4c-ac-db-e5-c9-0c")
    assert hits, "an unsolicited AnyConnect auth-init produced no classification"
    assert "cisco_anyconnect_auth_init" in _rules(hits)


def test_auth_init_is_tagged_as_vpn_recon():
    hits = _classify(AUTH_INIT % "4c-ac-db-e5-c9-0c")
    assert any(h[0] == "VPN_RECON" for h in hits)


def test_vpn_recon_is_registered_in_the_taxonomy():
    """An attack type absent from ATTACK_TYPE_SEVERITY silently scores as the
    default, which hides whether anyone chose its severity on purpose."""
    from honeylens.classification.scoring import ATTACK_TYPE_SEVERITY, get_severity

    assert "VPN_RECON" in ATTACK_TYPE_SEVERITY
    assert get_severity("VPN_RECON", "cisco_anyconnect_auth_init") == "medium"


# ------------------------------------------------------------ the forged MAC


@pytest.mark.parametrize(
    "mac",
    [
        "03-08-c1-75-53-d4",  # first octet 0x03 -> multicast bit set
        "05-86-fd-2a-15-ab",
        "09-a8-b5-94-58-5e",
        "0b-57-1d-80-5f-c6",
        "ff-21-1f-7b-6a-ef",
    ],
)
def test_multicast_bit_macs_are_flagged_as_forged(mac):
    """Bit 0 of the first octet marks a multicast address. A NIC's own MAC never
    has it, so this cannot be a real client reporting its hardware."""
    assert "cisco_anyconnect_forged_mac" in _rules(_classify(AUTH_INIT % mac))


@pytest.mark.parametrize(
    "mac",
    [
        "4c-ac-db-e5-c9-0c",  # 0x4c -> unicast
        "00-28-2a-fb-8a-be",
        "d8-3a-e8-65-71-6f",
        "b8-cc-74-dc-cf-43",
    ],
)
def test_valid_unicast_macs_are_not_flagged_as_forged(mac):
    """Roughly half the campaign's MACs are accidentally valid. Those must not
    trip the forged-MAC rule, or the rule says nothing about anything."""
    assert "cisco_anyconnect_forged_mac" not in _rules(_classify(AUTH_INIT % mac))


def test_forged_mac_outranks_the_plain_probe():
    from honeylens.classification.scoring import RULE_SEVERITY_OVERRIDE

    assert RULE_SEVERITY_OVERRIDE.get("cisco_anyconnect_forged_mac") == "high"


# ------------------------------------------------------------- the client UA


def test_legacy_anyconnect_user_agent_is_flagged():
    """The kit pins one 2018 client build across every source IP.

    Passed as a plain `user_agent` string, which is how hp_nginx now records it —
    the classifier only reads string metadata, so a UA left inside the headers dict
    is stored and never matched.
    """
    hits = _classify("", user_agent="AnyConnect Windows 4.5.04029")
    assert "cisco_anyconnect_legacy_client" in _rules(hits)


def test_current_secure_client_is_not_flagged_as_legacy():
    """Cisco Secure Client 5.x is the supported product; do not tag it as the kit."""
    hits = _classify("", user_agent="Cisco Secure Client 5.1.2.42 (Windows)")
    assert "cisco_anyconnect_legacy_client" not in _rules(hits)


# ------------------------------------------------------------- false positives


@pytest.mark.parametrize(
    "body",
    [
        '{"query":"query IntrospectionQuery{__schema{queryType{name}}}"}',
        "username=admin&password=Summer2024!",
        '<?xml version="1.0"?><soap:Envelope><soap:Body/></soap:Envelope>',
        "",
    ],
)
def test_unrelated_bodies_do_not_trigger_vpn_rules(body):
    rules = _rules(_classify(body)) if body else set()
    assert not {r for r in rules if r.startswith("cisco_anyconnect")}


def test_the_word_config_auth_alone_is_not_enough():
    """A rule that fires on a substring this common would be noise. The Cisco
    handshake is identified by the element AND its client attribute."""
    hits = _classify("see the config-auth section of the manual for client setup")
    assert not {r for r in _rules(hits) if r.startswith("cisco_anyconnect")}


def test_a_mac_outside_the_anyconnect_element_is_not_forged_evidence():
    """The forged-MAC rule must stay anchored to the AnyConnect device report;
    a multicast address elsewhere (DHCP logs, ARP dumps) means something else."""
    hits = _classify("dhcp discover from 03-08-c1-75-53-d4 on eth0")
    assert "cisco_anyconnect_forged_mac" not in _rules(hits)
