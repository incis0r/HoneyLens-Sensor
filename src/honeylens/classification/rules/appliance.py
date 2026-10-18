"""Text attack-detection rules — group: appliance.

Auto-relocated from classification/text_rules.py (Phase 2 / T8). The rule
literals are verbatim; edit rules here, not in the façade.
"""

import re


def register(add):
    add(
        "FORTI_ATTACK",
        "forti_cve_2022_40684",
        r"Forwarded:\s*.*for\s*=\s*(127\.0\.0\.1|localhost|::1)",
        re.IGNORECASE,
    )

    add(
        "FORTI_ATTACK",
        "forti_cve_2022_40684_xff",
        r"X-Forwarded-For:\s*(127\.0\.0\.1|localhost)",
        re.IGNORECASE,
    )

    add("FORTI_ATTACK", "forti_cve_2023_27997", r"/remote/hostcheck_validate")

    add("FORTI_ATTACK", "forti_cve_2023_27997_lang", r"/remote/fgt_lang")

    add(
        "FORTI_ATTACK",
        "forti_cve_2024_21762",
        r"/api/v2/cmdb/.*Content-Length:\s*[1-9]\d{4,}",
        re.IGNORECASE,
    )

    add(
        "FORTI_ATTACK",
        "fortiweb_cve_2025_64446_authbypass",
        r"/api/v2\.0/user/local\.add|\.\./\.\./mkey",
    )

    add(
        "FORTI_ATTACK",
        "fortiweb_cve_2025_64446_backup_upload",
        r"/api/v2\.0/system/maintenance/backup",
    )

    add("FORTI_ATTACK", "fortiweb_cve_2025_64446_rce_trigger", r"\bpwned\.dat\b")

    add("FORTI_ATTACK", "forti_api_status", r"/api/v2/monitor/system/status")

    add("FORTI_ATTACK", "forti_api_admin", r"/api/v2/cmdb/system/admin")

    add("FORTI_ATTACK", "forti_api_config_backup", r"/api/v2/monitor/system/config/backup")

    add("FORTI_ATTACK", "forti_api_firmware", r"/api/v2/monitor/system/firmware")

    add("FORTI_ATTACK", "forti_api_firewall", r"/api/v2/cmdb/firewall/policy")

    add("FORTI_ATTACK", "forti_logincheck", r"/logincheck.*secretkey=")

    add("FORTI_ATTACK", "forti_ng_login", r"/ng/login")

    add("FORTI_ATTACK", "forti_sslvpn_login", r"/remote/login")

    add("FORTI_ATTACK", "forti_sslvpn_logincheck", r"/remote/logincheck.*credential=")

    add("FORTI_ATTACK", "forti_sslvpn_info", r"/remote/info")

    add(
        "FORTI_ATTACK",
        "forti_scanner_nuclei",
        r"nuclei.*fortigate|fortigate.*nuclei",
        re.IGNORECASE,
    )

    add(
        "FORTI_ATTACK",
        "forti_scanner_exploit",
        r"(CVE-2022-40684|CVE-2023-27997|CVE-2024-21762)",
        re.IGNORECASE,
    )

    # ---- Ivanti Connect Secure / Policy Secure -------------------------------
    # CVE-2023-46805 (auth bypass) chained into CVE-2024-21887 (command injection):
    # the request traverses out of an unauthenticated endpoint to reach an
    # authenticated one. The traversal is the signal — the endpoint alone is normal.
    #
    # The review proposed also matching `/api/v1/cav/client/status/pathTraversal`.
    # That literal is a description of the flaw, not traffic; a rule containing it
    # would match nothing, which is the defect the `payload =~` rules had.
    add(
        "APPLIANCE_EXPLOIT",
        "ivanti_ics_auth_bypass_traversal",
        r"/api/v1/(?:totp/user-backup-code|license/keys-status|system/maintenance)"
        r"[^\s]*(?:\.\./|%2e%2e)",
        re.IGNORECASE,
    )

    # CVE-2024-21893 — SSRF in the SAML component.
    add(
        "APPLIANCE_EXPLOIT",
        "ivanti_ics_saml_ssrf",
        r"/dana-ws/saml(?:20|sso|ecp)\.ws",
        re.IGNORECASE,
    )

    # ---- Palo Alto PAN-OS GlobalProtect --------------------------------------
    # CVE-2024-3400: the payload rides in the SESSID cookie as a traversal that
    # creates a file under the web root. Both halves are required — a hipreport
    # request with an ordinary session id is normal GlobalProtect traffic.
    add(
        "APPLIANCE_EXPLOIT",
        "panos_cve_2024_3400_hipreport_sessid",
        r"(?is)/ssl-vpn/hipreport\.esp.{0,400}?SESSID\s*=\s*[^\r\n;]*" r"(?:\.\./|\.\.%2f|%2e%2e)",
        re.IGNORECASE,
    )

    # ---- Cisco AnyConnect / ASA SSL-VPN --------------------------------------
    # A tunnel-group enumeration campaign has been posting AnyConnect `auth-init`
    # handshakes at :8443 since 2026-08-08 — ~25 000 events on alternating days from
    # 200-400 sources — and matched nothing at all until the request body was being
    # stored. These rules key on the body and the client identity, never on the
    # request's shape: `POST / body_len≈700` describes the campaign perfectly today
    # and would describe half the internet tomorrow.

    # The handshake itself. Anchored on the element AND its client attribute, so the
    # bare phrase "config-auth" in prose cannot trigger it.
    add(
        "VPN_RECON",
        "cisco_anyconnect_auth_init",
        r"<config-auth\b[^>]*\bclient\s*=\s*[\"']vpn[\"']",
        re.IGNORECASE,
    )

    # The tell the operator did not think about. AnyConnect reports the endpoint's own
    # MAC; this kit generates six random bytes and never masks bit 0 of the first
    # octet, which marks a *multicast* address. No NIC can own one, so ~half the
    # campaign's clients announce hardware that cannot exist. The second hex digit
    # carries that bit — odd means multicast. Kept anchored inside <mac-address> so a
    # multicast address in an ARP or DHCP capture is not mistaken for this.
    add(
        "VPN_RECON",
        "cisco_anyconnect_forged_mac",
        r"<mac-address\b[^>]*>\s*[0-9a-f][13579bdf](?:[:-][0-9a-f]{2}){5}\s*<",
        re.IGNORECASE,
    )

    # One pinned 2018 build across every source IP. Cisco's supported client is
    # "Cisco Secure Client 5.x"; an AnyConnect 4.x UA arriving unsolicited at a decoy
    # is the kit, not a user. Bounded to 3.x/4.x so 5.x never matches.
    add(
        "VPN_RECON",
        "cisco_anyconnect_legacy_client",
        r"\bAnyConnect\b(?:\s+\w+)?\s+[34]\.\d+\.\d+",
        re.IGNORECASE,
    )

    # The GET surface. Every rule above keys on a POSTed body, so a plain
    # `GET /+CSCOE+/logon.html` — the first thing any ASA scanner asks for — matched
    # nothing and was left to whatever else happened to fire. On our sensors it came
    # back as AI_DETECTED, as PANOS_PROBE when it landed on the PAN-OS decoy, as
    # FORTI_PROBE on the FortiGate one, and most often as nothing at all.
    #
    # `+` is a regex quantifier, so the literal plus signs must be escaped; scanners
    # also send them percent-encoded, hence the alternation.
    #
    # Anchored on the *directory*, not on a list of filenames. `/+CSCOE+/`, `/+CSCOU+/`,
    # `/+CSCOT+/` and `/+webvpn+/` exist on no other vendor's appliance, so anything
    # requested beneath them is a Cisco request — which is what makes attribution from
    # the path alone defensible. Enumerating filenames instead left gaps that only
    # surfaced in the data: `/+CSCOU+/csco_logo.gif`, which scanners fetch to fingerprint
    # an ASA, was still landing as PANOS_PROBE and FORTI_PROBE.
    add(
        "VPN_RECON",
        "cisco_webvpn_portal_probe",
        r"/(?:\+|%2b)(?:CSCOE|CSCOU|CSCOT|webvpn)(?:\+|%2b)/[^\s\"'<>]*",
        re.IGNORECASE,
    )

    # AnyConnect's OEM-customization endpoint, requested by the real client during a
    # normal profile fetch — on its own this is reconnaissance, not exploitation.
    add(
        "VPN_RECON",
        "cisco_anyconnect_oem_customization",
        r"/(?:\+|%2b)CSCOT(?:\+|%2b)/oem-customization\b",
        re.IGNORECASE,
    )

    # Credentials pushed into the WebVPN portal via the URL rather than a form body.
    # The POST form is already covered; the GET variant was left to an AI rule that
    # filed it as AI_DETECTED — a label that says a rule fired and nothing else. A
    # password crossing the wire in a query string is a credential event whichever verb
    # carries it.
    add(
        "CREDENTIAL",
        "cisco_webvpn_credentials_in_query",
        r"/(?:\+|%2b)?webvpn(?:\+|%2b)?/index\.html\?[^\s\"']{0,200}?"
        r"username=[^&\s]{1,64}&[^\s\"']{0,120}?password=",
        re.IGNORECASE,
    )

    # CVE-2020-3452 — unauthenticated arbitrary file read in the ASA/FTD WebVPN
    # translation-table and oem-customization handlers. Kept apart from the recon rules
    # and given the exploit class deliberately: a traversal in `platform`,
    # `resource-type` or `lang` is an attempt to read a file off the appliance, not a
    # scanner noting that a portal exists. Anchored on a +CSCOT+/+CSCOE+ path, so a
    # traversal anywhere else belongs to somebody else's rule.
    # The traversal is the *whole* value, not a prefix of a longer path: the requests we
    # see carry `platform=..&resource-type=..`, and the translation-table variant carries
    # `lang=../`. An earlier version required a slash after the dots and matched neither.
    add(
        "APPLIANCE_EXPLOIT",
        "cisco_cve_2020_3452_file_read",
        r"/(?:\+|%2b)CSCO[TE](?:\+|%2b)/(?:translation-table|oem-customization)"
        r"[^\s\"']{0,300}?[?&](?:platform|resource-type|lang|name)="
        r"(?:\.\.|%2e%2e)(?:[/\\&]|%2f|[\s\"']|$)",
        re.IGNORECASE,
    )

    # ---- Citrix NetScaler ADC / Gateway --------------------------------------
    # CVE-2026-88771 — pre-auth command injection to RCE. The exploit (watchTowr PoC,
    # Sina Kheirkhah) poisons the pitboss/NSPPE log channel through the `login` field of
    # POST /nf/auth/doAuthentication.do with a value shaped like a genuine NSPPE crash line
    # so the log processor later picks the injected command up:
    #   login=pitboss PPE unexpectedly died NSPPE;<command>;# X   (also URL-encoded)
    # The honeypot_netscaler decoy already flags this on its own; this gives the central
    # classifier the same IOC so it lands in attack_patterns/MITRE and survives backfill.
    # Anchored on the invariant tell — the pitboss…NSPPE log line followed by a command
    # separator — which no benign Gateway login carries. `;` appears raw or as %3b.
    add(
        "APPLIANCE_EXPLOIT",
        "citrix_cve_2026_88771_pitboss_cmdi",
        r"pitboss[^\r\n]{0,120}NSPPE[^\r\n]{0,4}(?:;|%3b)",
        re.IGNORECASE,
    )
