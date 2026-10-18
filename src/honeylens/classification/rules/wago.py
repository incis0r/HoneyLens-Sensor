"""Text attack-detection rules — group: wago (Idea 54).

These catch WAGO WBM attack shapes on payloads that arrive through paths other than
the honeypot itself — eBPF capture, another honeypot's log, a Suricata payload. The
honeypot's own `honeypots/wago/detector.py` is richer (it sees parsed form fields and
per-source history); this family is the safety net for everything else.

Deliberately no CVE-named rules: an identifier is bound to a shape only after CIRCL
confirms it exists, and none have been verified for this surface yet.
"""

import re


def register(add):
    # --- reconnaissance ----------------------------------------------------
    add(
        "WAGO_RECON",
        "wago_wbm_page_access",
        r"GET\s+/wbm/(?:state|rts_info|tcpip|ethernet|port|snmp|mass_storage)\.(?:php|ssi)",
        re.I,
    )

    add("WAGO_RECON", "wago_wbm_banner", r"WAGO\s+Ethernet\s+Web-Based\s+Management|750-8202", re.I)

    # --- the I/O map is what an attacker reads before touching a process ----
    add("WAGO_IO_DISCLOSURE", "wago_io_config_read", r"GET\s+/wbm/io_config\.xml", re.I)

    add("WAGO_IO_DISCLOSURE", "wago_config_backup_read", r"GET\s+/wbm/plc_backup\.cfg", re.I)

    # --- credentials -------------------------------------------------------
    add("WAGO_CREDENTIAL_CAPTURE", "wago_wbm_login_post", r"POST\s+/wbm/users\.ssi", re.I)

    # Vendor default. A source using it knows what it is talking to.
    add(
        "WAGO_CREDENTIAL_CAPTURE",
        "wago_default_credentials",
        r"username=admin&password=wago\b",
        re.I,
    )

    # --- control: the ones that would matter on a real plant ---------------
    add("WAGO_CONTROL_WRITE", "wago_plc_stop", r"plc-action=(?:stop|reset)\b", re.I)

    add(
        "WAGO_CONTROL_WRITE",
        "wago_process_write",
        r"form-name=process_control|(?:pump=(?:on|off)[&\s].*(?:setpoint|valve)=)",
        re.I,
    )

    add("WAGO_CONTROL_WRITE", "wago_network_reconfigure", r"POST\s+/wbm/tcpip\.php", re.I)

    add("WAGO_FIRMWARE_UPLOAD", "wago_firmware_post", r"POST\s+/wbm/firmware_update\.php", re.I)

    # --- exploitation shapes against WBM parameters ------------------------
    add(
        "WAGO_EXPLOIT_ATTEMPT",
        "wago_wbm_traversal",
        r"/wbm/[^\s]*(?:\.\./){2,}|/wbm/[^\s]*/etc/passwd",
        re.I,
    )

    add(
        "WAGO_EXPLOIT_ATTEMPT",
        "wago_wbm_command_injection",
        r"(?:hostname|ip-address|gateway|subnet-mask)=[^&\s]*[;|`][^&\s]*"
        r"(?:cat|wget|curl|nc|sh|busybox|chmod)\b",
        re.I,
    )
