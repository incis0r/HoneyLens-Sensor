"""Text attack-detection rules — group: messaging.

Auto-relocated from classification/text_rules.py (Phase 2 / T8). The rule
literals are verbatim; edit rules here, not in the façade.
"""

import re


def register(add):
    add("SMTP_PROBE", "smtp_vrfy", r"\bVRFY\s+\S+", re.IGNORECASE)

    add("SMTP_PROBE", "smtp_expn", r"\bEXPN\s+\S+", re.IGNORECASE)

    add("SMTP_PROBE", "smtp_rcpt_to", r"\bRCPT\s+TO\s*:\s*<?[^>\s]+", re.IGNORECASE)

    add("SMTP_PROBE", "smtp_helo", r"^HELO\s+\S+", re.IGNORECASE | re.MULTILINE)

    add("SMTP_PROBE", "smtp_ehlo", r"^EHLO\s+\S+", re.IGNORECASE | re.MULTILINE)

    add("SMTP_PROBE", "smtp_mail_from", r"\bMAIL\s+FROM\s*:\s*<?[^>\s]+", re.IGNORECASE)

    add(
        "SMTP_PROBE",
        "smtp_user_enum",
        r"\b(VRFY|EXPN)\s+(root|admin|administrator|postmaster|info|test|guest|user)",
        re.IGNORECASE,
    )

    add("MQTT_ATTACK", "mqtt_wildcard_all", r"(SUBSCRIBE|SUB)\s*['\"]?\s*#\s*['\"]?", re.IGNORECASE)

    add("MQTT_ATTACK", "mqtt_wildcard_single", r"(SUBSCRIBE|SUB)\s+[^#]*\+", re.IGNORECASE)

    add(
        "MQTT_ATTACK",
        "mqtt_sys_topic_enum",
        r"\$SYS/(broker|clients|load|subscriptions|messages|bytes|version|uptime)",
        re.IGNORECASE,
    )

    add("MQTT_ATTACK", "mqtt_sys_wildcard", r"\$SYS/#", re.IGNORECASE)

    add("MQTT_ATTACK", "mqtt_scanner_mosquitto", r"mosquitto_(sub|pub|ctrl)\s+", re.IGNORECASE)

    add("MQTT_ATTACK", "mqtt_scanner_mqttsa", r"(mqttsa|mqtt-pwn|mqtt_fuzz)", re.IGNORECASE)

    add("MQTT_ATTACK", "mqtt_scanner_nmap", r"mqtt-subscribe|nmap.*mqtt", re.IGNORECASE)

    add(
        "MQTT_ATTACK",
        "mqtt_anonymous_connect",
        r"CONNECT\s+.*?(anonymous|guest|public|test)\b",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_empty_clientid",
        r"client[-_]?id\s*[=:]\s*['\"]?\s*['\"]?(\s|$)",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_default_user_text",
        r"MQTT.*username[=:\s]+['\"]?(admin|root|mqtt|device|sensor|guest)['\"]?",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_default_pass_text",
        r"MQTT.*password[=:\s]+['\"]?(admin|password|mqtt|123456|default|public|1234)['\"]?",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_topic_sensitive",
        r"(topic|subscribe)[=:\s]+.*(password|credential|secret|token|api[-_]?key|private)",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_config_disclosure",
        r"(config|settings|setup)/(wifi|network|credentials|auth)",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_iot_keywords",
        r"(sensor|actuator|device|gateway|hub)/(status|control|command|data)",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_qos2_abuse",
        r"QoS\s*[=:]\s*2|quality[-_]?of[-_]?service\s*[=:]\s*2",
        re.IGNORECASE,
    )

    add("MQTT_ATTACK", "mqtt_retain_flag", r"retain\s*[=:]\s*(true|1|yes)", re.IGNORECASE)

    add(
        "MQTT_ATTACK",
        "mqtt_will_message",
        r"(will[-_]?topic|last[-_]?will|lwt)\s*[=:]",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_topic_injection",
        r"(publish|pub)\s+.*?['\"][^'\"]*[\x00-\x1f][^'\"]*['\"]",
        re.IGNORECASE,
    )

    add("MQTT_ATTACK", "mqtt_topic_traversal", r"topic[=:\s]+['\"]?\.\.\/", re.IGNORECASE)

    add(
        "MQTT_ATTACK",
        "mqtt_connection_flood",
        r"(connect|connection)\s*(flood|dos|attack|storm)",
        re.IGNORECASE,
    )

    add("MQTT_ATTACK", "mqtt_large_payload", r"payload[-_]?size\s*[=:>]\s*\d{6,}", re.IGNORECASE)

    add("MQTT_ATTACK", "mqtt_slowite", r"slow[-_]?(ite|dos|connection|mqtt)", re.IGNORECASE)

    add(
        "MQTT_ATTACK",
        "mqtt_version_probe",
        r"mqtt[-_]?version|protocol[-_]?version\s*[=:]\s*(3\.1|5\.0|31|311|5)",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_broker_version",
        r"\$SYS/broker/(version|changeset|timestamp)",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_broker_stats",
        r"\$SYS/broker/(clients|messages|subscriptions)/(total|active|connected)",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_cred_extract",
        r"(connectionMQTT|mqtt[-_]?(host|port|username|password|endpoint|clientId))\s*[=:]",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK", "mqtt_js_config", r"(host|broker|server)\s*:\s*['\"]mqtts?://", re.IGNORECASE
    )

    add(
        "MQTT_ATTACK",
        "mqtt_websocket",
        r"(wss?://.*:8084|ws://.*mqtt|websocket.*mqtt)",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_acl_bypass",
        r"(acl|access[-_]?control|permission)\s*(bypass|test|check)",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_unauthorized_pub",
        r"(publish|pub)\s+.*?(admin|system|config|root)/",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_malformed",
        r"(malformed|invalid|corrupt)\s*(mqtt|packet|message)",
        re.IGNORECASE,
    )

    add(
        "MQTT_ATTACK",
        "mqtt_protocol_error",
        r"protocol[-_]?error|mqtt[-_]?error|connack\s*(fail|reject|error)",
        re.IGNORECASE,
    )

    # Was `payload =~ /\d{10}/` — Suricata rule syntax, which Python searched for as a
    # literal string. It could not match anything, and never did on any sensor.
    # Command injection carried in an MQTT topic or payload. The pattern must
    # describe the injection, not the size or shape of the message.
    #
    # It was `\d{10}` — any ten consecutive digits — from the August 2026 repair
    # of an IDS-syntax rule. That repair was only tested for what it should match,
    # never for what it must not, so it went on to tag SIP INVITEs (the callee's
    # phone number), PostgreSQL password messages (a slice of the MD5) and every
    # Unix timestamp as MQTT_ATTACK. Every production hit it ever produced was a
    # false positive.
    #
    # Shell metacharacters immediately followed by a command are the actual
    # signal. Backticks, $(...), and a pipe/semicolon into a known binary.
    add(
        "MQTT_ATTACK",
        "MQTT_Command_Injection_Detection",
        r"(?:`[^`\n]{1,80}`"
        r"|\$\([^)\n]{1,80}\)"
        r"|[;|&]{1,2}\s*/?(?:bin/)?(?:sh|bash|nc|ncat|curl|wget|python3?|perl|busybox)\b)",
        re.IGNORECASE,
    )

    # Alternation bound looser than intended: `A|B` made `image/(webp|avif|apng)` a
    # standalone branch, so a bare `Accept: image/webp` matched on its own. Both sides
    # are now grouped, and the header half is required.
    # Renamed from claude_http_headers_to_mqtt_port: the classifier scopes rules whose
    # name starts with "mqtt_" to MQTT ports and protocols. Under the old name the
    # rule was unscoped, and all four of its production hits were on 6379 (Redis).
    add(
        "MQTT_ATTACK",
        "mqtt_http_headers_on_mqtt_port",
        r"""(?i)(?:accept:|user-agent:|host:|sec-|content-type:)"""
        r"""[\s\S]*?(?:application/xml|image/(?:webp|avif|apng))""",
    )

    add(
        "SMTP_PROBE",
        "claude_smtp_generic_helo_probe",
        r"""^HELO\s+(User|user|admin|test|guest|mail|server|localhost|example)\s*$""",
    )

    add("SMTP_PROBE", "claude_smtp_probe_mail_from_without_helo", r"""^Mail from:<[^>]+>$""")

    add("SMTP_PROBE", "claude_smtp_rcpt_to_enumeration", r"""^RCPT\s+to:<[^>]+@[^>]+>$""")

    add("SMTP_PROBE", "claude_smtp_recipient_enumeration", r"""RCPT\s+[tT][oO]:\s*<[^>]+>""")
