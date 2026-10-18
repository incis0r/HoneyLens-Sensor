"""Text attack-detection rules — group: iot.

Auto-relocated from classification/text_rules.py (Phase 2 / T8). The rule
literals are verbatim; edit rules here, not in the façade.
"""

import re


def register(add):
    add("IOT_ATTACK", "mqtt_connect", r"\x10.{1,4}MQTT", re.DOTALL)

    add(
        "IOT_ATTACK",
        "mqtt_anonymous_connect",
        r"MQTT.{1,10}(anonymous|guest|admin|test|mqtt|user)",
        re.IGNORECASE | re.DOTALL,
    )

    add("IOT_ATTACK", "mqtt_wildcard_subscribe", r"\x82.{2,6}(\x00[\x01-\x10])?#", re.DOTALL)

    add("IOT_ATTACK", "mqtt_sys_topic_subscribe", r"\x82.{2,20}\$SYS", re.DOTALL)

    add(
        "IOT_ATTACK",
        "mqtt_control_publish",
        r"(command|control|actuator|valve|pump|motor|relay|switch|setpoint)\x00",
        re.IGNORECASE,
    )

    # An injection is something executable in the VALUE, not a `command` key in the object.
    #
    # The pattern used to be `\{[^}]*("command"|"cmd"|…)[^}]*\}` -- any JSON object with one of
    # those keys. That is the shape every command-protocol decoy of ours writes:
    # `{"phase": "command", "command": "...", "dst_port": 25}`. So the rule matched our own
    # serialisation, on every port, and the port gate let it past because the gate tested the
    # attack TYPE and this rule is typed IOT_ATTACK rather than MQTT_ATTACK.
    #
    # Measured on sensor-a 2026-11-05: 237,286 rows on :25, 9,825 on :21, 9,075 on :6379, 5,238 on
    # :11211. By command on port 25: `AUTH LOGIN` 63,730, `RSET` 61,604, `QUIT` 54,478,
    # `EHLO localhost` 53,628. 261,531 IOT_ATTACK rows in all, 259,002 carrying that and
    # nothing else -- so a quarter of a million rows said "IoT attack" about SMTP punctuation.
    #
    # `{"command": "ON"}` is what MQTT is FOR, so the value must carry a shell metacharacter,
    # a substitution, or a named binary.
    add(
        "IOT_ATTACK",
        "mqtt_command_injection",
        r"\{[^}]*\"(?:command|cmd|action|execute)\"\s*:\s*\"[^\"]*"
        r"(?:[;|`]|\$\(|\$\{|&&|\|\||\b(?:wget|curl|nc|ncat|sh|bash|busybox|chmod|reboot|rm)\b)",
        re.IGNORECASE,
    )

    add(
        "IOT_ATTACK",
        "mqtt_industrial_topic",
        r"(factory|plant|plc|scada|sensor|actuator|hmi)/(control|command|write|set)",
        re.IGNORECASE,
    )

    add(
        "IOT_ATTACK",
        "mqtt_weak_credentials",
        r"MQTT.{1,20}(password|admin123|12345|default|changeme|mqtt|test)",
        re.IGNORECASE | re.DOTALL,
    )

    add(
        "IOT_ATTACK",
        "mqtt_scanner_mqttsa",
        r"(mqttsa|mqtt.?scan|mqtt.?brute|mqtt.?fuzz)",
        re.IGNORECASE,
    )

    add(
        "IOT_ATTACK",
        "mqtt_mosquitto_exploit",
        r"(mosquitto.*(exploit|vuln|cve)|CVE.*(mosquitto|mqtt))",
        re.IGNORECASE,
    )

    add(
        "IOT_ATTACK",
        "mqtt_will_injection",
        r"MQTT.{4}\x04.{0,20}(last.?will|lwt|testament)",
        re.IGNORECASE | re.DOTALL,
    )

    add("IOT_ATTACK", "coap_discovery", r"\x40\x01.{2}\.well-known/core", re.DOTALL)

    add("IOT_ATTACK", "coap_put_request", r"\x40\x03", re.DOTALL)  # CoAP PUT

    add("IOT_ATTACK", "coap_delete_request", r"\x40\x04", re.DOTALL)  # CoAP DELETE

    add("IOT_ATTACK", "amqp_connection", r"AMQP\x00\x00\x09\x01", re.DOTALL)

    add(
        "IOT_ATTACK",
        "zigbee_network_key",
        r"(zigbee|zwave).*(network.?key|link.?key|trust.?center)",
        re.IGNORECASE,
    )

    add(
        "IOT_ATTACK",
        "lorawan_key_extraction",
        r"(lorawan|lora).*(app.?key|nwk.?key|dev.?eui)",
        re.IGNORECASE,
    )

    add(
        "IOT_ATTACK",
        "iot_default_login",
        r"(device|sensor|gateway|iot|embedded|firmware).*(admin:admin|root:root|user:user|admin:password|admin:1234)",
        re.IGNORECASE,
    )

    add(
        "IOT_ATTACK",
        "smart_home_attack",
        r"(home.?assistant|homekit|smartthings|tuya|nest).*(api|key|token|password)",
        re.IGNORECASE,
    )

    add(
        "IOT_ATTACK",
        "iiot_gateway_probe",
        r"(iiot|edge.?gateway|fog.?node).*(config|admin|debug)",
        re.IGNORECASE,
    )
