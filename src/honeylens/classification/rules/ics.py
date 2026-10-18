"""Text attack-detection rules — group: ics.

Auto-relocated from classification/text_rules.py (Phase 2 / T8). The rule
literals are verbatim; edit rules here, not in the façade.
"""

import re


def register(add):
    add("MODBUS", "modbus_read_coils", r"\x00\x00..\x01\x01", re.DOTALL)  # FC 0x01 Read Coils

    add(
        "MODBUS", "modbus_read_discrete_inputs", r"\x00\x00..\x01\x02", re.DOTALL
    )  # FC 0x02 Read Discrete Inputs

    add(
        "MODBUS", "modbus_read_holding_registers", r"\x00\x00..\x01\x03", re.DOTALL
    )  # FC 0x03 Read Holding Registers

    add(
        "MODBUS", "modbus_read_input_registers", r"\x00\x00..\x01\x04", re.DOTALL
    )  # FC 0x04 Read Input Registers

    add(
        "MODBUS", "modbus_write_coil_binary", r"\x00\x00..\x01\x05", re.DOTALL
    )  # FC 0x05 Write Single Coil

    add(
        "MODBUS", "modbus_write_register_binary", r"\x00\x00..\x01\x06", re.DOTALL
    )  # FC 0x06 Write Single Register

    add(
        "MODBUS", "modbus_write_multi_coils_binary", r"\x00\x00..\x01\x0f", re.DOTALL
    )  # FC 0x0F Write Multiple Coils

    add(
        "MODBUS", "modbus_write_multi_registers_binary", r"\x00\x00..\x01\x10", re.DOTALL
    )  # FC 0x10 Write Multiple Registers

    add(
        "MODBUS", "modbus_diagnostics_binary", r"\x00\x00..\x01\x08", re.DOTALL
    )  # FC 0x08 Diagnostics

    add(
        "MODBUS", "modbus_device_id_binary", r"\x00\x00..\x01\x2b\x0e", re.DOTALL
    )  # FC 0x2B/0x0E MEI Read Device ID

    add(
        "MODBUS", "modbus_report_slave_binary", r"\x00\x00..\x01\x11", re.DOTALL
    )  # FC 0x11 Report Slave ID

    add(
        "MODBUS", "modbus_broadcast_binary", r"\x00\x00..\x00[\x05\x06\x0f\x10]", re.DOTALL
    )  # Unit ID 0 with write FC

    add(
        "MODBUS",
        "modbus_illegal_fc_binary",
        r"\x00\x00..[\x00\x01][\x09\x0a\x0d\x0e\x29\x2a\x5a-\x64\x7d-\x7f]",
        re.DOTALL,
    )

    add("MODBUS", "modbus_write_single_coil", r"modbus.*(function|fc)\s*[=:]\s*(5|0x0?5)\b")

    add("MODBUS", "modbus_write_single_register", r"modbus.*(function|fc)\s*[=:]\s*(6|0x0?6)\b")

    add("MODBUS", "modbus_write_multiple_coils", r"modbus.*(function|fc)\s*[=:]\s*(15|0x0?[fF])\b")

    add("MODBUS", "modbus_write_multiple_registers", r"modbus.*(function|fc)\s*[=:]\s*(16|0x1?0)\b")

    add("MODBUS", "modbus_mask_write_register", r"modbus.*(function|fc)\s*[=:]\s*(22|0x16)\b")

    add("MODBUS", "modbus_read_write_registers", r"modbus.*(function|fc)\s*[=:]\s*(23|0x17)\b")

    add("MODBUS", "modbus_read_device_id", r"modbus.*(function|fc)\s*[=:]\s*(43|0x2[bB])\b")

    add("MODBUS", "modbus_report_slave_id", r"modbus.*(function|fc)\s*[=:]\s*(17|0x11)\b")

    add("MODBUS", "modbus_diagnostics", r"modbus.*(function|fc)\s*[=:]\s*(8|0x0?8)\b")

    add("MODBUS", "modbus_read_exception", r"modbus.*(function|fc)\s*[=:]\s*(7|0x0?7)\b")

    add(
        "MODBUS",
        "modbus_illegal_fc_user_defined",
        r"modbus.*(function|fc)\s*[=:]\s*(9[0-9]|100|0x5[aA-fF]|0x6[0-4])",
    )

    add(
        "MODBUS",
        "modbus_illegal_fc_reserved",
        r"modbus.*(function|fc)\s*[=:]\s*(12[5-7]|0x7[dDeEfF])",
    )

    add("MODBUS", "modbus_read_file_record", r"modbus.*(function|fc)\s*[=:]\s*(20|0x14)\b")

    add("MODBUS", "modbus_write_file_record", r"modbus.*(function|fc)\s*[=:]\s*(21|0x15)\b")

    add(
        "MODBUS",
        "modbus_scanner_modbuspwn",
        r"(modbuspwn|modbus.?pwn|modbus.?exploit)",
        re.IGNORECASE,
    )

    add("MODBUS", "modbus_scanner_smod", r"(smod|scada.?modbus|modbus.?scanner)", re.IGNORECASE)

    add("MODBUS", "modbus_scanner_mbtget", r"(mbtget|modbus.?tcp.?client)", re.IGNORECASE)

    add(
        "MODBUS",
        "modbus_scanner_metasploit_modbus",
        r"(modbus/scanner|modbus/client|modbusclient)",
        re.IGNORECASE,
    )

    add(
        "MODBUS",
        "modbus_crash_plc",
        r"(plc.?crash|crash.?plc|dos.?modbus|modbus.?dos)",
        re.IGNORECASE,
    )

    add("MODBUS", "modbus_restart_comm", r"modbus.*(restart|reset|reboot|halt|stop)", re.IGNORECASE)

    add(
        "MODBUS",
        "modbus_critical_register_write",
        r"(write|set).*(register|coil)\s*[=:@]\s*(0x)?0{0,2}[0-9]{1,2}\b",
    )

    add(
        "MODBUS",
        "modbus_register_zero_value",
        r"(register|value)\s*[=:]\s*0\b.*modbus|modbus.*(register|value)\s*[=:]\s*0\b",
    )

    add(
        "MODBUS", "modbus_register_max_value", r"(register|value)\s*[=:]\s*(65535|0x[fF]{4}|9999)\b"
    )

    add("MODBUS", "modbus_broadcast_unit_id", r"modbus.*(unit|slave)\s*[=:]\s*(0|255|0x[fF]{2})\b")

    add(
        "MODBUS",
        "modbus_schneider_unity",
        # Schneider Modicon identifiers, anchored. Bare "unity" matched "community",
        # "opportunity", etc., and bare "tsx" matched .tsx (TypeScript/React) files, tagging
        # ordinary HTTP as Modbus. Require the actual product form: "Unity Pro", a Modicon
        # model number, or a TSX model with digits — never the bare word.
        r"\b(unity[ _-]?pro|modicon|twido|m221|m241|m251|tsx\d{2,})\b",
        re.IGNORECASE,
    )

    add("MODBUS", "modbus_schneider_quantum", r"(quantum|140.?cpu|140.?cra)", re.IGNORECASE)

    add(
        "MODBUS",
        "modbus_siemens_s7_probe",
        r"(s7.?comm|s7.?300|s7.?400|s7.?1200|s7.?1500)",
        re.IGNORECASE,
    )

    add("ICS_ATTACK", "dnp3_data_link_probe", r"\x05\x64", re.DOTALL)  # DNP3 start bytes

    add(
        "ICS_ATTACK",
        "dnp3_read_request",
        r"dnp3.*read\s*(class|analog|binary|counter)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "dnp3_cold_restart",
        r"dnp3.*(cold.?restart|function.?code.?0x0d)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "dnp3_warm_restart",
        r"dnp3.*(warm.?restart|function.?code.?0x0e)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "dnp3_disable_unsolicited",
        r"dnp3.*(disable.?unsolicited|function.?code.?0x15)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "dnp3_direct_operate",
        r"dnp3.*(direct.?operate|function.?code.?0x0[345])",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "dnp3_select_operate",
        r"dnp3.*(select|operate).*(crob|analog.?output)",
        re.IGNORECASE,
    )

    add("ICS_ATTACK", "dnp3_write_request", r"dnp3.*write.*(time|interval|index)", re.IGNORECASE)

    add(
        "ICS_ATTACK",
        "dnp3_file_transfer",
        r"dnp3.*(file.?transfer|authenticate.?file|abort.?file)",
        re.IGNORECASE,
    )

    add("ICS_ATTACK", "dnp3_clear_restart_iin", r"dnp3.*(clear.?restart|clear.?iin)", re.IGNORECASE)

    add("ICS_ATTACK", "dnp3_scanner_aegis", r"(aegis|dnp3.?scan|dnp3.?master)", re.IGNORECASE)

    add("ICS_ATTACK", "s7comm_header", r"\x03\x00.{2}\x02\xf0\x80\x32", re.DOTALL)

    add(
        "ICS_ATTACK",
        "s7comm_read_szl",
        r"s7.*(read.?szl|system.?status.?list|szl.?id)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "s7comm_cpu_info",
        r"s7.*(cpu.?info|module.?info|identification)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "s7comm_list_blocks",
        r"s7.*(list.?blocks|block.?list|read.?db|read.?ob|read.?fc|read.?fb)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "s7comm_download_block",
        r"s7.*(download|upload).*(block|program)",
        re.IGNORECASE,
    )

    add("ICS_ATTACK", "s7comm_write_var", r"s7.*(write.?var|write.?area|write.?db)", re.IGNORECASE)

    add("ICS_ATTACK", "s7comm_stop_cpu", r"s7.*(stop.?cpu|plc.?stop|cpu.?stop)", re.IGNORECASE)

    add(
        "ICS_ATTACK",
        "s7comm_plc_control",
        r"s7.*(plc.?control|memory.?copy|compress|insert)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK", "s7comm_set_clock", r"s7.*(set.?clock|write.?clock|time.?sync)", re.IGNORECASE
    )

    add(
        "ICS_ATTACK",
        "s7comm_set_password",
        r"s7.*(set.?password|password|authentication)",
        re.IGNORECASE,
    )

    add("ICS_ATTACK", "s7comm_scanner_plcscan", r"(plcscan|s7scan|snap7|s7.?client)", re.IGNORECASE)

    add("ICS_ATTACK", "s7comm_metasploit", r"metasploit.*(s7|siemens|profinet)", re.IGNORECASE)

    add("ICS_ATTACK", "enip_list_identity", r"(list.?identity|ethernet.?ip.*0x63)", re.IGNORECASE)

    add("ICS_ATTACK", "enip_list_services", r"(list.?services|ethernet.?ip.*0x04)", re.IGNORECASE)

    add(
        "ICS_ATTACK",
        "enip_list_interfaces",
        r"(list.?interfaces|ethernet.?ip.*0x64)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "cip_get_attributes",
        r"cip.*(get.?attribute|service.?0x0[13e])",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "cip_get_all_attributes",
        r"cip.*(get.?all|multiple.?attribute)",
        re.IGNORECASE,
    )

    add("ICS_ATTACK", "cip_set_attribute", r"cip.*(set.?attribute|service.?0x10)", re.IGNORECASE)

    add("ICS_ATTACK", "cip_execute", r"cip.*(execute|apply|reset)", re.IGNORECASE)

    add("ICS_ATTACK", "cip_reset_service", r"cip.*(reset.?service|service.?0x05)", re.IGNORECASE)

    add("ICS_ATTACK", "cip_stop_service", r"cip.*(stop|abort|halt)", re.IGNORECASE)

    add("ICS_ATTACK", "enip_scanner_nmap", r"nmap.*enip|enip.?scan|cip.?enum", re.IGNORECASE)

    add("ICS_ATTACK", "enip_scanner_plcinfo", r"(plcinfo|pycomm|cpppo)", re.IGNORECASE)

    add("ICS_ATTACK", "bacnet_whois", r"bacnet.*(who.?is|who.?has|i.?am|i.?have)", re.IGNORECASE)

    add(
        "ICS_ATTACK",
        "bacnet_device_discovery",
        r"bacnet.*(device.?instance|object.?identifier)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "bacnet_read_property",
        r"bacnet.*(read.?property|confirmed.?service.?0x0c)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "bacnet_read_property_multiple",
        r"bacnet.*(read.?property.?multiple|rpm)",
        re.IGNORECASE,
    )

    add("ICS_ATTACK", "bacnet_read_range", r"bacnet.*(read.?range|trend.?log)", re.IGNORECASE)

    add(
        "ICS_ATTACK",
        "bacnet_write_property",
        r"bacnet.*(write.?property|confirmed.?service.?0x0f)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "bacnet_write_property_multiple",
        r"bacnet.*(write.?property.?multiple|wpm)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "bacnet_subscribe_cov",
        r"bacnet.*(subscribe.?cov|change.?of.?value)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "bacnet_reinitialize",
        r"bacnet.*(reinitialize|device.?comm.?control)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "bacnet_scanner_bacpypes",
        r"(bacpypes|bacnet.?scan|bas.?scanner)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "opcua_find_servers",
        r"opc.?ua.*(find.?servers|get.?endpoints)",
        re.IGNORECASE,
    )

    add("ICS_ATTACK", "opcua_browse", r"opc.?ua.*(browse|browse.?next|translate)", re.IGNORECASE)

    add(
        "ICS_ATTACK",
        "opcua_read_attributes",
        r"opc.?ua.*(read.?attribute|read.?node)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "opcua_create_subscription",
        r"opc.?ua.*(create.?subscription|monitored.?item)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "opcua_history_read",
        r"opc.?ua.*(history.?read|read.?raw|read.?processed)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "opcua_write",
        r"opc.?ua.*(write|write.?value|write.?attribute)",
        re.IGNORECASE,
    )

    add("ICS_ATTACK", "opcua_call_method", r"opc.?ua.*(call|method.?call|invoke)", re.IGNORECASE)

    add(
        "ICS_ATTACK",
        "opcua_no_security",
        r"opc.?ua.*(security.?mode.?none|no.?security|anonymous)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "opcua_scanner",
        r"(opcua.?scan|ua.?expert|python.?opcua|asyncua)",
        re.IGNORECASE,
    )

    add("ICS_ATTACK", "iec104_startdt", r"iec.?104.*(startdt|start.?data.?transfer)", re.IGNORECASE)

    add(
        "ICS_ATTACK",
        "iec104_interrogation",
        r"iec.?104.*(interrogation|general.?interrogation|c_ic_na)",
        re.IGNORECASE,
    )

    add("ICS_ATTACK", "iec104_read_command", r"iec.?104.*(read.?command|c_rd_na)", re.IGNORECASE)

    add(
        "ICS_ATTACK",
        "iec104_counter_interrogation",
        r"iec.?104.*(counter.?interrogation|c_ci_na)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "iec104_single_command",
        r"iec.?104.*(single.?command|c_sc_na|c_sc_ta)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "iec104_double_command",
        r"iec.?104.*(double.?command|c_dc_na|c_dc_ta)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "iec104_regulating_step",
        r"iec.?104.*(regulating.?step|c_rc_na)",
        re.IGNORECASE,
    )

    add("ICS_ATTACK", "iec104_setpoint", r"iec.?104.*(setpoint|c_se_na|c_se_nc)", re.IGNORECASE)

    add("ICS_ATTACK", "iec104_reset_process", r"iec.?104.*(reset.?process|c_rp_na)", re.IGNORECASE)

    add("ICS_ATTACK", "iec104_scanner", r"(iec104.?scan|60870.?scan|scada.?scan)", re.IGNORECASE)

    add(
        "ICS_ATTACK",
        "caldera_agent_beacon",
        r"(sandcat|manx|ragdoll|stockpile|54ndc47)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "caldera_c2_api",
        r"/api/(rest|v2)/(operations|agents|abilities)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "caldera_payload_download",
        r"/file/download.*\.(exe|ps1|sh|py)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "caldera_ability_execute",
        r"(ability[_\-]id|operation[_\-]id)\s*[=:]\s*[a-f0-9\-]{8,}",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "caldera_executor_config",
        r"\{[^}]*\"(executor|payloads)\"\s*:",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK",
        "caldera_adversary_profile",
        r"(adversary[_\-]?profile|atomic[_\-]?red[_\-]?team|emu[_\-]?plugin)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK", "caldera_ics_fieldmanual", r"(fieldmanual|ics.?ttp|ot.?attack)", re.IGNORECASE
    )

    add(
        "ICS_ATTACK", "ics_port_scan", r"scan.*(502|20000|44818|47808|4840|2404|102)", re.IGNORECASE
    )

    add("ICS_ATTACK", "ics_shodan_query", r"shodan.*(modbus|scada|plc|ics|hmi)", re.IGNORECASE)

    add(
        "ICS_ATTACK",
        "ics_banner_grab",
        r"(banner|version|identify).*(plc|scada|hmi|rtu)",
        re.IGNORECASE,
    )

    add(
        "ICS_ATTACK", "Modbus_Stack_Buffer_Overflow", r"""^5a47[0-9a-fA-F]{10}00000005002b0e0100$"""
    )

    add("ICS_ATTACK", "Modbus_Unauthenticated_Write_Attempt", r"""\b5a4700000005002b0e0100\b""")

    # Filed under SQLI, which it is not: MongoDB is not SQL, and the traffic is a
    # Modbus frame. The second branch `.*d3.*admin\.\$cmd` was also greedy enough to
    # match any payload containing "d3" somewhere before "admin.$cmd" — bounded now.
    add(
        "ICS_ATTACK",
        "claude_modbus_illegal_function_code_with_mongodb_injection",
        r"""(?i)37000000c168b9d3[0-9a-f]*61646d696e2e24636d64"""
        r"""|\bd3[0-9a-f]{0,64}admin\.\$cmd""",
    )

    add(
        "ICS_ATTACK",
        "claude_s7comm_cotp_connection_request",
        r"""0300[0-9a-fA-F]{4}0e[eE][0-9a-fA-F]{2}00000000000001000[0-9a-fA-F]{8}000000""",
    )

    add(
        "ICS_ATTACK",
        "claude_s7comm_cotp_connection_request_detection",
        r"""030000[0-9a-fA-F]{2}0e[eE][0-9a-fA-F]""",
    )

    add("MODBUS_RECON", "Modbus_Protocol_Anomaly_Detection", r"""^(0x05|0x06) [0-9a-fA-F]{8}$""")

    # Was `^[0-9A-Fa-f]{16}$` — any bare 16-hex string. The binary-protocol gate kept
    # it off HTTP, so the "half an MD5 in a cookie" case never occurred, but on an ICS
    # port it still fired on anything hex-shaped. Now requires the MBAP header shape:
    # transaction id (4), protocol id 0000, length (4), unit id (2), function code.
    add(
        "MODBUS_RECON",
        "Modbus_Scan_Detection",
        r"""(?i)^[0-9a-f]{4}0000[0-9a-f]{4}[0-9a-f]{2}[0-9a-f]{2}""",
    )

    add("MODBUS_RECON", "Modbus_Scan_Probe_Detection", r"""fea8[0-9a-f]{8}""")

    add(
        "MODBUS_RECON",
        "claude_modbus_broadcast_device_enumeration",
        r"""^[0-9a-fA-F]{4}0000[0-9a-fA-F]{4}002b0e01""",
    )

    # `^.{8}002b0e01` accepted any eight leading characters. Modbus/TCP requires the
    # protocol identifier to be 0000, which is what makes this Modbus rather than an
    # arbitrary string that happens to contain 002b0e01.
    add(
        "MODBUS_RECON",
        "claude_modbus_fc43_device_enumeration",
        r"""(?i)^[0-9a-f]{4}0000[0-9a-f]{0,4}002b0e01""",
    )
