"""Text attack-detection rules — group: database.

Auto-relocated from classification/text_rules.py (Phase 2 / T8). The rule
literals are verbatim; edit rules here, not in the façade.
"""

import re


def register(add):
    add(
        "REDIS_HEAP_CORRUPT",
        "redis_restore_stream_nack",
        r"\bRESTORE\b.*\bXGROUP\b.*\bDELCONSUMER\b",
        re.IGNORECASE | re.DOTALL,
    )

    add("REDIS_TOPK_WILDFREE", "redis_topk_cmd", r"\bTOPK\.(RESERVE|ADD|INCRBY|QUERY)\b")

    add("REDIS_TDIGEST_OVERFLOW", "redis_tdigest_cmd", r"\bTDIGEST\.(CREATE|ADD|MERGE)\b")

    add("ORACLE_TNS", "tns_version_enum", r"CONNECT_DATA=.*?COMMAND\s*=\s*VERSION", re.IGNORECASE)

    add("ORACLE_TNS", "tns_status_enum", r"CONNECT_DATA=.*?COMMAND\s*=\s*STATUS", re.IGNORECASE)

    add("ORACLE_TNS", "tns_services_enum", r"CONNECT_DATA=.*?COMMAND\s*=\s*SERVICES", re.IGNORECASE)

    add("ORACLE_TNS", "tns_listener_stop", r"CONNECT_DATA=.*?COMMAND\s*=\s*STOP", re.IGNORECASE)

    add("ORACLE_TNS", "tns_listener_reload", r"CONNECT_DATA=.*?COMMAND\s*=\s*RELOAD", re.IGNORECASE)

    add(
        "ORACLE_TNS",
        "tns_listener_save_config",
        r"CONNECT_DATA=.*?COMMAND\s*=\s*SAVE_CONFIG",
        re.IGNORECASE,
    )

    add("ORACLE_TNS", "tns_sid_enum", r"CONNECT_DATA=.*?SID\s*=\s*\w+", re.IGNORECASE)

    add(
        "ORACLE_TNS",
        "tns_service_name_enum",
        r"CONNECT_DATA=.*?SERVICE_NAME\s*=\s*\w+",
        re.IGNORECASE,
    )

    add(
        "ORACLE_TNS",
        "tns_default_sid",
        r"(SID|SERVICE_NAME)\s*=\s*(ORCL|XE|XEXDB|PLSExtProc|PROD|DEV|TEST|DB11G|DB12C|ORACLE|ORCLCDB|ORCLPDB1)\b",
        re.IGNORECASE,
    )

    add(
        "ORACLE_TNS",
        "oracle_default_creds",
        # Oracle default user/password pairs (SQL*Plus / TNS connect strings). The username
        # must NOT be a URL path segment — the `/` separator collided with request paths like
        # `/api/v2/cmdb/system/admin`, which matched "system/admin" and tagged HTTP as Oracle.
        # The negative lookbehind rejects a username preceded by `/`, a word char, or `.`.
        r"(?<![/\w.])(sys|system|scott|dbsnmp|sysman|outln|dip|oracle_ocm|appqossys|wmsys|exfsys|ctxsys|xdb|anonymous|hr|oe|pm|ix|sh|bi)/(change_on_install|manager|tiger|dbsnmp|sysman|oracle|welcome1?|password|admin)\b",
        re.IGNORECASE,
    )

    add("ORACLE_TNS", "tns_scanner_odat", r"\b(odat|ODAT|odat-libc)\b", re.IGNORECASE)

    add("ORACLE_TNS", "tns_scanner_tnscmd", r"tnscmd(10g)?", re.IGNORECASE)

    add("ORACLE_TNS", "tns_scanner_oscanner", r"\boscanner\b", re.IGNORECASE)

    add(
        "ORACLE_TNS",
        "tns_scanner_nmap",
        r"oracle-tns-version|oracle-sid-brute|oracle-brute|oracle-enum-users",
        re.IGNORECASE,
    )

    add(
        "ORACLE_TNS",
        "tns_poison_register",
        r"CONNECT_DATA=.*?(REGISTER|SERVICE_REGISTER)",
        re.IGNORECASE,
    )

    add("ORACLE_TNS", "oracle_sysdba_attempt", r"as\s+(sysdba|sysoper)\b", re.IGNORECASE)

    add(
        "ORACLE_TNS",
        "oracle_priv_escalation",
        r"GRANT\s+(DBA|ALL\s+PRIVILEGES)\s+TO\b",
        re.IGNORECASE,
    )

    add("ORACLE_TNS", "oracle_create_user", r"CREATE\s+USER\s+\w+\s+IDENTIFIED\s+BY", re.IGNORECASE)

    add(
        "ORACLE_TNS",
        "oracle_java_exec",
        r"DBMS_JAVA\.RUNJAVA|DBMS_JAVA_TEST\.FUNCALL",
        re.IGNORECASE,
    )

    add(
        "ORACLE_TNS",
        "oracle_scheduler_exec",
        r"DBMS_SCHEDULER\.(CREATE_JOB|CREATE_PROGRAM|RUN_JOB)",
        re.IGNORECASE,
    )

    add(
        "ORACLE_TNS",
        "oracle_file_access",
        r"(UTL_FILE\.(FOPEN|PUT_LINE|GET_LINE|FCOPY)|DBMS_LOB\.(LOADFROMFILE|LOADBLOBFROMFILE))",
        re.IGNORECASE,
    )

    add(
        "ORACLE_TNS",
        "oracle_network_access",
        r"(UTL_HTTP\.REQUEST|UTL_TCP\.OPEN_CONNECTION|UTL_INADDR\.GET_HOST|UTL_SMTP\.OPEN_CONNECTION|HTTPURITYPE)",
        re.IGNORECASE,
    )

    add("ORACLE_TNS", "oracle_extproc_exploit", r"(extproc|EXTPROC|ExtProc)", re.IGNORECASE)

    add(
        "ORACLE_TNS",
        "oracle_hash_extract",
        r"(SYS\.USER\$|DBA_USERS).*?(PASSWORD|SPARE4)",
        re.IGNORECASE,
    )

    add(
        "ORACLE_TNS",
        "lsnrctl_command",
        r"lsnrctl\s+(status|version|services|start|stop|reload|save_config)",
        re.IGNORECASE,
    )

    add(
        "ORACLE_SCAN",
        "claude_oracle_database_reconnaissance",
        r"""oracle.*1521|port.*1521.*oracle""",
    )

    add("ORACLE_SCAN", "claude_oracle_tns_zgrab2_scan", r"""PROGRAM=zgrab2""")
