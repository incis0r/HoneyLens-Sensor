"""Text attack-detection rules — group: serialization.

Auto-relocated from classification/text_rules.py (Phase 2 / T8). The rule
literals are verbatim; edit rules here, not in the façade.
"""

import re


def register(add):
    add("DESERIALIZE", "java_serialized_magic", r"\xac\xed\x00\x05", re.DOTALL)

    add("DESERIALIZE", "java_serialized_base64", r"\brO0AB[A-Za-z0-9+/]{8,}")

    add(
        "DESERIALIZE",
        "java_ysoserial_gadgets",
        r"(CommonsCollections[1-7]|Spring[12]|Hibernate[12]|JRMPClient|Groovy1)",
        re.IGNORECASE,
    )

    add(
        "DESERIALIZE",
        "java_rmi_exploit",
        r"(java\.rmi|javax\.management\.remote|com\.sun\.jndi)",
        re.IGNORECASE,
    )

    add("DESERIALIZE", "php_phar_wrapper", r"phar://", re.IGNORECASE)

    add(
        "DESERIALIZE",
        "php_object_injection",
        r"O:\d+:\"[A-Za-z_\\]+\":\d+:\{.*?s:\d+:\"",
        re.IGNORECASE,
    )

    add(
        "DESERIALIZE",
        "php_serialized_array",
        r"a:\d+:\{.*?s:\d+:\"(cmd|exec|system|eval)",
        re.IGNORECASE,
    )

    add(
        "DESERIALIZE",
        "dotnet_viewstate_gadget",
        r"__VIEWSTATE=.*?(TypeConfuseDelegate|TextFormattingRunProperties|DataSet)",
        re.IGNORECASE,
    )

    add(
        "DESERIALIZE",
        "dotnet_formatters",
        r"(BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer)",
        re.IGNORECASE,
    )

    add("DESERIALIZE", "dotnet_xaml_payload", r"<ObjectDataProvider.*MethodName", re.IGNORECASE)

    add(
        "DESERIALIZE",
        "dotnet_axhost_state_gadget",
        r"System\.Windows\.Forms\.AxHost\.State",
        re.IGNORECASE,
    )

    add(
        "DESERIALIZE",
        "python_pickle_reduce",
        r"(__reduce__|__reduce_ex__|__setstate__)\s*\(",
        re.IGNORECASE,
    )

    add(
        "DESERIALIZE",
        "python_pickle_import",
        r"c(os|subprocess|builtins)\n(system|popen|eval)",
        re.IGNORECASE,
    )

    add("DESERIALIZE", "python_pkl_proto_marker", r"\x80[\x02-\x05]\x95", re.DOTALL)

    add("DESERIALIZE", "yaml_python_object", r"!!python/(object|module|name|apply)", re.IGNORECASE)

    add("DESERIALIZE", "yaml_ruby_object", r"!!ruby/(object|struct|hash)", re.IGNORECASE)

    add("DESERIALIZE", "yaml_unsafe_load", r"yaml\.(unsafe_)?load\s*\(", re.IGNORECASE)

    add(
        "PROTO_ABUSE",
        "mqtt_sys_topics",
        r"\$SYS/(broker|clients|messages|bytes|load|subscriptions)",
    )

    add("PROTO_ABUSE", "ssh_exploit_banner", r"SSH-.*?(libssh|putty_release|dropbear.*?corrupt)")

    add("PROTO_ABUSE", "ftp_site_exec", r"SITE\s+(EXEC|CPFR|CPTO|CHMOD)\b", re.IGNORECASE)

    add(
        "PROTO_ABUSE",
        "redis_dangerous_cmd",
        r"\b(CONFIG\s+SET|SLAVEOF|REPLICAOF|MODULE\s+LOAD|DEBUG\s+SET|"
        r"FLUSHALL|FLUSHDB|SCRIPT\s+LOAD|EVAL)\b",
        re.IGNORECASE,
    )

    add(
        "SQLI", "mysql_load_file", r"(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\s*\(", re.IGNORECASE
    )

    add("PROTO_ABUSE", "dns_zone_transfer", r"(AXFR|IXFR)\b")

    add("PROTO_ABUSE", "telnet_shell_escape", r"(\x1b\[|\x1b\x5b).*?(sh|bash|\/bin\/)")

    add("PROTO_ABUSE", "SUSPICIOUS_TLS1_0_NON_STANDARD_PAYLOAD", r"""^[\xef\xbf\xbd]+$""")

    # ---- Spring / fastjson (added 2026-08-26 from the August rule review) -----
    # CVE-2022-22965 "Spring4Shell": DataBinder walks to the class loader through a
    # nested property path. `class.module.classLoader` is the canonical tell.
    add("RCE", "spring4shell_classloader_binding", r"class\.module\.classLoader\.", re.IGNORECASE)

    # CVE-2022-22963: SpEL injection through the routing-expression header.
    add(
        "RCE",
        "spring_cloud_function_spel_rce",
        r"spring\.cloud\.function\.routing-expression\s*[:=]",
        re.IGNORECASE,
    )

    # Polymorphic deserialisation. `@type` on its own is ordinary in several
    # serialisers, so the gadget class is what makes this an attack.
    add(
        "DESERIALIZE",
        "fastjson_autotype_rce",
        r"""['\"]@type['\"]\s*:\s*['\"](?:com\.sun\.rowset\.JdbcRowSetImpl"""
        r"""|org\.apache\.xbean|com\.mchange\.v2\.c3p0|org\.springframework"""
        r"""|com\.alibaba\.fastjson|java\.net\.Inet[46]?Address)""",
        re.IGNORECASE,
    )
