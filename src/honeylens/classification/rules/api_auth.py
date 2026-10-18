"""Text attack-detection rules — group: api_auth.

Auto-relocated from classification/text_rules.py (Phase 2 / T8). The rule
literals are verbatim; edit rules here, not in the façade.
"""

import re


def register(add):
    add(
        "CREDENTIAL",
        "cred_default_login",
        r"(admin|root|administrator|test|guest|user|oracle|"
        r"postgres|mysql|sa|ftp|anonymous):(admin|root|password|"
        r"123456|12345678|test|guest|default|pass|toor|changeme|"
        r"letmein|dragon|master|qwerty|abc123|monkey|shadow|"
        r"654321|111111|1234|passwd)",
    )

    add(
        "CREDENTIAL",
        "cred_auth_payload",
        r"(username|login|user|passwd|password|pass|pwd|secret|"
        r"credential|token|api_key|apikey)\s*[=:]\s*\S{3,}",
    )

    add("CREDENTIAL", "cred_basic_auth_header", r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}")

    add("GRAPHQL", "graphql_introspection_schema", r"__schema\s*\{", re.IGNORECASE)

    add("GRAPHQL", "graphql_introspection_type", r"__type\s*\(\s*name\s*:", re.IGNORECASE)

    add("GRAPHQL", "graphql_introspection_typename", r"__typename\b", re.IGNORECASE)

    add(
        "GRAPHQL",
        "graphql_introspection_full",
        r"query\s+IntrospectionQuery|introspectionQuery",
        re.IGNORECASE,
    )

    add("GRAPHQL", "graphql_batch_query", r"\[\s*\{\s*['\"]query['\"]\s*:", re.IGNORECASE)

    add(
        "GRAPHQL", "graphql_deep_nesting", r"(\{\s*\w+\s*\{){5,}", re.IGNORECASE
    )  # 5+ levels of nesting

    # 10+ aliases — counted, not expressed as a repeated group. The old pattern,
    # `(\w+\s*:\s*\w+\s*\{.*?){10,}`, was quadratic on a near-match (59.6 s for a 3.2 KB
    # payload) because the lazy `.*?` inside `{10,}` can be redistributed across the
    # repetitions. See `_CountingPattern` in text_rules.py.
    # The leading `\b` is not cosmetic. Without it the engine may start a match at every
    # position inside a long run of word characters, scan forward with `\w+`, fail on the
    # missing `:` and backtrack — quadratic again, 491 ms at 8 KB and over 30 s at 64 KB.
    # Anchored to a word boundary it is linear: 1.3 ms at 64 KB, 5.4 ms at 256 KB.
    add(
        "GRAPHQL",
        "graphql_alias_dos",
        r"\b\w+\s*:\s*\w+\s*\{",
        re.IGNORECASE,
        min_count=10,
    )

    add(
        "GRAPHQL",
        "graphql_directive_abuse",
        r"@(skip|include|deprecated)\s*\([^)]*\)\s*@",
        re.IGNORECASE,
    )

    add(
        "GRAPHQL",
        "graphql_sqli",
        r"(mutation|query)\s*\{.*?['\"].*?(union|select|insert|delete)\s",
        re.IGNORECASE,
    )

    add(
        "GRAPHQL",
        "graphql_nosql_injection",
        r"variables.*?\$\w+.*?(\$ne|\$gt|\$regex)",
        re.IGNORECASE,
    )

    add(
        "API_ABUSE", "jwt_none_algorithm", r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.$"
    )  # Empty signature

    add("API_ABUSE", "jwt_alg_none", r"['\"]alg['\"]\s*:\s*['\"]none['\"]", re.IGNORECASE)

    add(
        "API_ABUSE",
        "jwt_alg_confusion",
        r"['\"]alg['\"]\s*:\s*['\"]HS(256|384|512)['\"].*RS",
        re.IGNORECASE,
    )

    add(
        "API_ABUSE",
        "jwt_kid_injection",
        r"['\"]kid['\"]\s*:\s*['\"].*?(\.\.\/|;|\\x00|union|select)",
        re.IGNORECASE,
    )

    add(
        "API_ABUSE",
        "jwt_jku_injection",
        r"['\"]jku['\"]\s*:\s*['\"]https?://(?!.*(?:auth0|okta|cognito))",
        re.IGNORECASE,
    )

    add(
        "API_ABUSE",
        "rate_limit_bypass_xff",
        r"X-Forwarded-For:\s*127\.0\.0\.1|X-Forwarded-For:\s*localhost",
        re.IGNORECASE,
    )

    add(
        "API_ABUSE",
        "rate_limit_bypass_headers",
        r"(X-Real-IP|X-Originating-IP|X-Client-IP|True-Client-IP|CF-Connecting-IP)\s*:",
        re.IGNORECASE,
    )

    add(
        "API_ABUSE",
        "rate_limit_bypass_origin",
        r"X-Forwarded-Host:\s*\S+|X-Original-URL:\s*\S+",
        re.IGNORECASE,
    )

    add(
        "API_ABUSE",
        "idor_sequential_id",
        r"/api/v\d+/(users?|accounts?|orders?|profiles?|documents?)/\d{1,10}\b",
        re.IGNORECASE,
    )

    add(
        "API_ABUSE",
        "idor_uuid_enum",
        r"[?&](id|user_id|account_id|order_id)=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        re.IGNORECASE,
    )

    add(
        "API_ABUSE",
        "mass_assignment_admin",
        r"['\"]is_?admin['\"]\s*:\s*(true|1|['\"]true['\"])",
        re.IGNORECASE,
    )

    add(
        "API_ABUSE",
        "mass_assignment_role",
        r"['\"]role['\"]\s*:\s*['\"]?(admin|superuser|root)",
        re.IGNORECASE,
    )

    add(
        "API_ABUSE",
        "mass_assignment_privilege",
        r"['\"]privilege['\"]\s*:\s*['\"]?(elevated|admin|write)",
        re.IGNORECASE,
    )

    add("API_ABUSE", "http_param_pollution", r"[?&](\w+)=[^&]*&\1=", re.IGNORECASE)

    add(
        "API_ABUSE",
        "api_key_param",
        r"[?&](api_?key|access_?token|auth_?token|bearer)=\w{20,}",
        re.IGNORECASE,
    )

    add("AUTH_ATTACK", "credential_bulk_format", r"(user|email|login)\[\d+\]\s*=", re.IGNORECASE)

    add(
        "AUTH_ATTACK",
        "credential_combo_list",
        r"[a-zA-Z0-9._%+-]{3,}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}:[a-zA-Z0-9!@#$%^&*()_+=\-]{6,}",
    )

    add(
        "AUTH_ATTACK",
        "password_reset_host_injection",
        r"Host:\s*[^\r\n]+\.(evil|attacker|hacker)\.",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "password_reset_redirect",
        r"(redirect_uri|return_url|next)=https?://(?!localhost)",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "session_fixation_url",
        r"[?&;](JSESSIONID|PHPSESSID|ASP\.NET_SessionId|sid)=[a-zA-Z0-9]{16,}",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "session_cookie_inject",
        r"Set-Cookie:.*?(JSESSIONID|PHPSESSID|session)=[^;]+;.*?Path=/",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "oauth_redirect_bypass",
        r"redirect_uri=https?://[^/]*(@|%40|\\.|\.evil\.)",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "oauth_open_redirect",
        r"redirect_uri=https?://[^&]*[^a-zA-Z0-9](https?://|//)",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "oauth_state_missing",
        r"[?&]code=[a-zA-Z0-9_-]{20,}(?!.*[?&]state=)",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "2fa_bypass_null",
        r"(otp|code|token|2fa|mfa)\s*[=:]\s*(null|undefined|''|\"\"|\[\])",
        re.IGNORECASE,
    )

    add("AUTH_ATTACK", "2fa_bypass_array", r"(otp|code|token|2fa|mfa)\[\]\s*=", re.IGNORECASE)

    add(
        "AUTH_ATTACK",
        "2fa_bypass_type_juggling",
        r"(otp|code|token)\s*[=:]\s*(true|false|0|1)\b",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "http_basic_auth_default",
        r"Authorization:\s*Basic\s+(YWRtaW46YWRtaW4|YWRtaW46cGFzc3dvcmQ|YWRtaW46MTIzNDU2|cm9vdDpyb290|cm9vdDp0b29y|YWRtaW46YWRtaW4xMjM)",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "http_form_default_creds",
        r"(username|user|login|email)=(admin|root|administrator|guest|test|demo)&.*(password|passwd|pass|pwd)=(admin|password|123456|root|toor|default|guest|test|demo|admin123|pass123)",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "json_login_default_creds",
        r"['\"]?(username|user|login)['\"]?\s*:\s*['\"]?(admin|root|administrator)['\"]?\s*,\s*['\"]?(password|passwd|pass)['\"]?\s*:\s*['\"]?(admin|password|123456|root|default)['\"]?",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "ssh_default_creds",
        r"(ssh|scp|sftp)\s+.*(admin|root|pi|ubuntu|guest)@.*(:\s*|\s+-p\s*)(22|2222)\b",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "ftp_default_creds",
        r"(USER|PASS)\s+(admin|root|ftp|anonymous|guest|test)\r?\n",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "db_conn_default_creds",
        r"(mysql|postgres|mongodb|redis|oracle|mssql)://\s*(root|admin|sa|postgres|mongo):?(root|admin|password|123456|'')?@",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "router_default_creds",
        r"(router|gateway|modem|switch|firewall|ap|access.?point).*(admin|root|user).*(admin|password|1234|default)",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "vnc_weak_auth",
        r"VNC.*(password|auth)\s*[=:]\s*['\"]?(vnc|password|123456|admin)['\"]?",
        re.IGNORECASE,
    )

    add(
        "AUTH_ATTACK",
        "snmp_default_community",
        r"(community|snmp.?string)\s*[=:]\s*['\"]?(public|private|admin|default|cisco|secret)['\"]?",
        re.IGNORECASE,
    )

    add(
        "CREDENTIAL",
        "WebVPN_Login_Attempt",
        r"""/webvpn\/index\.html\?username=\w+&password=\w+&Login=Login""",
    )

    add(
        "CREDENTIAL",
        "claude_cisco_asa_webvpn_credential_attack",
        r"""POST\s+/\+webvpn\+/index\.html.*Login=Login.*password=.*username=""",
    )

    add(
        "CREDENTIAL",
        "claude_cisco_webvpn_credential_attack",
        r"""POST\s+/\+webvpn\+/index\.html.*username=[^&]+&password=[^&]+""",
    )

    add(
        "CREDENTIAL",
        "claude_credential_basic_auth_weak_patterns",
        r"""(?:Authorization|Proxy-Authorization):\s*Basic\s+([A-Za-z0-9+/=]+)""",
    )
