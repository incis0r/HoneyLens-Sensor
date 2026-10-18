"""Text attack-detection rules — group: implant.

What an operator sends to something they believe they already own: a webshell check-in, the key
that authenticates it, and the commands it runs to inventory the host. Separate from
`web_injection` on purpose — those rules are about getting in, these are about what comes after,
and the dashboard reads them as different acts.
"""

import re


def register(add):
    # --- `/k7f3a9` + `X-K` webshell check-in beacon -----------------------------------------
    #
    # The internal beacon IOC notes. Since 2026-11-01 one sender has sent a single
    # `POST /k7f3a9` every three hours on the hour, to a path that exists in no product,
    # carrying a constant 28-hex key in an `X-K` header and a four-command body -- `id; nproc;
    # hostname; uname -m`: identity, core count, name, architecture. Those are the questions a
    # mining or proxy operator asks, not a data thief. Every row of it carried `RCE`: correct in
    # class, because the body is a shell command list, and silent about everything that matters.
    #
    # The 4 Oct-4 Nov fleet review §5.1 then found it is half of a fixed eight-second sequence
    # on the same cycle -- `POST /v3/kv/put` into the etcd decoy one second earlier, then the
    # beacon to two decoys. Find compute, then persist. The etcd half is named by B2's
    # `k8s_etcd_kv_write`; this is the other half.
    #
    # The path alone, because no product uses it and the operator asking for it at all is the
    # finding -- method and body do not matter.
    add("WEBSHELL_CHECKIN", "webshell_checkin_known_path", r"/k7f3a9\b", re.IGNORECASE)

    # The family rather than the one path: the next key will be a different six characters, and
    # the one thing the operator cannot change is that it is asking a shell to report back. Both
    # halves are required because a short hex path on its own is an ordinary URL shape -- commit
    # hashes, short links, cache keys -- and a shell body on an ordinary path is host profiling,
    # which is named on its own below.
    #
    # Anchored at `^POST`, so it starts at one position per target and the lazy span is bounded:
    # the decoy's payload is `METHOD path body_len=N` followed by the captured body, and a
    # capture row is the request line followed by headers and body, so one pattern reads the
    # method, the path and the body out of either shape.
    add(
        "WEBSHELL_CHECKIN",
        "webshell_checkin_hex_path_shell_body",
        r"^POST\s+/[0-9a-f]{5,8}(?=[\s?])[\s\S]{0,2048}?"
        r"\b(?:id|whoami|nproc|hostname|uname|uptime|curl|wget)\s*;",
        re.IGNORECASE,
    )

    # §4.2: a single-letter-plus-dash header carrying 28 hex characters is a shell key, not a
    # cache hint. The key is the OPERATOR's -- constant across every sensor and all 72 hours --
    # which makes it the one indicator here that is not the victim's. Both header dialects,
    # because a decoy stores `metadata["headers"]` as a dict and a capture row stores wire form.
    #
    # 16 hex characters is the floor: a one-letter header with four hex digits could be
    # anything, and `X-Request-Id` and friends are excluded by the single-letter name.
    add(
        "WEBSHELL_KEY",
        "webshell_hex_key_header",
        r'(?:"x-[a-z]"\s*:\s*"|\bx-[a-z]:[ \t]*)[0-9a-f]{16,64}(?![0-9a-z])',
        re.IGNORECASE,
    )

    # §4.3, generalised past this operator's four commands. The tell is commands CHAINED -- a
    # single `id` in a body is a word, two host-identity commands separated by `;` is a script
    # someone expects to be executed. Medium: it says what the implant asked for, not that it
    # got an answer; our decoys return a static page and never answer it.
    add(
        "HOST_PROFILING",
        "shell_host_profiling_chain",
        r"\b(?:id|whoami|nproc|hostname|uname|uptime|lscpu|free)\b[^\n;]{0,40};\s*"
        r"(?:id|whoami|nproc|hostname|uname|uptime|lscpu|free)\b",
        re.IGNORECASE,
    )

    # --- dota3 / Outlaw XMRig dropper (`badmonner.s.gy`) ------------------------------------
    #
    # The internal dota3 dropper IOC notes: one payload delivered through several frameworks --
    # fetch `dota-download`, unpack it to `~/.configrc6`, run `initall`, and on Windows run
    # `xmrig.exe` against a named pool with a named wallet. §6.1 lists the tokens and says none
    # has a benign form.
    #
    # Two rules, not one, because the delivery chain and the payment identifier are different
    # claims about the same request. The sheet writes the verdict as `MALWARE_DROPPER,
    # CRYPTOMINER`; those types do not exist and `MALWARE` and `CRYPTOMINING` do, already at
    # high, so the verdict uses the vocabulary the dashboard already groups by.
    add(
        "MALWARE",
        "outlaw_dota3_dropper",
        r"badmonner\.s\.gy|dota-?download|dota3\.tar\.gz|\.configrc6|\$D/initall",
        re.IGNORECASE,
    )

    # The pool and the wallet. The wallet is the one indicator that survives the operator
    # changing download hosts, which is why the sheet calls it the payment identifier.
    add(
        "CRYPTOMINING",
        "xmrig_pool_or_wallet",
        r"auto\.c3pool\.org|xmrig(?:\.exe)?\b|--randomx-mode"
        r"|87FjG9Yn2MASj6JQ3KyL1MQGdTijxsBCBWLAb4pfBx9gi1MTgnwiGGJ6jc6jKHgk78b8h6rXK6M4k4L8Wv4veL1oNmL5sDZ",
        re.IGNORECASE,
    )

    # §6.2, Spring4Shell. `class.module.classLoader.` is the write primitive: it walks from a
    # bound request parameter to Tomcat's access-log valve and makes it write a JSP.
    #
    # The verdict is `RCE`, not `CVE_2022_22965`. A CVE label needs the affected service bound
    # to the request -- that is what Phase A was about -- and nothing in a form body says Spring
    # is behind it. The sheet also asks to drop the `PHP` co-label these bodies pick up; that
    # needs a suppression mechanism the registry does not have, and the `RCE` row outranks it.
    add(
        "RCE",
        "spring4shell_class_loader",
        r"class\.module\.classLoader\.",
        re.IGNORECASE,
    )

    # §6.3: a webshell being WRITTEN is a different event from one being probed -- the
    # distinction the `sp-webshell-aspx` verdict got wrong. Both halves are required: a PUT or
    # POST to a script path, and code in the body. Anchored at `^` so the request line is read
    # once per target, with a bounded lazy span to the body.
    add(
        "WEBSHELL_UPLOAD",
        "webshell_upload_to_script_path",
        r"^(?:PUT|POST)\s+\S+\.(?:jspx?|aspx?|php\d?|phtml)(?=[\s?])[\s\S]{0,2048}?"
        r"(?:Runtime\.getRuntime\(\)\.exec|<\?php|<%@?\s*page|eval\s*\(\s*request)",
        re.IGNORECASE,
    )

    # §6.4: a `{"code": ...}` body on a `/run` or `*/exec/*` path is an exposed code-execution
    # API. `SUPPLY_CHAIN` was carrying this, and that verdict is for dependency abuse.
    add(
        "CODE_EXEC_API",
        "code_exec_api_json_body",
        r"^(?:PUT|POST)\s+\S*(?:/run|/exec/|/eval)(?=[\s?/])[\s\S]{0,2048}?"
        r'"code"\s*:\s*["\[{]',
        re.IGNORECASE,
    )

    # --- MCP transport discovery ------------------------------------------------------------
    #
    # Review §3.8: `/mcp` (182) with `/sse` (182) on honeypotng :8001, stored `(none)`. An
    # exposed Model Context Protocol server is a free inference endpoint -- the same demand for
    # compute as the Ollama `/api/generate` sweeps -- so it takes the verdict that already means
    # that rather than a new one.
    #
    # `/sse` deliberately gets no rule: server-sent events are an ordinary transport, and one
    # request for `/sse` says nothing. The equal rates are a correlation across requests, which
    # a per-request rule cannot see.
    add(
        "AI_ENDPOINT_PROBE",
        "mcp_endpoint_probe",
        r"(?:^|/)(?:api/)?mcp/?(?=[\s?]|$)",
        re.IGNORECASE,
    )

    # MCP's own handshake: a dated protocol version inside a JSON-RPC `initialize`. Observed
    # from Azure addresses as `protocolVersion 2025-03-26` (the internal NetScaler IOC
    # notes), in the same /24 as the PHP2Shell census probe -- one operator, two checkers.
    add(
        "AI_ENDPOINT_PROBE",
        "mcp_initialize_handshake",
        r'"protocolVersion"\s*:\s*"20\d\d-\d\d-\d\d"',
        re.IGNORECASE,
    )
