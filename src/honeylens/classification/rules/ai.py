"""Text attack-detection rules — group: ai.

Auto-relocated from classification/text_rules.py (Phase 2 / T8). The rule
literals are verbatim; edit rules here, not in the façade.
"""

import re


def register(add):
    add(
        "AI_ATTACK",
        "prompt_ignore_previous",
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
        re.IGNORECASE,
    )

    add(
        "AI_ATTACK",
        "prompt_new_instructions",
        r"(new|your|the)\s+instructions?\s+(are|is|:)",
        re.IGNORECASE,
    )

    add(
        "AI_ATTACK",
        "prompt_disregard",
        r"disregard\s+(all|any|previous|prior)\s+(instructions?|rules?|guidelines?)",
        re.IGNORECASE,
    )

    add(
        "AI_ATTACK",
        "prompt_roleplay",
        r"(pretend|act|imagine|roleplay|you\s+are\s+now)\s+(you\s+are|to\s+be|as\s+if|as\s+a)",
        re.IGNORECASE,
    )

    add(
        "AI_ATTACK",
        "jailbreak_dan",
        r"(DAN|Do\s+Anything\s+Now|Developer\s+Mode|STAN|DUDE)\s*(mode|prompt|:)",
        re.IGNORECASE,
    )

    add(
        "AI_ATTACK",
        "jailbreak_opposite",
        r"(opposite\s+day|reverse\s+psychology|evil\s+mode|villain\s+mode)",
        re.IGNORECASE,
    )

    add(
        "AI_ATTACK",
        "jailbreak_bypass",
        r"(bypass|disable|ignore|override)\s+(your\s+)?(filter|safety|restriction|guardrail)",
        re.IGNORECASE,
    )

    add(
        "AI_ATTACK",
        "prompt_extraction_repeat",
        r"(repeat|print|show|reveal|display)\s+(your\s+)?(system|initial|original)\s+(prompt|instructions?)",
        re.IGNORECASE,
    )

    add(
        "AI_ATTACK",
        "prompt_extraction_verbatim",
        r"(verbatim|word\s+for\s+word|exact)\s+(system|initial)\s+(prompt|message)",
        re.IGNORECASE,
    )

    add("CREDENTIAL", "openai_api_key", r"sk-[a-zA-Z0-9]{48}")

    add("CREDENTIAL", "anthropic_api_key", r"sk-ant-[a-zA-Z0-9\-]{90,100}")

    add("CREDENTIAL", "huggingface_token", r"hf_[a-zA-Z0-9]{34}")

    # ---- Chat-template and tool-call injection (2026-08-26, August rule review) ----
    # Control tokens from the model's own chat template. A user turn that contains a
    # role delimiter is trying to forge a system message.
    add(
        "AI_ATTACK",
        "prompt_chat_template_delimiter",
        r"(?:<\|im_(?:start|end)\|>|<<\s*/?SYS\s*>>|\[/?INST\]" r"|<\|(?:start|end)_header_id\|>)",
        re.IGNORECASE,
    )

    # Context exfiltration through a rendered image: the client fetches the URL and the
    # stolen text rides in the query string.
    add(
        "AI_ATTACK",
        "prompt_markdown_data_exfil",
        r"!\[[^\]]*\]\(\s*https?://[^\)\s]+\?[^\)\s]*"
        r"(?:key|token|secret|exfil|leak|prompt|session|cookie|data)=",
        re.IGNORECASE,
    )

    # Angle-bracket tool-call tags injected into prose. Deliberately NOT matching the
    # JSON keys `"tool_calls":` / `"function_call":` the review also proposed — those
    # are the ordinary OpenAI wire format, which our own LLM decoy emits, and flagging
    # a normal protocol shape as an attack is the mistake the MQTT rule made.
    add(
        "AI_ATTACK",
        "prompt_tool_call_tag_injection",
        r"</?(?:tool_call|function_call|tool_use|invoke)\s*>",
        re.IGNORECASE,
    )

    # ---- Provider credentials seen in captured traffic ----
    add("CREDENTIAL", "google_ai_studio_key", r"AIzaSy[A-Za-z0-9_\-]{33}")

    # Real format is github_pat_<22>_<59>; the separating underscore is part of it, so
    # the review's [a-zA-Z0-9]{82} could never match a genuine token.
    add("CREDENTIAL", "github_fine_grained_pat", r"github_pat_[A-Za-z0-9_]{82}")

    add("CREDENTIAL", "slack_api_token", r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}")
