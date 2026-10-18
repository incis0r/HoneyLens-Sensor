#!/usr/bin/env python3
"""Guard for the text-rules registry split (Phase 2 / T8).

`classification/text_rules.py` was split so the individual `_add(...)` rule
definitions live in the per-family `classification/rules/` package behind a
registry, while `text_rules.py` stays a stable façade. These tests pin the
invariant: the fully-assembled rule set and the façade surface are unchanged.

The golden snapshot (`tests/data/text_rules_snapshot.json`) is the frozen
`(attack_type, name, pattern, flags)` multiset captured before the split. The
matcher in `attack_classifier.py` collects *all* hits (no first-match break),
so rule ordering is irrelevant — identity is the sorted multiset.
"""

import json
import pathlib

from honeylens.classification import text_rules as t

_SNAPSHOT = pathlib.Path(__file__).with_name("data") / "text_rules_snapshot.json"


def _current():
    return sorted([a, n, rx.pattern, rx.flags] for a, n, rx in t._RULES)


def test_rule_set_matches_golden_snapshot():
    """Every rule (type, name, pattern, compiled flags) is preserved exactly."""
    golden = json.loads(_SNAPSHOT.read_text())
    current = _current()
    assert current == golden, (
        f"rule set drifted from the golden snapshot "
        f"(golden={len(golden)} current={len(current)}). "
        "If this change is intentional, regenerate "
        "tests/data/text_rules_snapshot.json."
    )


def test_rule_count_and_names():
    # 715 since 2026-11-05: +1 smtp_auth_offer (SMTP_PROBE, info). `mqtt_command_injection`'s
    # pattern changed in the same pass — it matched any JSON object with a `command` key, which
    # is the shape our own command-protocol decoys write, and filed 261,531 rows as IOT_ATTACK
    # including `QUIT` and `RSET`. Removing that label would have left the 63,730 `AUTH LOGIN`
    # rows unnamed. See tests/test_verdict_naming_smtp_and_smb.py.
    #
    # 714 since 2026-11-05: +14 from B4d, the indicators the IOC sheets recommended and nothing
    # implemented — the Outlaw/dota3 dropper and its XMRig pool and wallet, Spring4Shell's
    # classLoader primitive, a webshell being WRITTEN (not probed), a code-execution API, MCP
    # transport and handshake discovery, the Citrix traversal family, tRPC and better-auth
    # routes, `X-Custom-IP-Authorization`, self-contradicting CDN provenance, and the PHP2Shell
    # `t[]` repetition spray. See tests/test_carried_indicator_bundle.py.
    #
    # 700 since 2026-11-05: +1 phpunit_eval_stdin_probe (RECON). It exists because fixing
    # `redis_dangerous_cmd` — whose case-insensitive `EVAL` matched the word in
    # `eval-stdin.php` and filed 57 of 4,000 sampled rows on sensor-b as a Redis attack — left the
    # CVE-2017-9841 probe with no verdict at all. Two more patterns changed in the same pass:
    # `rate_limit_bypass_headers` and `rate_limit_bypass_origin` now test the CLAIMED VALUE
    # instead of the presence of a header our own edge sets. See
    # tests/test_proxy_header_claims.py.
    #
    # 699 since 2026-11-05: +4 implant check-in in a new `rules/implant.py` —
    # webshell_checkin_known_path and webshell_checkin_hex_path_shell_body (WEBSHELL_CHECKIN),
    # webshell_hex_key_header (WEBSHELL_KEY) and shell_host_profiling_chain (HOST_PROFILING).
    # The `/k7f3a9` beacon carried a bare `RCE` on every row: right in class, silent about the
    # three-hourly check-in it was. A new subject file because getting in and polling something
    # you already own are different acts. See tests/test_webshell_checkin_beacon.py and
    # the internal beacon IOC notes.
    #
    # 695 since 2026-11-05: +2 AndroxGh0st in `rules/scanners.py` — androxgh0st_probe_body
    # (ANDROXGH0ST, the twenty-byte constant) and androxgh0st_named_token (RECON, the name
    # anywhere, a weaker claim). 1,402 rows over 30 days across four sensors, every one with
    # an empty attack_types. See tests/test_androxgh0st_verdict.py and
    # the internal AndroxGh0st IOC notes.
    #
    # 693 since 2026-11-05: +6 React2Shell / Node execution in `rules/web_injection.py` —
    # react_server_action_header (REACT_SERVER_ACTION, the kit's footprint),
    # react2shell_proto_pollution and react2shell_eval_oracle_arith (CVE_2025_55182),
    # node_child_process_require and node_sync_command_exec (RCE) and
    # node_reverse_shell_connect (C2). Measured over 14 days: 313 decoy bodies carried the
    # pollution key and not one was labelled, including the 2026-11-03 reverse shell to
    # 91.92.40.12:12323 — see tests/test_react2shell_classification.py and
    # the internal REACT2SHELL IOC notes. The same change made header rules reachable on
    # a decoy row at all, which is why node2shell_brotli_request_body's pattern moved.
    #
    # 687 since 2026-11-05: +6 WordPress in a new `rules/cms.py` — wordpress_content_enum,
    # wordpress_plugin_probe, wordpress_admin_probe (WORDPRESS_RECON) and
    # wordpress_login_attempt, wordpress_xmlrpc_multicall, wordpress_config_exposure
    # (WORDPRESS_CRED). There was no WordPress verdict in this registry at all: scanners.py
    # lists wp-admin|wp-login|wp-config|xmlrpc.php inside the generic scan_vuln_paths pattern
    # and never mentions wp-json or wp-content, so the REST API and every plugin path matched
    # nothing. Measured unlabelled WordPress-shaped requests: sensor-b 3,690 of 6,305 (58%),
    # sensor-a 4,739 of 13,513 (35%), sensor-c 917 of 2,159 (42%), sensor-e 56 of 117 (48%).
    # A new subject file because this is a product, not a scanner fingerprint or an
    # injection. See tests/test_wordpress_verdicts.py.
    #
    # 681 since 2026-11-04: +2 Kubernetes Secrets by breadth —
    # k8s_secrets_cluster_wide (`/api/v1/secrets`, critical) and k8s_secrets_namespace_list
    # (`/api/v1/namespaces/<ns>/secrets`, high). Measured: 84 cluster-wide requests on sensor-a
    # and 107 on sensor-b, every one labelled and not one of those labels saying "secrets" —
    # k8s_secret_read needs `/secrets/` with a trailing slash, so it only matched a single
    # named secret. Not port-gated, because 45% of the rows arrived on ports where
    # `_detect_k8s_attack` returns early. See tests/test_k8s_secrets_verdicts.py.
    #
    # 679 since 2026-11-04: -1 k8s_etcd_keys, moved out of this registry and into
    # `binary_detectors._detect_k8s_attack`. Here it was an ungated regex
    # (`/v2/keys/registry|/v3/kv/range`) and so put an etcd verdict on any port at all —
    # measured firing for `/v3/kv/range` on :9999. Every etcd rule now sits in one block
    # gated on :2379/:2380, and the rule keeps only the registry prefix, because
    # `k8s_etcd_kv_read` covers a plain range. See tests/test_etcd_verdicts.py.
    #
    # 680 since 2026-11-01: +1 node2shell_brotli_request_body -> NODE2SHELL, the request-body
    # `Content-Encoding: br` that CVE-2026-111497 needs (Express 5 + body-parser 2 inflate it by
    # default). Paired with the hp_express decoy: without a Node surface the fleet's zero was a
    # statement about our bait, not the traffic. The attack_type is NOT the CVE -- a compressed
    # body is the precondition, not evidence the decoder went out of bounds. Measured
    # false-positive rate over the whole retention window: zero rows fleet-wide carry a
    # Brotli-encoded body, against 18,300/15,600/2,122 rows on sensor-a/sensor-b/sensor-c that merely
    # declare `Accept-Encoding: ...br`.
    #
    # 679 since 2026-10-30: +1 php2shell_upload_progress_exhaustion -> CVE_2026_109618. The
    # identifier had lived in this codebase only inside comments, so the half of the pair that
    # does not execute code had no verdict and could not be hunted: on sensor-a, 85.11.167.243's
    # 62,929-byte padded body (user-agent `php2shell-109618`) and 94.154.43.7's ten bodies with
    # a 240-deep nested array field were all stored as a bare PHP2SHELL.
    #
    # 678 since 2026-10-26: +3 PHP2Shell, the session.upload_progress pair
    # CVE-2026-109618/109619 (php2shell_upload_progress_rce -> CVE_2026_109619;
    # php2shell_upload_progress_field and php2shell_tool_user_agent -> PHP2SHELL).
    # Measured cause: of 94 rows carrying this vector on the fleet, 14 were named for it and
    # all 14 came from Suricata on one sensor; 20 were labelled NGINX_CVE_2026_42533 by the
    # nginx decoy's own >16 KB overflow indicator, 13 as bare RCE,PHP and 35 as nothing.
    # Detection existed per-host and in no shared place. See
    # tests/test_php2shell_classification.py and the 26 Oct PHP2Shell review §4.
    #
    # 675 since 2026-10-04: +1 Citrix NetScaler CVE-2026-88771 pre-auth command injection
    # (citrix_cve_2026_88771_pitboss_cmdi, APPLIANCE_EXPLOIT) — the watchTowr PoC's
    # pitboss/NSPPE log-poisoning IOC, given to the central classifier. See
    # tests/test_cisco_webvpn_classification.py.
    #
    # 674 since 2026-09-07: the 670 below plus the Cisco SSL-VPN *GET* surface —
    # cisco_webvpn_portal_probe, cisco_anyconnect_oem_customization (VPN_RECON),
    # cisco_cve_2020_3452_file_read (APPLIANCE_EXPLOIT) and
    # cisco_webvpn_credentials_in_query (CREDENTIAL). The earlier AnyConnect rules
    # all keyed on a POSTed body, so `GET /+CSCOE+/logon.html` matched nothing and was
    # being filed as AI_DETECTED, PANOS_PROBE or FORTI_PROBE depending on which decoy
    # answered. See tests/test_cisco_webvpn_classification.py.
    #
    # 670 since 2026-08-27: +3 Cisco AnyConnect (VPN_RECON), then +12 from the August
    # rule review — Ivanti x2, PAN-OS CVE-2024-3400, Spring x2, fastjson, and six
    # LLM/provider-credential rules. See tests/test_new_signatures_aug_review.py.
    assert len(t._RULES) == 715
    names = [n for _, n, _ in t._RULES]
    # 715 rules, 713 distinct names (two MQTT names intentionally repeat)
    assert len(set(names)) == 713


def test_facade_surface_intact():
    """text_rules.py must keep exporting the symbols its consumers import."""
    for name, expected_len in [
        ("_ICS_PORTS", 15),
        ("_HTTP_PORTS", 15),
        ("_K8S_PORTS", 10),
        ("_ICS_PORT_CONTEXT_RULES", 18),
        ("_HTTP_EXCLUDED_RULES", 93),
        ("_BINARY_PROTOCOLS", 45),
        ("_PLAINTEXT_PROTOCOLS", 15),
        ("_ENCRYPTED_PROTOCOLS", 14),
    ]:
        obj = getattr(t, name)
        assert len(obj) == expected_len, f"{name} changed size"
    assert isinstance(t._CUSTOM_RULE_NAMES, set)
    for fn in ("reload_custom_rules", "get_custom_rule_names", "is_custom_rule"):
        assert callable(getattr(t, fn)), f"{fn} missing"


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])
