"""Six shapes the registry still misses, measured 2026-11-19 across the fleet.

Found while diagnosing why `sensor-e`'s SharePoint decoy had 99.4% of its rows unlabelled. Two of
the paths on that list turned out to be covered already and only *looked* uncovered because
`sensor-e` was importing stale bytes (`/containers/json` -> CLOUD_ATTACK since 2026-11-08,
`/+CSCOE+/logon.html` -> VPN_RECON); they are pinned at the bottom so the next reader does not
re-chase them. The six below were then re-measured on all eight sensors, excluding our own
validation sources and RFC1918:

    shape                        rows   srcs   unlabelled
    /database|backup|dump.sql    1,070    119        880
    docker-compose.y(a)ml          764    207        615
    /secrets.json                  451    163        387
    /application.y(a)ml            273     82        226
    /.circleci/config.y(a)ml       121     67         99
    /global-protect/login.esp       84     61         60
                                 -----              -----
                                 2,763              2,267  (82%)

`sensor-d` has none of them, which is a fact about exposure, not about rules.

Verdict choices, each against the precedent beside it:

`application.yml` is the same file as `application.properties`, which `lfi_sensitive_config`
has covered since the registry was written -- one serialisation apart. The rest of the config
group discloses the deployment's configuration the way `Dockerrun.aws.json` does (image
references, service topology, and in practice the credentials wired into them), so they share
`SENSITIVE_FILE` rather than taking a new verdict. `secrets.json` is named for its contents.

A `.sql` dump at the web root is the data, not a key or a config -- but it is the asset `.env`
is a step toward, so grading it below `.env` would be backwards.

`/global-protect/login.esp` is the GlobalProtect portal, the PAN-OS twin of Cisco's
`/+CSCOE+/logon.html`. That Cisco rule is deliberately generic, so a scanner mapping an ASA
earns `VPN_RECON` on every sensor. GlobalProtect earned it on exactly one: `sensor-f`, from the
PAN-OS decoy's own `PANOS_*` verdict, which is decoy-scoped by design. 60 of 84 rows on the
other seven sensors had nothing. Closing the asymmetry, not adding a family.

These are bare GETs for a file from scanner ranges. None of them is an exploit and none gets a
verdict that claims one -- the correction `sp-webshell-aspx` earned for claiming too much.
"""

from __future__ import annotations

from honeylens.classification.scoring import get_severity

from .test_credential_and_framework_gaps import body_post, by_path, rules, summary


class TestConfigAndSecretHarvest:
    def test_secrets_json(self) -> None:
        """451 rows, 163 sources, 387 unlabelled."""
        assert "SENSITIVE_FILE" in by_path("/secrets.json")

    def test_compose_file_in_both_spellings(self) -> None:
        """764 rows, the largest of the config shapes."""
        for path in ("/docker-compose.yml", "/docker-compose.yaml"):
            assert "SENSITIVE_FILE" in by_path(path), path

    def test_the_environment_suffixed_compose_files(self) -> None:
        """`docker-compose.prod.yml` is where the production values actually live."""
        for path in ("/docker-compose.prod.yml", "/docker-compose.override.yaml"):
            assert "SENSITIVE_FILE" in by_path(path), path

    def test_spring_application_yaml(self) -> None:
        """The same file `application.properties` already covers, one serialisation apart."""
        for path in ("/application.yml", "/application.yaml"):
            assert "SENSITIVE_FILE" in by_path(path), path

    def test_circleci_config(self) -> None:
        """121 rows. Carries deploy keys and the registry it pushes to."""
        for path in ("/.circleci/config.yml", "/.circleci/config.yaml"):
            assert "SENSITIVE_FILE" in by_path(path), path

    def test_a_database_dump_at_the_web_root(self) -> None:
        """1,070 rows, the largest single shape on the list."""
        for path in ("/database.sql", "/backup.sql", "/dump.sql", "/db.sql"):
            assert "SENSITIVE_FILE" in by_path(path), path

    def test_the_compressed_dump_too(self) -> None:
        """A dump is served compressed as often as not."""
        assert "SENSITIVE_FILE" in by_path("/backup.sql.gz")

    def test_the_path_alone_is_enough(self) -> None:
        """On the sharepoint and netscaler decoys a request with a body replaces the payload
        summary line, so the path exists ONLY in metadata."""
        assert "SENSITIVE_FILE" in body_post("/secrets.json")
        assert "SENSITIVE_FILE" in body_post("/docker-compose.yml")

    def test_severity_matches_the_class_it_joined(self) -> None:
        for rule in (
            "config_secrets_json",
            "config_compose_file",
            "config_spring_application_yaml",
            "config_circleci_file",
            "db_dump_at_web_root",
        ):
            assert get_severity("SENSITIVE_FILE", rule) == get_severity(
                "SENSITIVE_FILE", "lfi_sensitive_config"
            ), rule


class TestTheBoundariesRejectTheNearMisses:
    """Each of these exists in the store or in our own asset namespaces. A rule that labels one
    of them trades a measured gap for a manufactured false positive."""

    def test_a_legitimate_sharepoint_asset_stays_unlabelled(self) -> None:
        """`/_layouts/15/init.js` is a real SharePoint file that every browser fetches. It was
        on the sensor-e unlabelled list and belongs there: at most SCANNER, never SENSITIVE_FILE."""
        assert "SENSITIVE_FILE" not in by_path("/_layouts/15/init.js")

    def test_a_plural_applications_list_is_not_the_spring_config(self) -> None:
        assert "SENSITIVE_FILE" not in by_path("/applications.yaml")

    def test_an_unrelated_yaml_is_not_a_config_file(self) -> None:
        for path in ("/openapi.yaml", "/swagger.yml", "/sitemap.yml"):
            assert "SENSITIVE_FILE" not in by_path(path), path

    def test_a_word_boundary_protects_the_asset_namespaces(self) -> None:
        for path in ("/assets/secrets.jsonp", "/js/db.sqlite"):
            assert "SENSITIVE_FILE" not in by_path(path), path


class TestGlobalProtectPortal:
    def test_the_portal_login_page(self) -> None:
        """60 of 84 rows unlabelled on the seven sensors without a PAN-OS decoy."""
        assert "VPN_RECON" in by_path("/global-protect/login.esp")

    def test_the_other_portal_endpoints_in_the_same_sweep(self) -> None:
        for path in ("/global-protect/getconfig.esp", "/global-protect/portal/css/login.css"):
            assert "VPN_RECON" in by_path(path), path

    def test_it_matches_the_cisco_rule_it_is_symmetric_with(self) -> None:
        assert by_path("/global-protect/login.esp") >= {"VPN_RECON"}
        assert by_path("/+CSCOE+/logon.html") >= {"VPN_RECON"}

    def test_the_boundary_rejects_a_global_protection_marketing_page(self) -> None:
        assert "VPN_RECON" not in by_path("/global/protection.html")


class TestTwoShapesThatWereAlreadyCovered:
    """Pinned so the sensor-e residual list is not re-chased. Both looked uncovered because that
    sensor was importing bytes older than the rules."""

    def test_the_docker_engine_api_is_cloud_attack(self) -> None:
        assert "CLOUD_ATTACK" in by_path("/containers/json")

    def test_the_cisco_portal_is_vpn_recon(self) -> None:
        assert "VPN_RECON" in by_path("/+CSCOE+/logon.html")


def test_each_new_rule_is_the_one_that_fires() -> None:
    """The verdict without the rule name is not evidence: `attack_patterns.rule_name` is what a
    responder reads. A pre-existing rule matching by accident would make the tests above pass
    while the new rules were dead."""
    cases = {
        "/secrets.json": "config_secrets_json",
        "/docker-compose.yml": "config_compose_file",
        "/application.yml": "config_spring_application_yaml",
        "/.circleci/config.yml": "config_circleci_file",
        "/database.sql": "db_dump_at_web_root",
        "/global-protect/login.esp": "vpn_globalprotect_portal",
    }
    for path, rule in cases.items():
        assert rule in rules(summary(path), {"path": path}), (path, rule)
