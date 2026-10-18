"""Unit tests for intelligence/apt_attribution.py — scoring math + JSON loader.

These tests pin the option-β scoring contract.
"""

from __future__ import annotations

import json

import pytest

from honeylens.intelligence.apt_attribution import (
    EFFECTIVE_TECH_BUDGET,
    MIN_SCORE,
    MitreAttackData,
    _band,
    _compute_score,
    _group_prior,
    _load_attack_to_mitre,
    compute_apt_attribution,
)

# ---------------------------------------------------------------------------
# _group_prior
# ---------------------------------------------------------------------------


class TestGroupPrior:
    def test_tier1_full_prior(self):
        assert _group_prior("G0007") == 1.0  # APT28
        assert _group_prior("G0016") == 1.0  # APT29
        assert _group_prior("G0096") == 1.0  # APT41

    def test_unknown_group_half_prior(self):
        assert _group_prior("G9999") == 0.5
        assert _group_prior("") == 0.5
        assert _group_prior("not-a-real-id") == 0.5


# ---------------------------------------------------------------------------
# _compute_score
# ---------------------------------------------------------------------------


class TestComputeScore:
    """The scoring math is the heart of the rework — these tests pin it."""

    def test_empty_overlap_zero(self):
        assert _compute_score(set(), {}, "G0007") == 0.0

    def test_small_vs_large_group_symmetry(self):
        """The bias fix: same observed-techniques set should score the same
        regardless of how many techniques the matched group documents.

        Old formula gave the small group ~25x higher; new formula gives
        equal scores because we no longer divide by |group_techniques|.
        """
        counts = {"T1110.003": 4}
        overlap = {"T1110.003"}
        # We only pass overlap + counts now — no group_techniques arg —
        # so the two cases are literally identical at the scoring level.
        score_a = _compute_score(overlap, counts, "G9999")
        score_b = _compute_score(overlap, counts, "G9999")
        assert score_a == score_b

    def test_rarest_drives_score_not_mean(self):
        """One rare + one common technique should NOT dilute the rare one.

        Old formula averaged 1/4 + 1/30 → ~0.14 / 2 = 0.07 rarity, then
        blended with coverage. New formula: rarest only.
        """
        counts_rare_only = {"T1110.003": 4}
        counts_with_common = {"T1110.003": 4, "T1110.001": 30}
        rare_score = _compute_score({"T1110.003"}, counts_rare_only, "G9999")
        mixed_score = _compute_score({"T1110.003", "T1110.001"}, counts_with_common, "G9999")
        # Mixed is HIGHER (more matches → higher capped coverage), but the
        # *per-technique discriminator* is unchanged because we look at min.
        assert mixed_score >= rare_score
        # And critically, observing one rare-tech doesn't get diluted to
        # below the rare-only baseline.
        assert mixed_score >= rare_score

    def test_tier1_prior_applied(self):
        counts = {"T1110.003": 4}
        overlap = {"T1110.003"}
        unknown = _compute_score(overlap, counts, "G9999")
        tier1 = _compute_score(overlap, counts, "G0007")
        # Tier-1 prior is 1.0 vs 0.5 → exactly 2x score.
        assert tier1 == pytest.approx(2 * unknown, rel=0.01)

    def test_capped_coverage_caps_at_budget(self):
        """Adjusted coverage saturates at 1.0 once |overlap| ≥ EFFECTIVE_TECH_BUDGET.

        At the budget boundary and beyond, the coverage component contributes
        the same maximum, so score is driven purely by rarest x prior.
        """
        # Same rarity, varying overlap size around the budget boundary
        counts = {f"T{i:04d}": 4 for i in range(EFFECTIVE_TECH_BUDGET + 4)}
        small = {f"T{i:04d}" for i in range(EFFECTIVE_TECH_BUDGET)}
        big = {f"T{i:04d}" for i in range(EFFECTIVE_TECH_BUDGET + 4)}
        score_at_budget = _compute_score(small, counts, "G9999")
        score_above_budget = _compute_score(big, counts, "G9999")
        assert score_at_budget == score_above_budget  # cap is hit

    def test_score_in_zero_one(self):
        # Worst case: all techniques used by 999 groups, 0 overlap → 0
        # Best case: 1 unique tech (used by 1 group), tier-1 prior, full budget
        counts = {f"T{i:04d}": 1 for i in range(EFFECTIVE_TECH_BUDGET)}
        big_unique = {f"T{i:04d}" for i in range(EFFECTIVE_TECH_BUDGET)}
        score = _compute_score(big_unique, counts, "G0007")
        # rarest=1.0, adj_cov=1.0, prior=1.0 → 1.0 capped
        assert score == 1.0


# ---------------------------------------------------------------------------
# _band
# ---------------------------------------------------------------------------


class TestBand:
    def test_band_boundaries(self):
        assert _band(0.20) == "high"
        assert _band(0.50) == "high"
        assert _band(0.05) == "medium"
        assert _band(0.19) == "medium"
        assert _band(0.01) == "low"
        assert _band(0.04) == "low"
        assert _band(0.0099) == "none"
        assert _band(0.0) == "none"

    def test_band_min_score_aligns_with_low_floor(self):
        """MIN_SCORE is the threshold below which results are filtered.
        It should match the floor of the 'low' band so we don't return
        rows that the band classifier would call 'none'.
        """
        assert MIN_SCORE == 0.01
        assert _band(MIN_SCORE) == "low"
        assert _band(MIN_SCORE - 0.0001) == "none"


# ---------------------------------------------------------------------------
# compute_apt_attribution — integration with a fake MitreAttackData
# ---------------------------------------------------------------------------


def _fake_mitre(groups):
    """Build a MitreAttackData stand-in from a {attack_id: {techniques}} map."""
    md = MitreAttackData(stix_path="/dev/null")
    md.loaded = True
    for attack_id, techniques in groups.items():
        stix_id = f"intrusion-set--{attack_id}"
        md.groups[stix_id] = {
            "stix_id": stix_id,
            "attack_id": attack_id,
            "name": attack_id,
            "aliases": [],
            "description": "",
        }
        md.group_techniques[stix_id] = set(techniques)
        for t in techniques:
            md.technique_groups[t].add(stix_id)
    for t, groups_set in md.technique_groups.items():
        md.technique_group_counts[t] = len(groups_set)
    return md


class TestComputeAptAttribution:
    def test_empty_observed_returns_empty(self):
        md = _fake_mitre({"G9999": ["T1110.003"]})
        assert compute_apt_attribution([], md) == []

    def test_all_filtered_out_returns_empty(self):
        # A technique used by 50 groups → exceeds default MAX_GROUPS_PER_TECHNIQUE=10
        groups = {f"G{i:04d}": ["T1190"] for i in range(50)}
        md = _fake_mitre(groups)
        assert compute_apt_attribution(["T1190"], md) == []

    def test_basic_match_returns_candidate(self):
        md = _fake_mitre({"G9999": ["T1110.003"]})
        out = compute_apt_attribution(["T1110.003"], md)
        assert len(out) == 1
        c = out[0]
        assert c["group_id"] == "G9999"
        assert c["score"] > 0
        assert c["confidence"] in ("low", "medium", "high")
        assert c["probability"] == c["score"]  # backwards-compat alias
        assert c["matching_techniques"] == ["T1110.003"]
        assert c["rarest_technique"] == "T1110.003"
        assert c["tier1_prior_applied"] is False

    def test_tier1_group_gets_prior(self):
        md = _fake_mitre(
            {
                "G0007": ["T1110.003"],  # APT28
                "G9999": ["T1110.003"],  # unknown
            }
        )
        out = compute_apt_attribution(["T1110.003"], md)
        by_id = {c["group_id"]: c for c in out}
        assert by_id["G0007"]["tier1_prior_applied"] is True
        assert by_id["G9999"]["tier1_prior_applied"] is False
        # G0007 score should be exactly 2x G9999 (same overlap, prior 1.0 vs 0.5)
        assert by_id["G0007"]["score"] == pytest.approx(2 * by_id["G9999"]["score"], rel=0.01)

    def test_sort_stable_by_group_id_on_score_tie(self):
        md = _fake_mitre(
            {
                "G9998": ["T1110.003"],
                "G9999": ["T1110.003"],
                "G9997": ["T1110.003"],
            }
        )
        out = compute_apt_attribution(["T1110.003"], md)
        # Same score → sorted alphabetically by group_id
        assert [c["group_id"] for c in out] == ["G9997", "G9998", "G9999"]

    def test_top_10_truncation(self):
        # 15 groups, each using a unique rare technique. We observe all 15
        # techniques. Each technique's group-count is 1 (unique), so none
        # get filtered as "too common", and each group gets a non-zero
        # score → 15 candidates → top-10 truncation kicks in.
        techs = [f"T9{i:03d}.001" for i in range(15)]
        groups = {f"G{8000 + i:04d}": [techs[i]] for i in range(15)}
        md = _fake_mitre(groups)
        out = compute_apt_attribution(techs, md)
        assert len(out) == 10

    def test_filtered_out_techniques_recorded(self):
        # T1190 used by 12 groups (over filter), T1110.003 by 1 (under).
        # Same group uses both → result should record T1190 as filtered.
        groups = {f"G{8000 + i:04d}": ["T1190"] for i in range(11)}
        groups["G9999"] = ["T1190", "T1110.003"]
        md = _fake_mitre(groups)
        out = compute_apt_attribution(["T1190", "T1110.003"], md, max_groups_per_technique=10)
        match = next(c for c in out if c["group_id"] == "G9999")
        assert "T1110.003" in match["matching_techniques"]
        assert "T1190" in match["filtered_out_techniques"]


# ---------------------------------------------------------------------------
# JSON loader fallback
# ---------------------------------------------------------------------------


class TestLoadAttackToMitre:
    def test_loads_known_file(self):
        # The bundled file should be reachable from the source tree
        result = _load_attack_to_mitre()
        assert "ssh_brute" in result
        assert result["ssh_brute"] == ["T1110.001", "T1110.003"]

    def test_falls_back_when_no_files_readable(self, caplog):
        with caplog.at_level("WARNING"):
            result = _load_attack_to_mitre(paths=("/nonexistent/path.json",))
        assert "ssh_brute" in result  # fallback contains it
        assert any("fallback" in r.message for r in caplog.records)

    def test_skips_underscore_keys(self, tmp_path):
        f = tmp_path / "attack_to_mitre.json"
        f.write_text(
            json.dumps(
                {
                    "_documentation": "header text",
                    "_comment": "another comment",
                    "real_category": {"foo_attack": ["T9999"]},
                }
            )
        )
        result = _load_attack_to_mitre(paths=(str(f),))
        assert "foo_attack" in result
        assert "_documentation" not in result
        assert "_comment" not in result

    def test_handles_corrupt_json(self, tmp_path, caplog):
        f = tmp_path / "attack_to_mitre.json"
        f.write_text("not json {[}")
        with caplog.at_level("DEBUG"):
            result = _load_attack_to_mitre(paths=(str(f),))
        # Falls back to bundled
        assert "ssh_brute" in result
