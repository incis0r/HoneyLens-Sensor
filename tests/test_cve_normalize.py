#!/usr/bin/env python3
"""Tests for analysis/cve_normalize.normalize_cve."""

from datetime import UTC

import pytest

from honeylens.analysis.cve_normalize import normalize_cve


@pytest.mark.parametrize(
    "raw,expect",
    [
        ("CVE-2021-44228", "CVE-2021-44228"),  # already canonical
        ("cve-2021-44228", "CVE-2021-44228"),  # lowercase
        (" CVE-2021-44228 ", "CVE-2021-44228"),  # whitespace
        ("CVE_2021_44228", "CVE-2021-44228"),  # underscores -> hyphens
        ("CVE-2017-0144", "CVE-2017-0144"),  # padded sequence kept
        ("CVE-2024-3400", "CVE-2024-3400"),
    ],
)
def test_valid_normalises(raw, expect):
    assert normalize_cve(raw) == expect


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "null",
        "None",
        "N/A",
        "unknown",
        "-",
        "CVE-XXXX-XXXXX",
        "CVE-2023-XXXXX",  # placeholders
        "CVE-2021-123",  # too-short sequence
        "not-a-cve",
        "2021-44228",
        "CVE2021-44228",
        "CVE-1998-0001",  # before CVE existed
        "CVE-2199-0001",  # implausible future year
    ],
)
def test_junk_rejected(raw):
    assert normalize_cve(raw) is None


def test_future_slack_allows_next_year():
    from datetime import datetime

    y = datetime.now(UTC).year + 1
    assert normalize_cve(f"CVE-{y}-0001") == f"CVE-{y}-0001"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
