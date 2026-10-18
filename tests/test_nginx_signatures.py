"""Offline tests for the NGINX honeypot CVE catalog + classifier.

No network: every test drives classify()/matchers directly with byte inputs.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeylens.honeypots.nginx import signatures as sig
from honeylens.honeypots.nginx.detector import Detection, SourceTracker, classify
from honeylens.honeypots.nginx.server import SERVER_BANNER


# --- CVE-2026-42533: script-engine capture overflow (heuristic) -------------
def test_42533_long_uri_is_leak_not_overflow():
    # long URI capture value = the info-leak primitive (undersized captures), GET
    path = b"/x/" + b"A" * 600 + b"?q=1"
    d = classify("GET", path, {}, b"")
    assert d.matched and d.cve_id == "CVE-2026-42533"
    assert d.attack_class == "cve-2026-42533-leak" and not d.is_overflow
    assert d.confidence == "low"
    assert any(i.startswith("cve_2026_42533_leak:") for i in d.indicators)


def test_42533_extreme_uri_leak_is_medium():
    d = classify("GET", b"/x/" + b"A" * 3000, {}, b"")
    assert d.cve_id == "CVE-2026-42533" and d.attack_class == "cve-2026-42533-leak"
    assert d.confidence == "medium" and not d.is_overflow


def test_42533_below_threshold_no_match():
    d = classify("GET", b"/x/" + b"A" * 100, {}, b"")
    assert not d.matched


def test_42533_long_host_header_is_leak():
    d = classify("GET", b"/", {"Host": "a" * 700 + ".example"}, b"")
    assert d.cve_id == "CVE-2026-42533" and d.attack_class == "cve-2026-42533-leak"
    assert not d.is_overflow


def test_42533_post_body_overflow_is_overflow():
    # POST whose $request_body regex clobbers captures = the heap-overflow trigger
    body = b"payload=" + b"A" * 600
    d = classify("POST", b"/r", {"Content-Type": "application/x-www-form-urlencoded"}, body)
    assert d.matched and d.cve_id == "CVE-2026-42533"
    assert d.attack_class == "cve-2026-42533" and d.is_overflow
    assert d.confidence == "medium"
    assert any(i.startswith("cve_2026_42533_overflow:") for i in d.indicators)


def test_42533_extreme_body_overflow_is_high():
    d = classify("POST", b"/r", {}, b"A" * 3000)
    assert d.cve_id == "CVE-2026-42533" and d.is_overflow and d.confidence == "high"


def test_42533_overflow_outranks_leak_in_one_request():
    # long URI (leak) AND long POST body (overflow) in one request -> overflow wins
    d = classify("POST", b"/x/" + b"A" * 600, {}, b"B" * 600)
    assert d.is_overflow and d.attack_class == "cve-2026-42533"


def test_42533_get_body_ignored_only_post_overflows():
    # a body on a GET is not the overflow primitive
    d = classify("GET", b"/short", {}, b"A" * 3000)
    assert not d.matched


# --- CVE-2026-42945: Rift rewrite-module overflow ---------------------------
def test_42945_api_escape_flood_is_dos():
    path = b"/api/" + b"+" * 40
    d = classify("GET", path, {}, b"")
    assert d.attack_type == "cve_2026_42945_dos" and d.is_overflow


def test_42945_flood_plus_spray_is_rce():
    path = b"/api/" + b"%2b" * 40
    body = b"\x41" * 64 + b"\x00" + b"C" * 300
    d = classify("POST", path, {}, body)
    assert d.attack_type == "cve_2026_42945_rce"


def test_42945_xdelay_alone_is_not_an_attack():
    d = classify("GET", b"/api/thing", {"X-Delay": "5"}, b"")
    assert not d.matched


# --- CVE-2013-2028: chunked stack overflow ----------------------------------
def test_2013_2028_huge_chunk_size():
    headers = {"Transfer-Encoding": "chunked"}
    body = b"ffffffffffffffff0\r\nAAAA\r\n"
    d = classify("POST", b"/", headers, body)
    assert d.cve_id == "CVE-2013-2028" and d.is_overflow


def test_2013_2028_normal_chunk_no_match():
    headers = {"Transfer-Encoding": "chunked"}
    body = b"10\r\n" + b"A" * 16 + b"\r\n0\r\n\r\n"
    d = classify("POST", b"/", headers, body)
    assert d.cve_id != "CVE-2013-2028"


# --- CVE-2017-7529: range integer overflow ----------------------------------
def test_2017_7529_many_ranges():
    d = classify("GET", b"/f", {"Range": "bytes=" + ",".join(["0-1"] * 9)}, b"")
    assert d.cve_id == "CVE-2017-7529" and not d.is_overflow


def test_2017_7529_big_offset():
    d = classify("GET", b"/f", {"Range": "bytes=-9999999999"}, b"")
    assert d.cve_id == "CVE-2017-7529"


def test_2017_7529_normal_range_no_match():
    d = classify("GET", b"/f", {"Range": "bytes=0-1023"}, b"")
    assert not d.matched


# --- CVE-2022-41741: mp4 module ---------------------------------------------
def test_mp4_probe_with_seek():
    d = classify("GET", b"/video/clip.mp4?start=1000", {}, b"")
    assert d.cve_id == "CVE-2022-41741"


def test_mp4_without_seek_no_match():
    d = classify("GET", b"/video/clip.mp4", {}, b"")
    assert not d.matched


# --- CVE-2021-23017: resolver — banner-draw only, never matches inbound ------
def test_2021_23017_never_matches():
    for m in sig.CATALOG:
        if m.cve_id == "CVE-2021-23017":
            assert m.match("GET", b"/anything", {"Host": "x"}, b"", "HTTP/1.1") is None


# --- classifier behaviour ----------------------------------------------------
def test_benign_request_no_match():
    d = classify("GET", b"/index.html", {"Host": "example.com"}, b"")
    assert not d.matched and d.attack_class == "none"


def test_overflow_outranks_recon_when_both_present():
    # a .mp4 recon probe whose POST body is also an over-long capture (42533 overflow)
    d = classify("POST", b"/video/x.mp4?start=1", {}, b"A" * 700)
    assert d.is_overflow and d.cve_id == "CVE-2026-42533"  # overflow beats mp4 recon


def test_matcher_never_raises_on_garbage():
    d = classify("GET", b"\xff\x00/api/\xfe", {"Range": "bytes=abc"}, b"\x00\xff")
    assert isinstance(d, Detection)


# --- SourceTracker correlation ----------------------------------------------
def test_tracker_correlates_flood_then_spray_into_rce():
    tr = SourceTracker(window_seconds=120)
    flood = classify("GET", b"/api/" + b"+" * 40, {}, b"")
    assert tr.observe("1.2.3.4", flood, now=1000.0) == "cve-2026-42945-dos"
    spray = classify("POST", b"/x", {}, b"\x41" * 64 + b"\x00" + b"C" * 300)
    assert tr.observe("1.2.3.4", spray, now=1001.0) == "cve-2026-42945-rce"


# --- banner ------------------------------------------------------------------
def test_banner_is_vulnerable_version():
    assert SERVER_BANNER == "nginx/1.31.2"
