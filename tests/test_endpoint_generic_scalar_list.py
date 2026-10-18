"""The generic HTML renderer must survive a stats field that is a list of scalars.

Regression: /mitre/technique/{id} returns ``matching_attack_types`` as a list of strings.
``_generate_stats_html`` rendered every list as a record table, and ``_generate_table_html``
called ``data[0].keys()`` on it — ``AttributeError: 'str' object has no attribute 'keys'``,
a 500 on the drilled-down technique page.
"""

from honeylens.webui.endpoint_generic import _generate_stats_html, _generate_table_html


def test_table_of_scalars_renders_one_column_not_crash():
    html = _generate_table_html(["SQL_INJECTION", "PATH_TRAVERSAL"], "stats")
    assert "SQL_INJECTION" in html
    assert "PATH_TRAVERSAL" in html
    assert "<table>" in html


def test_table_of_scalars_escapes_values():
    html = _generate_table_html(["<script>"], "stats")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_mitre_technique_result_shape_renders():
    result = {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "matching_attack_types": ["SQLI", "XSS"],
        "events": [{"event_id": "abc123", "src_ip": "1.2.3.4"}],
        "count": 1,
    }
    html = _generate_stats_html(result)
    assert "SQLI" in html and "XSS" in html
    assert "T1190" in html
