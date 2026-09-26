import json

import pytest

import unified_scan
from unified_scan import Finding, _parse_trufflehog_ndjson, drop_secret_duplicates


def _line(raw, file="a.py", line=5):
    return json.dumps({"SourceMetadata": {"Data": {"Filesystem": {"file": file, "line": line}}},
                       "DetectorName": "SQLServer", "Raw": raw, "Verified": False})


@pytest.mark.parametrize("raw", ["{pw}", "${DB_PASSWORD}", "%s", "%(pw)s", "$PW", "<password>", "****"])
def test_placeholders_dropped(raw):
    assert _parse_trufflehog_ndjson(_line(raw), git_mode=False) == []


@pytest.mark.parametrize("raw", ["Sommer2026!", "p{w}d", "abc$def"])
def test_real_values_kept(raw):
    assert len(_parse_trufflehog_ndjson(_line(raw), git_mode=False)) == 1


def test_secret_duplicate_of_own_rule_dropped():
    t = Finding(tool="trufflehog", severity="high", rule_id="SQLServer", title="t", file="c.py", line=5, category="secret")
    own = Finding(tool="bearer", severity="high", rule_id="idv_python_db_password_in_code", title="t", file="c.py", line=5, category="secret")
    other = Finding(tool="bearer", severity="high", rule_id="idv_python_db_password_in_code", title="t", file="d.py", line=3, category="secret")
    assert drop_secret_duplicates([t, own, other]) == [t, other]
