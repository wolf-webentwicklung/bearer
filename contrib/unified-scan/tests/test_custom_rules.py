"""Own Bearer rules (custom-rules/) and the C# check, pinned against the invented corpus in
fixtures/idv_corpus/custom (dangerous: must be found, benign: must not)."""
import json
from pathlib import Path

import pytest

import unified_scan
from unified_scan import Finding, compute_criticality, parse_bearer_json, scan_csharp_db_passwords

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures" / "idv_corpus"
RULES = HERE.parent / "custom-rules"


def _parsed(name):
    return parse_bearer_json(json.loads((FIXTURES / "bearer_results" / f"{name}.json").read_text()),
                             unified_scan.load_severity_policy())


@pytest.fixture(autouse=True)
def _policy_on(monkeypatch):
    monkeypatch.delenv("UNIFIED_SCAN_SEVERITY_POLICY", raising=False)
    monkeypatch.delenv("UNIFIED_SCAN_SEVERITY_POLICY_FILE", raising=False)


def test_rule_files_are_valid_and_named_by_id():
    import yaml
    files = sorted(RULES.rglob("*.yml"))
    assert len(files) == 6
    for f in files:
        rule = yaml.safe_load(f.read_text())
        assert rule["metadata"]["id"] == f.stem and f.stem.startswith("idv_")
        assert rule["severity"] in ("critical", "high", "medium")


def test_dangerous_patterns_found():
    found = {(f.rule_id, f.file, f.line): f for f in _parsed("custom_dangerous")}
    by_file = {}
    for (rule, file, _), f in found.items():
        by_file.setdefault(file, set()).add((rule, f.severity, f.category))
    for file in ("conn_pyodbc.py", "conn_concat.py", "conn_sqlalchemy.py", "conn_psycopg2.py"):
        assert ("idv_python_db_password_in_code", "high", "secret") in by_file[file], file
    assert ("idv_javascript_db_password_in_code", "high", "secret") in by_file["conn_node.js"]
    assert ("idv_python_sql_string_building", "medium", "security") in by_file["sql_concat.py"]
    assert {(r, s) for r, s, _ in by_file["sql_concat.py"]} >= {("python_lang_sql_injection", "medium")}
    assert ("idv_python_yaml_unsafe_load", "high", "security") in by_file["yaml_unsafe.py"]
    assert sum(1 for k in found if k[0] == "idv_python_yaml_unsafe_load") == 3
    node = {(r, s) for r, s, _ in by_file["node_exec.js"]}
    assert ("idv_javascript_eval_dynamic", "critical") in node
    assert ("javascript_lang_dynamic_os_command", "high") in node


def test_benign_variants_not_flagged():
    flagged = [f for f in _parsed("custom_benign") if f.severity in ("critical", "high", "medium")]
    assert flagged == []


def test_same_line_duplicate_dropped():
    sql = [(f.rule_id, f.line) for f in _parsed("custom_dangerous") if f.file == "sql_concat.py"]
    assert ("idv_python_sql_string_building", 7) in sql
    assert ("idv_python_sql_string_building", 12) not in sql  # default rule reports line 12
    assert ("python_lang_sql_injection", 12) in sql


def test_old_corpus_now_found():
    found = {(f.rule_id, f.file) for f in _parsed("dangerous")}
    assert ("idv_python_db_password_in_code", "hardcoded_password.py") in found
    assert ("idv_python_yaml_unsafe_load", "yaml_unsafe.py") in found
    assert ("idv_javascript_child_process_dynamic", "exec_js.js") in found
    assert ("idv_javascript_eval_dynamic", "exec_js.js") in found


def test_csharp_check(tmp_path):
    for sub in ("dangerous", "benign"):
        for f in (FIXTURES / "custom" / sub).glob("*.cs"):
            (tmp_path / sub).mkdir(exist_ok=True)
            (tmp_path / sub / f.name).write_text(f.read_text())
    bad = scan_csharp_db_passwords(tmp_path / "dangerous")
    assert [(f.rule_id, f.file, f.line, f.category) for f in bad] == [
        ("idv_csharp_db_password_in_code", "Conn.cs", 5, "secret")]
    assert scan_csharp_db_passwords(tmp_path / "benign") == []


def test_csharp_check_edge_cases(tmp_path):
    (tmp_path / "a.cs").write_text('var a = "Server=x;Password=;";\nvar b = "Password=" + pw;\n'
                                   'var c = $"Password={pw}";\nvar d = "User=x;PWD=geheim1";\n')
    assert [f.line for f in scan_csharp_db_passwords(tmp_path)] == [4]


class TestGroupScore:
    def _f(self, sev, rule, line=1, tool="bearer", **kw):
        return Finding(tool=tool, severity=sev, rule_id=rule, title="t", file="a.py", line=line, **kw)

    def test_many_locations_of_one_low_rule_stay_green(self):
        crit = compute_criticality([self._f("low", "r", line=i) for i in range(20)])
        assert crit["score_0_100"] == 2 and crit["verdict"].startswith("GRÜN")
        assert crit["by_severity"]["low"] == 1 and crit["rule_groups"] == 1

    def test_low_hints_capped(self):
        crit = compute_criticality([self._f("low", f"r{i}") for i in range(10)] + [self._f("info", "i")])
        assert crit["score_0_100"] == 5 and crit["verdict"].startswith("GRÜN")

    def test_group_counts_highest_severity_once(self):
        crit = compute_criticality([self._f("medium", "r", 1), self._f("high", "r", 2), self._f("high", "r", 3)])
        assert crit["score_0_100"] == 20 and crit["by_severity"]["high"] == 1

    def test_trivy_grouped_per_package(self):
        fs = [self._f("high", f"CVE-{i}", tool="trivy", package="flask") for i in range(3)]
        assert compute_criticality(fs)["score_0_100"] == 20
