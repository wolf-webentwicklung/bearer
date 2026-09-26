"""severity_policy.json: Bearer findings re-rated for internal employee scripts.

The corpus under fixtures/idv_corpus/ is invented; bearer_results/ holds Bearer's raw output
for it (bearer-rules v0.48.4, trimmed), so these tests pin the before/after behaviour without
needing the bearer binary.
"""
import json
from pathlib import Path

import pytest

import unified_scan
from unified_scan import Finding, apply_severity_policy, load_severity_policy, parse_bearer_json

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "idv_corpus" / "bearer_results"
BLOCKING = {"critical", "high", "medium"}


def _bearer(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


@pytest.fixture
def policy(monkeypatch):
    monkeypatch.delenv("UNIFIED_SCAN_SEVERITY_POLICY", raising=False)
    monkeypatch.delenv("UNIFIED_SCAN_SEVERITY_POLICY_FILE", raising=False)
    return load_severity_policy()


def _f(rule_id, severity, category="security", tool="bearer", file="tool.py"):
    return Finding(tool=tool, severity=severity, rule_id=rule_id, title="t", file=file,
                   category=category)


def test_policy_file_is_valid_and_documented(policy):
    assert policy
    assert all(r["reason"] for r in policy)


def test_path_rules_become_hints(policy):
    f = _f("python_lang_path_traversal", "high")
    apply_severity_policy(f, policy)
    assert f.severity == "low"
    assert f.original_severity == "high"
    assert "Dateipfade" in f.policy_reason


def test_eval_stays_critical_and_min_never_lowers(policy):
    f = _f("python_lang_eval_using_user_input", "critical")
    apply_severity_policy(f, policy)
    assert f.severity == "critical" and f.original_severity is None

    f = _f("python_lang_ssl_verification", "medium")
    apply_severity_policy(f, policy)
    assert f.severity == "high" and f.original_severity == "medium"


def test_command_injection_and_pickle_stay_blocking_but_justifiable(policy):
    for rule in ("python_lang_os_command_injection", "python_lang_avoid_pickle"):
        f = _f(rule, "critical")
        apply_severity_policy(f, policy)
        assert f.severity == "high"  # blocks, but high can be justified per finding


def test_sql_injection_is_medium(policy):
    f = _f("javascript_lang_sql_injection", "critical")
    apply_severity_policy(f, policy)
    assert f.severity == "medium"


def test_unknown_rule_keeps_bearer_severity(policy):
    f = _f("python_lang_something_new", "high")
    apply_severity_policy(f, policy)
    assert f.severity == "high" and f.original_severity is None


@pytest.mark.parametrize("category", ["secret", "malware", "malicious-package", "unscannable"])
def test_never_applied_to_protected_categories(policy, category):
    f = _f("python_lang_path_traversal", "high", category=category)
    apply_severity_policy(f, policy)
    assert f.severity == "high"


def test_only_bearer(policy):
    f = _f("python_lang_path_traversal", "high", tool="checkov")
    apply_severity_policy(f, policy)
    assert f.severity == "high"


def test_downgrade_in_test_path_recomputes_score_exclusion(policy):
    # critical is never excluded from the score; once downgraded, the test-path rule applies again
    f = _f("python_lang_os_command_injection", "critical", file="tests/test_x.py")
    assert f.excluded_from_score is False
    apply_severity_policy(f, policy)
    assert f.excluded_from_score is True


def test_disable_via_env(monkeypatch):
    monkeypatch.setenv("UNIFIED_SCAN_SEVERITY_POLICY", "off")
    assert load_severity_policy() == []


def test_broken_policy_file_raises(tmp_path, monkeypatch):
    bad = tmp_path / "p.json"
    bad.write_text(json.dumps({"rules": [{"match": "*", "mode": "drop", "severity": "low"}]}))
    monkeypatch.delenv("UNIFIED_SCAN_SEVERITY_POLICY", raising=False)
    monkeypatch.setenv("UNIFIED_SCAN_SEVERITY_POLICY_FILE", str(bad))
    with pytest.raises(ValueError):
        load_severity_policy()


def test_to_dict_carries_original_severity(policy):
    f = _f("python_lang_path_traversal", "high")
    apply_severity_policy(f, policy)
    d = f.to_dict()
    assert d["severity"] == "low" and d["original_severity"] == "high" and d["policy_reason"]


# --- corpus: typical internal scripts vs. genuinely dangerous code -------------------------

def test_corpus_benign_scripts_only_blocked_by_justifiable_findings(policy):
    before = parse_bearer_json(_bearer("benign"))
    after = parse_bearer_json(_bearer("benign"), policy)
    # 13 from Bearer's default rules + the string-built SQL report (own rule, medium)
    assert sum(f.severity in BLOCKING for f in before) == 14
    blocking_after = [f for f in after if f.severity in BLOCKING]
    # left: local pickle cache (2x) + subprocess with a fixed argument list (high) and the
    # string-built SQL report (own rule, medium) - all justifiable, nothing critical any more
    assert sorted(f.rule_id for f in blocking_after) == [
        "idv_python_sql_string_building", "python_lang_avoid_pickle", "python_lang_avoid_pickle",
        "python_lang_os_command_injection",
    ]
    assert all(f.severity in ("high", "medium") for f in blocking_after)
    assert {f.file for f in blocking_after} == {"pickle_cache_local.py", "run_tool.py", "sql_report_stringbuilt.py"}


def test_corpus_dangerous_code_still_blocks(policy):
    after = {(f.file, f.rule_id): f for f in parse_bearer_json(_bearer("dangerous"), policy)}
    assert after[("eval_input.py", "python_lang_eval_using_user_input")].severity == "critical"
    for key in (("shell_input.py", "python_lang_os_command_injection"),
                ("os_system_input.py", "python_lang_os_command_injection"),
                ("pickle_remote.py", "python_lang_avoid_pickle"),
                ("tls_off.py", "python_lang_ssl_verification")):
        assert after[key].severity == "high", key
    assert after[("weak_hash_password.py", "python_lang_weak_hash_md5")].severity == "medium"


def test_criticality_uses_adjusted_severity(policy):
    after = parse_bearer_json(_bearer("benign"), policy)
    crit = unified_scan.compute_criticality(after)
    assert crit["by_severity"]["critical"] == 0
