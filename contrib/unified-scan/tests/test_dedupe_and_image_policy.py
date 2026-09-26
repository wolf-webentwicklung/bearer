"""Duplicate findings, base-image CVE policy, insecure SMTP rating and the setattr/getattr
line check for *_code_injection - all rule-class/pattern based, nothing project specific."""
import json

import pytest

import unified_scan
from unified_scan import (Finding, apply_base_image_policy, drop_duplicate_findings,
                          load_base_image_policy, load_severity_policy, parse_bearer_json,
                          refine_code_injection)


@pytest.fixture(autouse=True)
def _policy_on(monkeypatch):
    monkeypatch.delenv("UNIFIED_SCAN_SEVERITY_POLICY", raising=False)
    monkeypatch.delenv("UNIFIED_SCAN_SEVERITY_POLICY_FILE", raising=False)


# --- duplicates ------------------------------------------------------------------------

def test_same_bearer_rule_same_line_kept_once():
    fs = [Finding(tool="bearer", severity="low", rule_id="python_lang_exception", title="t",
                  file="app/security.py", line=29) for _ in range(4)]
    fs.append(Finding(tool="bearer", severity="low", rule_id="python_lang_exception", title="t",
                      file="app/security.py", line=30))
    out = drop_duplicate_findings(fs)
    assert [(f.file, f.line) for f in out] == [("app/security.py", 29), ("app/security.py", 30)]


def test_trivy_image_same_cve_same_image_kept_once_across_packages_and_stages():
    def img(cve, pkg, image="python:3.13-slim"):
        return Finding(tool="trivy-image", severity="high", rule_id=cve, title="t",
                       file="Dockerfile", image=image, package=pkg)
    fs = [img("CVE-1", "libc6"), img("CVE-1", "libc-bin"), img("CVE-1", "libc6"),
          img("CVE-2", "zlib1g"), img("CVE-1", "libc6", image="node:20-slim")]
    out = drop_duplicate_findings(fs)
    assert [(f.rule_id, f.image) for f in out] == [
        ("CVE-1", "python:3.13-slim"), ("CVE-2", "python:3.13-slim"), ("CVE-1", "node:20-slim")]


def test_trivy_fs_same_cve_different_packages_both_kept():
    fs = [Finding(tool="trivy", severity="high", rule_id="CVE-9", title="t", file="req.txt",
                  package=p) for p in ("a", "b", "a")]
    assert [f.package for f in drop_duplicate_findings(fs)] == ["a", "b"]


def test_different_tools_same_place_not_merged():
    a = Finding(tool="bearer", severity="high", rule_id="r", title="t", file="x.py", line=1)
    b = Finding(tool="trufflehog", severity="high", rule_id="r", title="t", file="x.py", line=1,
                category="secret")
    assert len(drop_duplicate_findings([a, b])) == 2


# --- base image policy -------------------------------------------------------------------

def _img(sev, fixed):
    return Finding(tool="trivy-image", severity=sev, rule_id="CVE-x", title="t",
                   file="Dockerfile", category="dependency", image="python:3.13-slim",
                   fixed_version=fixed)


@pytest.mark.parametrize("sev,fixed,expected", [
    ("critical", "1.2.3", "critical"),   # rebuilding fixes it -> keeps blocking
    ("critical", None, "low"),           # no fix available -> nothing the uploader can do
    ("high", "1.2.3", "low"),
    ("medium", None, "low"),
    ("low", None, "low"),
    ("info", None, "info"),              # never raised
])
def test_base_image_cves_become_hints(sev, fixed, expected):
    f = _img(sev, fixed)
    apply_base_image_policy(f, load_base_image_policy())
    assert f.severity == expected
    if expected != sev:
        assert f.original_severity == sev and f.policy_reason


def test_base_image_policy_only_for_trivy_image():
    f = Finding(tool="trivy", severity="high", rule_id="CVE-x", title="t", category="dependency")
    apply_base_image_policy(f, load_base_image_policy())
    assert f.severity == "high"


def test_base_image_policy_off(monkeypatch):
    monkeypatch.setenv("UNIFIED_SCAN_SEVERITY_POLICY", "off")
    f = _img("high", None)
    apply_base_image_policy(f, load_base_image_policy())
    assert f.severity == "high"


def test_scan_trivy_docker_images_sets_image_and_applies_policy(monkeypatch, tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.13-slim AS build\nRUN true\nFROM python:3.13-slim\nCOPY --from=build / /\n")
    out = {"Results": [{"Target": "debian", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-A", "PkgName": "libc6", "InstalledVersion": "2.36",
         "FixedVersion": "2.36-9", "Severity": "CRITICAL"},
        {"VulnerabilityID": "CVE-B", "PkgName": "zlib1g", "InstalledVersion": "1.2",
         "Severity": "HIGH"},
    ]}]}
    calls = []
    monkeypatch.setattr(unified_scan, "run_tool",
                        lambda name, cmd, **k: (calls.append(cmd), (True, json.dumps(out), ""))[1])
    findings, meta = unified_scan.scan_trivy_docker_images(tmp_path)
    assert meta["images_checked"] == ["python:3.13-slim"] and len(calls) == 1
    assert [(f.rule_id, f.image, f.package, f.severity) for f in findings] == [
        ("CVE-A", "python:3.13-slim", "libc6", "critical"),
        ("CVE-B", "python:3.13-slim", "zlib1g", "low"),
    ]
    assert findings[0].to_dict()["image"] == "python:3.13-slim"


# --- insecure SMTP -----------------------------------------------------------------------

def test_insecure_smtp_is_medium_and_justifiable():
    data = {"critical": [{"rule_id": "python_lang_insecure_smtp", "title": "Insecure SMTP",
                          "filename": "mail.py", "source": {"start": 3}}]}
    (f,) = parse_bearer_json(data, load_severity_policy())
    assert f.severity == "medium" and f.original_severity == "critical" and "TLS" in f.policy_reason


# --- setattr/getattr line check ----------------------------------------------------------

def _ci(tmp_path, code, line=2):
    (tmp_path / "ocr.py").write_text(code)
    data = {"critical": [{"rule_id": "python_lang_code_injection", "title": "Code injection",
                          "filename": "ocr.py", "source": {"start": line}}]}
    findings = parse_bearer_json(data, load_severity_policy())
    refine_code_injection(findings, tmp_path)
    return findings[0]


@pytest.mark.parametrize("code", [
    "def apply(obj, field, value):\n    setattr(obj, field, value)\n",
    "def read(obj, name):\n    return getattr(obj, name, None)\n",
    "def drop(obj, name):\n    delattr(obj, name)\n",
])
def test_attribute_access_lowered_to_high(tmp_path, code):
    f = _ci(tmp_path, code)
    assert f.severity == "high" and f.original_severity == "critical"
    assert "setattr" in f.policy_reason


@pytest.mark.parametrize("code", [
    "def run(expr):\n    return eval(expr)\n",
    "def run(src):\n    exec(src)\n",
    "def run(obj, name, src):\n    setattr(obj, name, eval(src))\n",   # eval on the same line
    "def run(src):\n    code = compile(src, 'x', 'exec')\n",
])
def test_real_code_execution_stays_critical(tmp_path, code):
    assert _ci(tmp_path, code).severity == "critical"


def test_line_outside_target_or_missing_file_stays_critical(tmp_path):
    data = {"critical": [{"rule_id": "python_lang_code_injection", "title": "t",
                          "filename": "../outside.py", "source": {"start": 1}}]}
    (tmp_path.parent / "outside.py").write_text("setattr(o, n, v)\n")
    findings = parse_bearer_json(data, load_severity_policy())
    refine_code_injection(findings, tmp_path)
    assert findings[0].severity == "critical"
    data["critical"][0]["filename"] = "missing.py"
    findings = parse_bearer_json(data, load_severity_policy())
    refine_code_injection(findings, tmp_path)
    assert findings[0].severity == "critical"
