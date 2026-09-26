import json

import unified_scan


TRIVY_OUT = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
    {"VulnerabilityID": "CVE-2023-30861", "PkgName": "flask", "InstalledVersion": "0.12.2",
     "FixedVersion": "2.2.5, 2.3.2", "Severity": "HIGH", "Title": "flask: session cookie"},
    {"VulnerabilityID": "CVE-2018-1000656", "PkgName": "flask", "InstalledVersion": "0.12.2",
     "FixedVersion": "0.12.3", "Severity": "HIGH", "Title": "flask: DoS"},
    {"VulnerabilityID": "CVE-2099-0001", "PkgName": "oldlib", "InstalledVersion": "1.0",
     "Severity": "LOW", "Title": "no fix yet"},
]}]}


def test_trivy_findings_carry_package_fields(monkeypatch, tmp_path):
    monkeypatch.setattr(unified_scan, "run_tool", lambda *a, **k: (True, json.dumps(TRIVY_OUT), ""))
    findings, meta = unified_scan.scan_trivy(tmp_path)
    assert meta["error"] is None
    d = [f.to_dict() for f in findings]
    assert [(x["package"], x["installed_version"], x["fixed_version"]) for x in d] == [
        ("flask", "0.12.2", "2.2.5, 2.3.2"), ("flask", "0.12.2", "0.12.3"), ("oldlib", "1.0", None),
    ]


def test_other_tools_have_no_package_fields():
    f = unified_scan.Finding(tool="bearer", severity="high", rule_id="r", title="t")
    assert f.to_dict()["package"] is None and f.to_dict()["fixed_version"] is None
