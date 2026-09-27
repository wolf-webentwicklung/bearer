"""Findings of the independent final review: test-path exemption needs real test content,
camouflaged nested archives, code-injection line check, olevba severities/source files,
GuardDog categories and timeout, OSV malicious-package index, unpinned versions, coverage and
core_failed_tools."""
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import build_osv_index  # noqa: E402
import http_wrapper  # noqa: E402
import unified_scan  # noqa: E402
from unified_scan import Finding  # noqa: E402

from test_review_findings import _fake_guarddog  # noqa: E402


# --- M1: tests/ folder alone does not exempt ------------------------------------------------

def _finding(file, severity="high", category="security"):
    return Finding(tool="bearer", severity=severity, rule_id="python_lang_os_command_injection",
                   title="t", file=file, line=1, category=category)


@pytest.mark.parametrize("rel,content,exempt", [
    ("tests/helper.py", "import os\nos.system(cmd)\n", False),         # just a folder name
    ("tests/test_x.py", "import pytest\n\ndef test_a():\n    pass\n", True),
    ("tests/test_y.py", "from unittest import TestCase\n", True),
    ("spec/app.spec.js", "const x = require('child_process')\n", False),
    ("spec/app.spec.js", "import { describe, it } from 'vitest'\n", True),
    ("__tests__/a.test.ts", "describe('a', () => { it('b', () => {}) })\n", True),
    ("src/app.py", "import pytest\n", False),                            # not a test path
])
def test_test_exemption_needs_test_content(tmp_path, rel, content, exempt):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    f = _finding(rel)
    unified_scan.refine_test_exemption([f], tmp_path)
    assert f.excluded_from_score is exempt


def test_test_exemption_never_for_critical_or_secret(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_a.py").write_text("import pytest\n")
    crit = _finding("tests/test_a.py", severity="critical")
    secret = _finding("tests/test_a.py", category="secret")
    unified_scan.refine_test_exemption([crit, secret], tmp_path)
    assert not crit.excluded_from_score and not secret.excluded_from_score


# --- M2: nested archive dressed up as an Office document -------------------------------------

def _zip(path, entries):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries:
            zf.writestr(name, data)


def test_fake_content_types_zip_is_a_nested_archive(tmp_path):
    """The reviewer's repro: data.bin = ZIP with a dummy [Content_Types].xml and evil.py."""
    _zip(tmp_path / "data.bin", [("[Content_Types].xml", "<x/>"), ("evil.py", "import os\n")])
    findings, _ = unified_scan.scan_nested_archives(tmp_path)
    assert [f.rule_id for f in findings] == ["nested-archive"]


def test_fake_odf_mimetype_zip_is_a_nested_archive(tmp_path):
    _zip(tmp_path / "doc.odt", [("mimetype", "application/vnd.oasis.opendocument.text"),
                                ("content.xml", "<x/>"), ("run.ps1", "iex")])
    findings, _ = unified_scan.scan_nested_archives(tmp_path)
    assert [f.rule_id for f in findings] == ["nested-archive"]


def test_real_ooxml_and_odf_documents_are_not_archives(tmp_path):
    _zip(tmp_path / "report.xlsx", [("[Content_Types].xml", "<x/>"), ("xl/workbook.xml", "<x/>"),
                                    ("xl/embeddings/oleObject1.bin", "x")])
    _zip(tmp_path / "letter.odt", [("mimetype", "application/vnd.oasis.opendocument.text"),
                                   ("content.xml", "<x/>")])
    findings, _ = unified_scan.scan_nested_archives(tmp_path)
    assert findings == []


def test_content_types_without_main_part_is_an_archive(tmp_path):
    _zip(tmp_path / "x.docx", [("[Content_Types].xml", "<x/>"), ("readme.txt", "hi")])
    findings, _ = unified_scan.scan_nested_archives(tmp_path)
    assert [f.rule_id for f in findings] == ["nested-archive"]


# --- L2: code-injection line check ------------------------------------------------------------

@pytest.mark.parametrize("line,expected", [
    ("setattr(obj, field, value)\n", "high"),
    ("setattr(obj, name, importlib.import_module(mod))\n", "critical"),
    ("setattr(obj, n, __import__(m))\n", "critical"),
    ("setattr(o, k, os.execvp(p, a))\n", "critical"),
    ("setattr(o, k, globals()[name])\n", "critical"),
    ("fn = getattr(builtins, name); setattr(o, k, fn)\n", "critical"),
    ("setattr(o, k, os.spawnl(0, p))\n", "critical"),
])
def test_code_injection_downgrade_only_without_exec(tmp_path, line, expected):
    (tmp_path / "a.py").write_text(line)
    f = Finding(tool="bearer", severity="critical", rule_id="python_lang_code_injection",
                title="t", file="a.py", line=1, category="security")
    unified_scan.refine_code_injection([f], tmp_path)
    assert f.severity == expected


# --- olevba ---------------------------------------------------------------------------------

def _fake_olevba(monkeypatch, analysis):
    monkeypatch.setattr(unified_scan.shutil, "which", lambda name: "/bin/" + name)
    out = json.dumps([{"type": "OLE", "analysis": analysis}])
    monkeypatch.setattr(unified_scan, "run_tool", lambda *a, **k: (True, out, ""))


def test_olevba_scans_vba_source_files(tmp_path, monkeypatch):
    (tmp_path / "Modul1.bas").write_text('Sub A()\n  Shell "notepad.exe"\nEnd Sub\n')
    (tmp_path / "tool.vbs").write_text('CreateObject("WScript.Shell").Run "x"\n')
    assert [p.name for p in unified_scan._find_office_macro_files(tmp_path)] == ["Modul1.bas", "tool.vbs"]
    _fake_olevba(monkeypatch, [{"type": "Suspicious", "keyword": "Shell", "description": "May run"}])
    findings, _ = unified_scan.scan_olevba(tmp_path)
    assert {(f.file, f.severity, f.category) for f in findings} == {
        ("Modul1.bas", "high", "macro"), ("tool.vbs", "high", "macro")}
    assert findings[0].title == "Makro startet Programme: Shell"


def test_olevba_titles_are_german_and_file_type_correct(tmp_path, monkeypatch):
    (tmp_path / "Auswertung.xlsm").write_bytes(b"x")
    _fake_olevba(monkeypatch, [{"type": "AutoExec", "keyword": "Workbook_Open",
                                "description": "Runs when the Word document is opened"}])
    findings, _ = unified_scan.scan_olevba(tmp_path)
    assert findings[0].title == "Makro startet automatisch (Excel-Datei): Workbook_Open"
    assert "Word" not in findings[0].title + findings[0].description


def test_olevba_dropper_combination_is_critical(tmp_path, monkeypatch):
    (tmp_path / "invoice.docm").write_bytes(b"x")
    _fake_olevba(monkeypatch, [
        {"type": "AutoExec", "keyword": "AutoOpen"},
        {"type": "Suspicious", "keyword": "URLDownloadToFileA"},
        {"type": "Suspicious", "keyword": "Shell"},
    ])
    findings, _ = unified_scan.scan_olevba(tmp_path)
    combo = [f for f in findings if f.rule_id == "olevba.combo.autoexec_download_execute"]
    assert len(combo) == 1 and combo[0].severity == "critical" and combo[0].category == "malware"
    assert {f.severity for f in findings if f is not combo[0]} == {"high"}


def test_olevba_business_macro_without_download_is_justifiable(tmp_path, monkeypatch):
    """Opens, reads a REST API via XMLHTTP, runs a program: common - no dropper (nothing saved)."""
    (tmp_path / "tool.xlsm").write_bytes(b"x")
    _fake_olevba(monkeypatch, [{"type": "AutoExec", "keyword": "Workbook_Open"},
                               {"type": "Suspicious", "keyword": "MSXML2.XMLHTTP"},
                               {"type": "Suspicious", "keyword": "Run"},
                               {"type": "Suspicious", "keyword": "Shell"}])
    findings, _ = unified_scan.scan_olevba(tmp_path)
    assert "critical" not in {f.severity for f in findings}
    assert not any(f.category == "malware" for f in findings)


# --- GuardDog --------------------------------------------------------------------------------

def _gd_json(label, dep="nichepkg"):
    return json.dumps([{"dependency": dep, "version": "1.0",
                        "result": {"risk_score": {"label": label, "score": 5},
                                   "risks": [{"rule_id": "threat-x", "threat_description": "x"}]}}])


@pytest.mark.parametrize("label,severity,category", [
    ("high_risk", "critical", "malware"),
    ("suspicious", "high", "suspicious-package"),
    ("brand-new-label", "high", "malware"),  # unknown: fail closed, not justifiable
])
def test_guarddog_categories(label, severity, category):
    findings, err = unified_scan._parse_guarddog_json(_gd_json(label), "pypi")
    assert err is None
    assert (findings[0].severity, findings[0].category) == (severity, category)


def test_guarddog_timeout_is_a_tool_error_not_unscannable(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "1.0.0"}}')
    _fake_guarddog(monkeypatch, {"pypi": (True, "[]", ""),
                                 "npm": (False, "", "guarddog timed out after 240s")})
    findings, meta = unified_scan.scan_guarddog(tmp_path)
    assert findings == [] and meta["timed_out"] == ["npm"] and "npm" in meta["ecosystem_errors"]


def test_guarddog_infra_failure_is_marked(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("six==1.16.0\n")
    _fake_guarddog(monkeypatch, {"pypi": (False, "", "guarddog exit 1: x"), "npm": (True, "[]", "")},
                   control_ok=False)
    _findings, meta = unified_scan.scan_guarddog(tmp_path)
    assert meta["infra_errors"] == ["pypi"]


# --- OSV malicious-package index -------------------------------------------------------------

def _osv_zip(path, advisories):
    with zipfile.ZipFile(path, "w") as zf:
        for adv in advisories:
            zf.writestr(f"{adv['id']}.json", json.dumps(adv))


def _adv(id_, eco, name, versions=None, all_versions=False):
    affected = {"package": {"ecosystem": eco, "name": name}}
    if all_versions:
        affected["ranges"] = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
    if versions:
        affected["versions"] = versions
    return {"id": id_, "affected": [affected]}


@pytest.fixture
def osv_index(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _osv_zip(src / "PyPI.zip", [_adv("MAL-1", "PyPI", "Evil_Pkg", all_versions=True),
                                _adv("MAL-2", "PyPI", "num2words", versions=["0.5.15", "0.5.16"]),
                                {"id": "GHSA-x", "affected": [{"package": {"ecosystem": "PyPI", "name": "flask"}}]}])
    _osv_zip(src / "npm.zip", [_adv("MAL-3", "npm", "chalk", versions=["5.6.1"])])
    out = tmp_path / "idx.json"
    assert build_osv_index.main.__name__  # module importable
    sys_argv = sys.argv
    sys.argv = ["build_osv_index.py", str(out), "--source-dir", str(src)]
    try:
        assert build_osv_index.main() == 0
    finally:
        sys.argv = sys_argv
    return json.loads(out.read_text())


def test_osv_index_keeps_only_mal_entries(osv_index):
    assert set(osv_index["ecosystems"]["pypi"]) == {"evil-pkg", "num2words"}


def test_osv_matches(tmp_path, osv_index):
    (tmp_path / "requirements.txt").write_text(
        "evil-pkg\nnum2words==0.5.16\nflask==2.0.0\nnum2words>=0.5\n")
    (tmp_path / "package.json").write_text('{"dependencies": {"chalk": "^5.0.0"}}')
    (tmp_path / "package-lock.json").write_text(
        '{"packages": {"node_modules/chalk": {"version": "5.6.1"}}}')
    deps = unified_scan.collect_dependencies(tmp_path)
    findings, meta = unified_scan.scan_osv_malicious(tmp_path, deps, osv_index)
    got = sorted((f.file, f.severity, f.category, f.rule_id) for f in findings)
    assert got == [
        ("npm:chalk", "critical", "malware", "osv.malicious-package"),        # version from lockfile
        ("pypi:evil-pkg", "critical", "malware", "osv.malicious-package"),    # every version
        ("pypi:num2words", "critical", "malware", "osv.malicious-package"),   # pinned bad version
        ("pypi:num2words", "high", "suspicious-package", "osv.malicious-versions"),  # unpinned
    ]
    assert meta["ran"] and meta["error"] is None


def test_osv_safe_pinned_version_is_clean(tmp_path, osv_index):
    (tmp_path / "requirements.txt").write_text("num2words==0.5.13\n")
    findings, _ = unified_scan.scan_osv_malicious(tmp_path, unified_scan.collect_dependencies(tmp_path),
                                                  osv_index)
    assert findings == []


def test_osv_missing_index_is_a_tool_error(tmp_path, monkeypatch):
    monkeypatch.setattr(unified_scan, "OSV_INDEX_FILE", tmp_path / "nope.json")
    findings, meta = unified_scan.scan_osv_malicious(tmp_path, {"pypi": [], "npm": []})
    assert findings == [] and meta["error"]


# --- unpinned versions, coverage ---------------------------------------------------------------

def test_unpinned_dependencies_are_one_hint_per_manifest(tmp_path):
    (tmp_path / "requirements.txt").write_text("pandas\nrequests>=2\nflask==2.0.0\n-r other.txt\n")
    (tmp_path / "package.json").write_text('{"dependencies": {"left-pad": "1.3.0", "chalk": "^5"}}')
    hints = unified_scan.unpinned_dependency_hints(unified_scan.collect_dependencies(tmp_path))
    assert [(h.file, h.severity) for h in hints] == [("package.json", "low"), ("requirements.txt", "low")]
    assert "pandas, requests" in hints[1].description and "flask" not in hints[1].description
    assert "chalk" in hints[0].description and "left-pad" not in hints[0].description


def test_coverage_lists_unchecked_code_and_manifests(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/run.ps1").write_text("Get-Item")
    (tmp_path / "query.sql").write_text("select 1")
    (tmp_path / "app.py").write_text("print(1)")
    (tmp_path / "requirements.txt").write_text("pandas==2.0.0")
    (tmp_path / "node_modules/x").mkdir(parents=True)
    (tmp_path / "node_modules/x/a.sh").write_text("x")
    cov = unified_scan.coverage_report(tmp_path)
    assert cov == {"unscanned_files": ["query.sql", "scripts/run.ps1"], "unscanned_file_count": 2,
                   "dependency_manifests": ["requirements.txt"]}


# --- core_failed_tools --------------------------------------------------------------------------

def test_core_failed_tools():
    report = {"tools": {
        "bearer": {"error": "bearer exit 137"},
        "checkov": {"error": "boom"},                                  # not core
        "guarddog": {"ecosystem_errors": {"pypi": "net"}, "infra_errors": ["pypi"]},  # infra
        "trufflehog": {"error": None},
        "osv": {"error": "index missing"},
    }, "employee_findings": []}
    out = http_wrapper.annotate_report(report, "x.zip")
    assert out["failed_tools"] == ["bearer", "checkov", "guarddog", "osv"]
    assert out["core_failed_tools"] == ["bearer", "osv"]


def test_guarddog_file_caused_error_is_core():
    report = {"tools": {"guarddog": {"ecosystem_errors": {"npm": "timed out"}, "timed_out": ["npm"]}},
              "employee_findings": []}
    assert http_wrapper.annotate_report(report, "x.zip")["core_failed_tools"] == ["guarddog"]
