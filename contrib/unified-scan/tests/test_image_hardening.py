import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unified_scan  # noqa: E402


def _fake_bearer(monkeypatch, out='', err='', report=None):
    def run_tool(name, cmd, cwd, timeout=900):
        if report is not None:
            Path(cmd[cmd.index('--output') + 1]).write_text(json.dumps(report))
        return True, out, err
    monkeypatch.setattr(unified_scan, 'run_tool', run_tool)


def test_bearer_zero_rules_is_an_error_not_a_clean_result(tmp_path, monkeypatch):
    monkeypatch.delenv('BEARER_DISABLE_DEFAULT_RULES', raising=False)
    _fake_bearer(monkeypatch, err='Error: 0 rules found for supported language, default rules '
                                  'could not be downloaded or possibly disabled', report={})
    findings, meta = unified_scan.scan_bearer(tmp_path, tmp_path / 'b.json')
    assert findings == []
    assert 'without rules' in meta['error']


def test_bearer_zero_rules_banner_in_stdout(tmp_path, monkeypatch):
    monkeypatch.delenv('BEARER_DISABLE_DEFAULT_RULES', raising=False)
    _fake_bearer(monkeypatch, out='Zero rules found. A security report requires rules to function.',
                 report={})
    _, meta = unified_scan.scan_bearer(tmp_path, tmp_path / 'b.json')
    assert meta['error']


def test_bearer_preflight_disabled_defaults_without_rule_dir(tmp_path, monkeypatch):
    monkeypatch.setenv('BEARER_DISABLE_DEFAULT_RULES', 'true')
    monkeypatch.setenv('BEARER_EXTERNAL_RULE_DIR', str(tmp_path / 'nope'))
    called = []
    monkeypatch.setattr(unified_scan, 'run_tool', lambda *a, **k: called.append(1))
    _, meta = unified_scan.scan_bearer(tmp_path, tmp_path / 'b.json')
    assert 'external rule dir missing' in meta['error'] and not called

    empty = tmp_path / 'rules'
    empty.mkdir()
    monkeypatch.setenv('BEARER_EXTERNAL_RULE_DIR', str(empty))
    _, meta = unified_scan.scan_bearer(tmp_path, tmp_path / 'b.json')
    assert 'no rules' in meta['error']


def test_bearer_with_rules_and_findings_summarizes_description(tmp_path, monkeypatch):
    rules = tmp_path / 'rules' / 'python'
    rules.mkdir(parents=True)
    (rules / 'r.yml').write_text('x: 1')
    monkeypatch.setenv('BEARER_DISABLE_DEFAULT_RULES', 'true')
    monkeypatch.setenv('BEARER_EXTERNAL_RULE_DIR', str(tmp_path / 'rules'))
    desc = ('## Description\n\nUsing **unsanitized** input in a `SQL` query '
            'leads to [SQL injection](https://owasp.org).\n\n## Remediations\n\n- Use params\n')
    _fake_bearer(monkeypatch, report={'high': [{
        'rule_id': 'python_lang_sql_injection', 'title': 'SQL injection', 'filename': 'a.py',
        'source': {'start': 3}, 'description': desc}]})
    findings, meta = unified_scan.scan_bearer(tmp_path, tmp_path / 'b.json')
    assert meta['error'] is None
    assert findings[0].description == 'Using unsanitized input in a SQL query leads to SQL injection.'
    assert findings[0].raw['description'] == desc


def test_plain_summary_edge_cases():
    assert unified_scan._plain_summary('') == ''
    assert unified_scan._plain_summary('just text') == 'just text'
    assert unified_scan._plain_summary('# Only heading') == '# Only heading'
    assert len(unified_scan._plain_summary('a' * 2000)) == 500


def test_trufflehog_never_verifies_live(tmp_path, monkeypatch):
    cmds = []
    monkeypatch.setattr(unified_scan, 'run_tool', lambda name, cmd, cwd, timeout=900:
                        (cmds.append(cmd), (True, '', ''))[1])
    for git_mode in (False, True):
        monkeypatch.setattr(unified_scan, '_has_git_history', lambda p, g=git_mode: g)
        unified_scan.scan_trufflehog(tmp_path)
    # filesystem, then filesystem + git history
    assert len(cmds) == 3 and all('--no-verification' in c for c in cmds)


def test_guarddog_3x_risk_objects_are_readable():
    risk = {
        'name': 'risk.runtime.obfuscation', 'severity': 'medium',
        'threat_rule': 'threat-runtime-obfuscation-general',
        'threat_description': 'Detects heavy code obfuscation techniques',
        'threat_location': 'BeautifulSoupTests.py:793',
        'threat_code': '...\\xe3\\x81\\xa7...', 'threat_match': '\\xe3\\x81\\xa7',
    }
    out = json.dumps([{'dependency': 'beautifulsoup', 'version': '3.2.2', 'result': {
        'risk_score': {'label': 'suspicious', 'score': 6.3}, 'risks': [risk]}}])
    findings, err = unified_scan._parse_guarddog_json(out, 'pypi')
    assert err is None
    f = findings[0]
    assert f.rule_id == 'threat-runtime-obfuscation-general'
    assert f.description == ('GuardDog-Score 6.3. Detects heavy code obfuscation techniques '
                             '(BeautifulSoupTests.py:793) [medium]')
    assert '\\x' not in f.description and '{' not in f.description


def test_dockerfile_ships_hardening():
    df = (Path(__file__).resolve().parent.parent / 'Dockerfile').read_text()
    for needle in ('oletools==', 'BEARER_EXTERNAL_RULE_DIR=/opt/bearer-rules',
                   'BEARER_DISABLE_DEFAULT_RULES=true',
                   'GUARDDOG_TOP_PACKAGES_CACHE_LOCATION=/tmp/guarddog-cache',
                   'entrypoint.sh'):
        assert needle in df


def test_entrypoint_seeds_guarddog_cache_without_importing_guarddog(tmp_path):
    # Importing guarddog loads its typosquatting detectors, which crash while the cache is
    # still empty - the seed must locate the bundled lists by path only.
    import subprocess

    src = (Path(__file__).resolve().parent.parent / 'entrypoint.sh').read_text()
    code = [l for l in src.splitlines() if not l.lstrip().startswith('#')]
    assert not any('import guarddog' in l for l in code)

    res = tmp_path / 'venvs/guarddog/lib/python3.12/site-packages/guarddog/analyzer/metadata/resources'
    res.mkdir(parents=True)
    (res / 'top_pypi_packages.json').write_text('[]')
    (res / 'top_go_packages.json').write_text('[]')
    script = tmp_path / 'entrypoint.sh'
    script.write_text(src.replace('/opt/venvs', str(tmp_path / 'venvs'))
                         .replace('exec python /opt/unified-scan/http_wrapper.py', 'exit 0'))
    cache = tmp_path / 'cache'
    subprocess.run(['sh', str(script)], check=True,
                   env={'PATH': '/usr/bin:/bin', 'GUARDDOG_TOP_PACKAGES_CACHE_LOCATION': str(cache)})
    assert sorted(p.name for p in cache.iterdir()) == ['top_go_packages.json', 'top_pypi_packages.json']
