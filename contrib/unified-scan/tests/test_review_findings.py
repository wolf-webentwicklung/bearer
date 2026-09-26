"""Regression tests for the review of the gvintra integration: findings must not be switched
off by folder names, a broken .git, nested archives, renamed Office files or a broken manifest."""
import io
import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import http_wrapper  # noqa: E402
import unified_scan  # noqa: E402
from unified_scan import Finding  # noqa: E402

OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'


def _zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


# --- score exclusion (H1) -------------------------------------------------------------------

@pytest.mark.parametrize('path', ['build/app.py', 'dist/app.js', 'vendor/lib/x.py',
                                  'examples/run.py', 'node_modules/a/index.js', '.venv/x.py'])
def test_shipped_code_folders_are_not_excluded(path):
    assert not Finding(tool='bearer', severity='high', rule_id='r', title='t', file=path).excluded_from_score


@pytest.mark.parametrize('path', ['tests/test_app.py', 'src/__tests__/a.js', 'test_app.py',
                                  'pkg/app_test.go', 'web/app.spec.ts', 'fixtures/data.py'])
def test_real_test_paths_are_excluded_for_non_critical(path):
    assert Finding(tool='bearer', severity='high', rule_id='r', title='t', file=path).excluded_from_score


@pytest.mark.parametrize('severity,category', [
    ('critical', 'security'), ('high', 'secret'), ('high', 'malware'),
    ('medium', 'malicious-package'), ('high', 'unscannable'),
])
def test_never_excluded_even_in_test_paths(severity, category):
    f = Finding(tool='x', severity=severity, rule_id='r', title='t',
                file='tests/test_app.py', category=category)
    assert not f.excluded_from_score
    unified_scan._relativize_findings([f], Path('/nonexistent'))
    assert not f.excluded_from_score


# --- exit codes (H2) ------------------------------------------------------------------------

def test_run_tool_non_zero_exit_is_a_failure(tmp_path):
    ok, _out, err = unified_scan.run_tool('sh', ['sh', '-c', 'echo boom >&2; exit 3'], cwd=tmp_path)
    assert not ok and 'exit 3' in err and 'boom' in err


def test_run_tool_olevba_keeps_output_on_non_zero_exit(tmp_path, monkeypatch):
    fake = tmp_path / 'olevba'
    fake.write_text('#!/bin/sh\necho "[]"\nexit 8\n')
    fake.chmod(0o755)
    monkeypatch.setenv('PATH', str(tmp_path))
    ok, out, _err = unified_scan.run_tool('olevba', ['olevba'], cwd=tmp_path)
    assert ok and out.strip() == '[]'


def test_bearer_and_checkov_exit_zero_despite_findings(tmp_path, monkeypatch):
    cmds = []
    monkeypatch.delenv('BEARER_DISABLE_DEFAULT_RULES', raising=False)
    monkeypatch.setattr(unified_scan, 'run_tool', lambda name, cmd, cwd, timeout=900:
                        (cmds.append(cmd), (True, '[]', ''))[1])
    unified_scan.scan_bearer(tmp_path, tmp_path / 'b.json')
    unified_scan.scan_checkov(tmp_path)
    assert cmds[0][-2:] == ['--exit-code', '0']
    assert '--soft-fail' in cmds[1]


# --- trufflehog modes (H2) ------------------------------------------------------------------

def _record_tools(monkeypatch, fail=()):
    """Fake scanners, but real git (for _has_git_history)."""
    calls = []
    real = unified_scan.run_tool

    def run_tool(name, cmd, cwd, timeout=900):
        if cmd[0] == 'git':
            return real(name, cmd, cwd, timeout)
        calls.append(cmd)
        if cmd[1] in fail:
            return False, '', f'{name} exit 1: broken'
        return True, '', ''
    monkeypatch.setattr(unified_scan, 'run_tool', run_tool)
    return calls


@pytest.mark.parametrize('git_content', ['file', 'empty-dir', 'garbage-dir'])
def test_trufflehog_broken_git_still_scans_filesystem(tmp_path, monkeypatch, git_content):
    if git_content == 'file':
        (tmp_path / '.git').write_text('gitdir: /nonexistent')
    else:
        (tmp_path / '.git').mkdir()
        if git_content == 'garbage-dir':
            (tmp_path / '.git' / 'HEAD').write_text('garbage')
    calls = _record_tools(monkeypatch)
    _findings, meta = unified_scan.scan_trufflehog(tmp_path)
    assert [c[1] for c in calls] == ['filesystem']
    assert meta['mode'] == 'filesystem' and not meta['error']


def test_trufflehog_valid_repo_scans_filesystem_and_history(tmp_path, monkeypatch):
    if not unified_scan.shutil.which('git'):
        pytest.skip('git not installed')
    env = {'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.invalid',
           'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@example.invalid', 'PATH': '/usr/bin:/bin'}
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True, env=env)
    (tmp_path / 'a.py').write_text('x = 1')
    subprocess.run(['git', '-C', str(tmp_path), 'add', '.'], check=True, env=env)
    subprocess.run(['git', '-C', str(tmp_path), 'commit', '-qm', 'i'], check=True, env=env)
    calls = _record_tools(monkeypatch)
    _findings, meta = unified_scan.scan_trufflehog(tmp_path)
    assert [c[1] for c in calls] == ['filesystem', 'git']
    assert meta['mode'] == 'filesystem+git-history'


def test_trufflehog_filesystem_failure_is_an_error(tmp_path, monkeypatch):
    _record_tools(monkeypatch, fail=('filesystem',))
    findings, meta = unified_scan.scan_trufflehog(tmp_path)
    assert findings == [] and 'exit 1' in meta['error']


def test_trufflehog_dedupes_secret_found_in_both_modes():
    line = json.dumps({'SourceMetadata': {'Data': {'Filesystem': {'file': 'a.py', 'line': 1}}},
                       'DetectorName': 'AWS', 'Raw': 'AKIAIOSFODNN7EXAMPLE'})
    fs = unified_scan._parse_trufflehog_ndjson(line, git_mode=False)
    assert len(unified_scan._dedupe_secrets(fs + fs)) == 1


# --- nested archives (H3) -------------------------------------------------------------------

def test_nested_archives_by_extension_and_magic(tmp_path):
    (tmp_path / 'proj').mkdir()
    (tmp_path / 'proj/payload.zip').write_bytes(_zip_bytes([('a.py', 'x')]))
    (tmp_path / 'proj/renamed.dat').write_bytes(_zip_bytes([('a.py', 'x')]))
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode='w:gz') as tf:
        data = b'x'
        info = tarfile.TarInfo('a.py')
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    (tmp_path / 'proj/lib.bin').write_bytes(tar_buf.getvalue())
    (tmp_path / 'proj/report.xlsx').write_bytes(
        _zip_bytes([('[Content_Types].xml', '<x/>'), ('xl/workbook.xml', '<x/>')]))
    (tmp_path / 'proj/main.py').write_text('print(1)')
    (tmp_path / '.git').mkdir()
    (tmp_path / '.git/pack.zip').write_bytes(_zip_bytes([('a', 'x')]))

    findings, meta = unified_scan.scan_nested_archives(tmp_path)
    files = sorted(f.file for f in findings)
    assert files == ['proj/lib.bin', 'proj/payload.zip', 'proj/renamed.dat']
    assert all(f.severity == 'critical' and f.category == 'unscannable'
               and f.rule_id == 'nested-archive' and not f.excluded_from_score for f in findings)
    assert meta['finding_count'] == 3


def test_main_nested_archive_does_not_trip_malware_gate(tmp_path, monkeypatch):
    empty = tmp_path / 'bin'
    empty.mkdir()
    monkeypatch.setenv('PATH', str(empty))
    outer = tmp_path / 'tool.zip'
    outer.write_bytes(_zip_bytes([('src/inner.zip', _zip_bytes([('evil.py', 'x')])),
                                  ('src/main.py', 'print(1)')]))
    out = tmp_path / 'report'
    monkeypatch.setattr(sys, 'argv', ['unified_scan.py', str(outer), '--out', str(out)])
    assert unified_scan.main() == 1
    report = json.loads((out / 'combined_report.json').read_text())
    assert report['gate_passed'] is True
    nested = [f for f in report['employee_findings'] if f['rule_id'] == 'nested-archive']
    assert [f['file'] for f in nested] == ['src/inner.zip']


# --- olevba (H3/M1) -------------------------------------------------------------------------

def test_office_files_found_by_content(tmp_path):
    (tmp_path / 'macro.bin').write_bytes(OLE_MAGIC + b'\x00' * 100)
    (tmp_path / 'sheet.dat').write_bytes(_zip_bytes([('[Content_Types].xml', '<x/>'),
                                                     ('xl/vbaProject.bin', 'x')]))
    (tmp_path / 'plain.xlsx').write_bytes(_zip_bytes([('[Content_Types].xml', '<x/>')]))
    (tmp_path / 'Invoice.DOCM').write_bytes(b'x')
    (tmp_path / 'notes.txt').write_text('hello')
    found = sorted(p.name for p in unified_scan._find_office_macro_files(tmp_path))
    assert found == ['Invoice.DOCM', 'macro.bin', 'sheet.dat']


def test_olevba_crash_blocks_as_unscannable(tmp_path, monkeypatch):
    (tmp_path / 'm.xlsm').write_bytes(b'x')
    monkeypatch.setattr(unified_scan.shutil, 'which', lambda name: '/bin/' + name)
    crash = json.dumps([{'type': 'MetaInformation'},
                        {'type': 'msg', 'level': 'ERROR', 'msg': 'Unhandled exception'}])
    monkeypatch.setattr(unified_scan, 'run_tool', lambda name, cmd, cwd, timeout=900: (True, crash, ''))
    findings, meta = unified_scan.scan_olevba(tmp_path)
    assert [(f.rule_id, f.file, f.severity, f.category) for f in findings] == [
        ('unscannable.office-file', 'm.xlsm', 'critical', 'unscannable')]
    assert 'm.xlsm' in meta['file_errors']


def test_olevba_empty_output_blocks(tmp_path, monkeypatch):
    (tmp_path / 'm.doc').write_bytes(b'x')
    monkeypatch.setattr(unified_scan.shutil, 'which', lambda name: '/bin/' + name)
    monkeypatch.setattr(unified_scan, 'run_tool', lambda name, cmd, cwd, timeout=900: (True, '', 'died'))
    findings, _meta = unified_scan.scan_olevba(tmp_path)
    assert [f.rule_id for f in findings] == ['unscannable.office-file']


# --- guarddog manifest errors (M1) ----------------------------------------------------------

def _fake_guarddog(monkeypatch, results, control_ok=True):
    """results per ecosystem for the upload; the control run (temp dir with a known-good
    manifest) succeeds or fails depending on control_ok."""
    monkeypatch.setattr(unified_scan.shutil, 'which', lambda name: '/bin/' + name)
    monkeypatch.setattr(unified_scan, '_guarddog_control_cache', {})

    def run_tool(name, cmd, cwd, timeout=900):
        if 'unified-scan-guarddog-control-' in cmd[-1]:
            return (True, '[]', '') if control_ok else (False, '', 'guarddog exit 1: ConnectionError')
        return results[cmd[1]]
    monkeypatch.setattr(unified_scan, 'run_tool', run_tool)


def test_guarddog_broken_package_json_blocks(tmp_path, monkeypatch):
    (tmp_path / 'web').mkdir()
    (tmp_path / 'web/package.json').write_text('{"dependencies": ')
    _fake_guarddog(monkeypatch, {'pypi': (True, '[]', ''),
                                 'npm': (False, '', 'guarddog exit 1: JSONDecodeError in web/package.json')})
    findings, meta = unified_scan.scan_guarddog(tmp_path)
    assert [(f.rule_id, f.file, f.category, f.severity) for f in findings] == [
        ('unscannable.manifest', 'web/package.json', 'unscannable', 'critical')]
    assert 'npm' not in (meta.get('ecosystem_errors') or {})


def test_guarddog_manifest_parse_error_blocks(tmp_path, monkeypatch):
    (tmp_path / 'requirements.txt').write_text('flask==\x00\n')
    _fake_guarddog(monkeypatch, {'pypi': (False, '', 'guarddog exit 1: InvalidRequirement: flask=='),
                                 'npm': (True, '[]', '')})
    findings, _meta = unified_scan.scan_guarddog(tmp_path)
    assert [(f.rule_id, f.file) for f in findings] == [('unscannable.manifest', 'requirements.txt')]


def test_guarddog_network_error_is_only_a_note(tmp_path, monkeypatch):
    (tmp_path / 'requirements.txt').write_text('flask==2.0.0\n')
    _fake_guarddog(monkeypatch, {
        'pypi': (False, '', "guarddog exit 1: ProxyError('Unable to connect to proxy')"),
        'npm': (True, '[]', '')}, control_ok=False)
    findings, meta = unified_scan.scan_guarddog(tmp_path)
    assert findings == []
    assert 'ProxyError' in meta['ecosystem_errors']['pypi']


def test_guarddog_error_text_cannot_fake_a_network_problem(tmp_path, monkeypatch):
    """The upload controls the error text (e.g. an invalid requirement echoed back) - only the
    control run decides whether it's infrastructure."""
    (tmp_path / 'requirements.txt').write_text('ConnectionError timed out 403==x\n')
    _fake_guarddog(monkeypatch, {
        'pypi': (False, '', 'guarddog exit 1: InvalidRequirement: ConnectionError timed out 403==x'),
        'npm': (True, '[]', '')}, control_ok=True)
    findings, _meta = unified_scan.scan_guarddog(tmp_path)
    assert [f.rule_id for f in findings] == ['unscannable.manifest']


def test_guarddog_error_without_manifest_is_only_a_note(tmp_path, monkeypatch):
    _fake_guarddog(monkeypatch, {'pypi': (False, '', 'guarddog exit 1: weird'), 'npm': (True, '[]', '')})
    findings, meta = unified_scan.scan_guarddog(tmp_path)
    assert findings == [] and 'pypi' in meta['ecosystem_errors']


def test_unscannable_manifest_does_not_skip_security_scan(tmp_path, monkeypatch):
    """Malware gate stops the pipeline only for real malware, not for a broken manifest."""
    (tmp_path / 'package.json').write_text('not json')
    monkeypatch.setattr(unified_scan, 'scan_guarddog',
                        lambda t: ([unified_scan._unscannable_manifest('package.json', 'x')], {}))
    ran = []
    for name in ('scan_bearer', 'scan_trufflehog', 'scan_trivy', 'scan_trivy_docker_images',
                 'scan_checkov', 'scan_olevba'):
        monkeypatch.setattr(unified_scan, name, lambda *a, n=name: (ran.append(n), ([], {}))[1])
    monkeypatch.setattr(sys, 'argv', ['unified_scan.py', str(tmp_path), '--out', str(tmp_path / 'r')])
    unified_scan.main()
    report = json.loads((tmp_path / 'r/combined_report.json').read_text())
    assert report['gate_passed'] is True and len(ran) == 6


def test_failed_malware_gate_still_runs_all_tools(tmp_path, monkeypatch):
    """A critical malware finding fails the gate, but every other tool still runs so the
    uploader sees all problems at once."""
    evil = unified_scan.Finding(tool='guarddog', severity='critical', rule_id='threat-x',
                                title='bad', file='pypi:evilpkg', category='malware')
    monkeypatch.setattr(unified_scan, 'scan_guarddog', lambda t: ([evil], {}))
    monkeypatch.setattr(unified_scan, 'load_guarddog_policy', lambda: {})
    ran = []
    for name in ('scan_bearer', 'scan_trufflehog', 'scan_trivy', 'scan_trivy_docker_images',
                 'scan_checkov', 'scan_olevba'):
        monkeypatch.setattr(unified_scan, name, lambda *a, n=name: (ran.append(n), ([], {}))[1])
    monkeypatch.setattr(sys, 'argv', ['unified_scan.py', str(tmp_path), '--out', str(tmp_path / 'r')])
    assert unified_scan.main() == 1
    report = json.loads((tmp_path / 'r/combined_report.json').read_text())
    assert report['gate_passed'] is False and len(ran) == 6
    assert report['internal_criticality']['by_severity']['critical'] == 1
    assert [f['rule_id'] for f in report['employee_findings']] == ['threat-x']


# --- wrapper priority (M2) ------------------------------------------------------------------

def test_wrapper_runs_scan_with_low_priority(tmp_path, monkeypatch):
    monkeypatch.setattr(http_wrapper.shutil, 'which', lambda name: '/usr/bin/' + name)
    cmd = http_wrapper.scan_command(tmp_path / 'a.zip', tmp_path / 'out')
    assert cmd[:6] == ['nice', '-n', '10', 'ionice', '-c', '3']
    assert cmd[-3:] == [str(tmp_path / 'a.zip'), '--out', str(tmp_path / 'out')]
