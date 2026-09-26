import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unified_scan  # noqa: E402
from safe_extract import ArchiveRejected  # noqa: E402
from unified_scan import Finding, _relative_file, _relativize_findings, resolve_target  # noqa: E402


def _zip(path, entries):
    with zipfile.ZipFile(path, 'w') as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return path


@pytest.fixture
def no_tools(tmp_path, monkeypatch):
    """No scanner binaries in PATH - every tool is skipped, as documented."""
    empty = tmp_path / 'empty-bin'
    empty.mkdir()
    monkeypatch.setenv('PATH', str(empty))


def test_resolve_target_extracts_archive_and_cleans_up(tmp_path):
    archive = _zip(tmp_path / 'tool.zip', [('src/main.py', 'print(1)')])
    target, handle, kind = resolve_target(str(archive))
    try:
        assert kind == 'archive'
        assert (target / 'src/main.py').read_text() == 'print(1)'
    finally:
        handle.cleanup()
    assert not target.exists()


def test_resolve_target_7z(tmp_path):
    py7zr = pytest.importorskip('py7zr')
    (tmp_path / 'm.py').write_text('x = 1')
    archive = tmp_path / 'tool.7z'
    with py7zr.SevenZipFile(archive, 'w') as z:
        z.write(tmp_path / 'm.py', 'pkg/m.py')
    target, handle, kind = resolve_target(str(archive))
    try:
        assert (target / 'pkg/m.py').exists()
    finally:
        handle.cleanup()


def test_resolve_target_rejects_unsafe_archive_without_leftovers(tmp_path, monkeypatch):
    monkeypatch.setattr(unified_scan.tempfile, 'tempdir', str(tmp_path / 'tmp'))
    (tmp_path / 'tmp').mkdir()
    archive = _zip(tmp_path / 'evil.zip', [('../evil.py', 'x')])
    with pytest.raises(ArchiveRejected):
        resolve_target(str(archive))
    assert list((tmp_path / 'tmp').iterdir()) == []


def test_untrusted_git_metadata_is_neutralized(tmp_path):
    config = (
        '[core]\n\trepositoryformatversion = 0\n\tfsmonitor = sh -c "id > /tmp/pwned"\n'
        '\tbare = false\n[core] hooksPath = /tmp/hooks\n[include]\n\tpath = /etc/gitconfig\n'
        '[filter "x"]\n\tsmudge = evil\n[extensions]\n\tobjectformat = sha1\n\tworktreeconfig = true\n'
    )
    archive = _zip(tmp_path / 'repo.zip', [
        ('.git/config', config),
        ('.git/hooks/post-checkout', '#!/bin/sh\nid\n'),
        ('.git/objects/info/alternates', '/etc\n'),
        ('.git/HEAD', 'ref: refs/heads/main\n'),
        ('sub/.git', 'gitdir: /etc\n'),
        ('main.py', 'print(1)'),
    ])
    target, handle, _kind = resolve_target(str(archive))
    try:
        cleaned = (target / '.git/config').read_text()
        assert 'fsmonitor' not in cleaned and 'hooksPath' not in cleaned
        assert 'include' not in cleaned and 'filter' not in cleaned and 'worktreeconfig' not in cleaned
        assert 'repositoryformatversion = 0' in cleaned and 'objectformat = sha1' in cleaned
        assert not (target / '.git/hooks').exists()
        assert not (target / '.git/objects/info/alternates').exists()
        assert not (target / 'sub/.git').exists()
        assert (target / '.git/HEAD').exists()
    finally:
        handle.cleanup()


def test_git_env_hardened_for_archives(tmp_path, monkeypatch):
    for key in ('GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0',
                'GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1', 'GIT_CONFIG_NOSYSTEM',
                'GIT_CEILING_DIRECTORIES'):
        monkeypatch.delenv(key, raising=False)
    archive = _zip(tmp_path / 'tool.zip', [('a.py', 'x')])
    _target, handle, _kind = resolve_target(str(archive))
    handle.cleanup()
    import os
    pairs = {os.environ[f'GIT_CONFIG_KEY_{i}']: os.environ[f'GIT_CONFIG_VALUE_{i}']
             for i in range(int(os.environ['GIT_CONFIG_COUNT']))}
    assert pairs == {'core.fsmonitor': 'false', 'core.hooksPath': '/dev/null'}


@pytest.mark.parametrize('raw,expected', [
    ('{root}/src/app.py', 'src/app.py'),
    ('file://{root}/src/app.py', 'src/app.py'),
    ('/Dockerfile', 'Dockerfile'),          # checkov style
    ('./requirements.txt', 'requirements.txt'),
    ('requirements.txt', 'requirements.txt'),
    ('pypi:requests', 'pypi:requests'),     # guarddog fallback, not a path
    (None, None),
])
def test_relative_file(tmp_path, raw, expected):
    (tmp_path / 'Dockerfile').write_text('FROM scratch')
    if raw:
        raw = raw.format(root=tmp_path)
    assert _relative_file(raw, tmp_path) == expected


def test_relativize_recomputes_noise_flag(tmp_path):
    # An absolute temp path containing e.g. /tests/ must not mark real code as test code.
    root = tmp_path / 'tests' / 'src'
    root.mkdir(parents=True)
    f = Finding(tool='bearer', severity='high', rule_id='r', title='t', file=str(root / 'app.py'))
    assert f.excluded_from_score
    _relativize_findings([f], root)
    assert f.file == 'app.py' and not f.excluded_from_score


def test_main_exit_code_3_for_rejected_archive(tmp_path, monkeypatch, capsys):
    archive = _zip(tmp_path / 'evil.zip', [('/etc/passwd', 'x')])
    monkeypatch.setattr(sys, 'argv', ['unified_scan.py', str(archive), '--out', str(tmp_path / 'r')])
    assert unified_scan.main() == 3
    assert 'Archiv abgelehnt: ' in capsys.readouterr().err


def test_main_on_archive_without_tools(tmp_path, monkeypatch, no_tools):
    archive = _zip(tmp_path / 'tool.zip', [('main.py', 'print(1)')])
    out = tmp_path / 'r'
    monkeypatch.setattr(sys, 'argv', ['unified_scan.py', str(archive), '--out', str(out)])
    assert unified_scan.main() == 0
    report = json.loads((out / 'combined_report.json').read_text())
    assert report['source_kind'] == 'archive'
    assert report['employee_findings'] == []
    assert report['tools']['guarddog']['error']


def test_guarddog_finding_location_is_stable():
    out = json.dumps([{
        'dependency': 'reqeusts', 'version': '1.0',
        'result': {'path': '/tmp/tmpabc123/reqeusts', 'risk_score': {'label': 'high_risk', 'score': 9},
                   'risks': [{'rule_id': 'typosquatting', 'message': 'looks like requests'}]},
    }])
    findings, err = unified_scan._parse_guarddog_json(out, 'pypi')
    assert err is None
    assert findings[0].file == 'pypi:reqeusts' and findings[0].severity == 'critical'
