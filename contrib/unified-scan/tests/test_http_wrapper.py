import io
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import http_wrapper  # noqa: E402


def _zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.fixture
def server(tmp_path, monkeypatch):
    empty = tmp_path / 'empty-bin'
    empty.mkdir()
    monkeypatch.setenv('PATH', str(empty))  # no scanners: every tool is skipped
    workdir = tmp_path / 'work'
    workdir.mkdir()
    monkeypatch.setattr(http_wrapper, 'WORKDIR', workdir)
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), http_wrapper.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{httpd.server_address[1]}', workdir
    httpd.shutdown()


def _post(url, body, filename='tool.zip'):
    req = urllib.request.Request(f'{url}/scan', data=body, method='POST',
                                 headers={'X-Filename': filename})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_health(server):
    url, _ = server
    with urllib.request.urlopen(f'{url}/health') as resp:
        data = json.loads(resp.read())
    assert data['ok'] is True and 'bearer' in data['tools']


def test_clean_archive_returns_report_and_cleans_job(server):
    url, workdir = server
    status, report = _post(url, _zip_bytes([('main.py', 'print(1)')]), 'Mein Tool.zip')
    assert status == 200
    assert report['target'] == 'Mein Tool.zip'
    assert report['source_kind'] == 'archive'
    assert list(workdir.iterdir()) == []


def test_unsafe_archive_is_422_with_reason(server):
    url, workdir = server
    status, body = _post(url, _zip_bytes([('../evil.py', 'x')]))
    assert status == 422
    assert '..' in body['error']
    assert list(workdir.iterdir()) == []


def test_wrong_extension_is_422(server):
    url, _ = server
    status, body = _post(url, b'MZ...', 'tool.exe')
    assert status == 422 and '.zip' in body['error']


def test_filename_path_is_ignored(server):
    url, _ = server
    status, report = _post(url, _zip_bytes([('a.py', 'x')]), '../../etc/tool.zip')
    assert status == 200 and report['target'] == 'tool.zip'


def test_too_big_is_422(server, monkeypatch):
    url, _ = server
    monkeypatch.setattr(http_wrapper, 'MAX_UPLOAD_BYTES', 10)
    status, body = _post(url, _zip_bytes([('a.py', 'x' * 100)]))
    assert status == 422 and 'zu groß' in body['error']


def test_timeout_kills_whole_process_group(tmp_path, monkeypatch):
    pidfile = tmp_path / 'child.pid'
    fake = tmp_path / 'fake_scan.py'
    fake.write_text(
        'import subprocess, sys, time\n'
        f'p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])\n'
        f'open({str(pidfile)!r}, "w").write(str(p.pid))\n'
        'time.sleep(60)\n'
    )
    monkeypatch.setattr(http_wrapper, 'SCRIPT', fake)
    job = tmp_path / 'job'
    job.mkdir()
    with pytest.raises(http_wrapper.ScanError) as exc:
        http_wrapper.run_scan(job / 'upload.zip', 'x.zip', job, timeout=2)
    assert exc.value.status == 504
    child = int(pidfile.read_text())
    for _ in range(50):
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        pytest.fail('scanner grandchild survived the timeout')


def test_crash_without_report_is_500(tmp_path, monkeypatch):
    fake = tmp_path / 'fake_scan.py'
    fake.write_text('import sys; sys.stderr.write("boom\\n"); sys.exit(2)\n')
    monkeypatch.setattr(http_wrapper, 'SCRIPT', fake)
    with pytest.raises(http_wrapper.ScanError) as exc:
        http_wrapper.run_scan(tmp_path / 'upload.zip', 'x.zip', tmp_path, timeout=10)
    assert exc.value.status == 500 and 'boom' in str(exc.value)


def test_purge_stale_jobs(tmp_path):
    (tmp_path / 'unified-scan-job-old').mkdir()
    (tmp_path / 'unrelated').mkdir()
    http_wrapper.purge_stale_jobs(tmp_path)
    assert [p.name for p in tmp_path.iterdir()] == ['unrelated']


def test_annotate_report_flags_failed_tools_and_sanitizes():
    report = {
        'target': '/tmp/x/upload.zip',
        'tools': {
            'bearer': {'ran': True, 'error': None},
            'trivy': {'ran': False, 'error': 'trivy timed out after 600s'},
            'trivy_docker_images': {'ran': True, 'error': None, 'image_errors': {'python:3.9': 'no network'}},
            'guarddog': {'ran': True, 'error': None, 'ecosystem_errors': {}},
        },
        'employee_findings': [
            {'title': 'a\x00b', 'line': 12},
            {'title': 't', 'line': 10**12},
            {'title': 't', 'line': -1},
            {'title': 't', 'line': '7'},
            {'title': 't', 'line': True},
        ],
    }
    out = http_wrapper.annotate_report(report, 'tool.zip')
    assert out['target'] == 'tool.zip'
    assert out['incomplete'] is True
    assert out['failed_tools'] == ['trivy', 'trivy_docker_images']
    assert out['employee_findings'][0] == {'title': 'ab', 'line': 12}
    assert [f['line'] for f in out['employee_findings'][1:]] == [None, None, None, None]


def test_annotate_report_complete():
    out = http_wrapper.annotate_report({'tools': {'bearer': {'ran': True, 'error': None}},
                                        'employee_findings': []}, 'x.zip')
    assert out['incomplete'] is False and out['failed_tools'] == []


def test_health_answers_while_scan_runs(server, monkeypatch, tmp_path):
    url, _ = server
    fake = tmp_path / 'slow_scan.py'
    fake.write_text('import time; time.sleep(5)\n')
    monkeypatch.setattr(http_wrapper, 'SCRIPT', fake)
    t = threading.Thread(target=_post, args=(url, _zip_bytes([('a.py', 'x')])), daemon=True)
    t.start()
    time.sleep(0.5)
    started = time.monotonic()
    with urllib.request.urlopen(f'{url}/health', timeout=3) as resp:
        assert resp.status == 200
    assert time.monotonic() - started < 1


def test_broken_archive_via_http_is_422(server):
    url, _ = server
    data = bytearray(_zip_bytes([('a.txt', 'hello world')]))
    for sig, offset in ((b'PK\x03\x04', 8), (b'PK\x01\x02', 10)):
        pos = data.index(sig) + offset
        data[pos:pos + 2] = (9).to_bytes(2, 'little')
    status, body = _post(url, bytes(data))
    assert status == 422 and body['error']
