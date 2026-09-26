import io
import stat
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import safe_extract  # noqa: E402
from safe_extract import ArchiveRejected, safe_extract as extract  # noqa: E402


def _zip(tmp_path, entries, name='a.zip'):
    path = tmp_path / name
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for entry in entries:
            if isinstance(entry, zipfile.ZipInfo):
                zf.writestr(entry, b'x')
            else:
                zf.writestr(entry[0], entry[1])
    return path


def test_normal_zip(tmp_path):
    archive = _zip(tmp_path, [('src/main.py', b'print(1)'), ('README.md', b'hi')])
    extract(archive, tmp_path / 'out', 'tool.zip')
    assert (tmp_path / 'out/src/main.py').read_bytes() == b'print(1)'


@pytest.mark.parametrize('name', ['../evil.py', 'a/../../evil.py', '/etc/evil', 'C:/evil', '..\\evil.py'])
def test_path_traversal_rejected(tmp_path, name):
    archive = _zip(tmp_path, [(name, b'x')])
    with pytest.raises(ArchiveRejected):
        extract(archive, tmp_path / 'out', 'tool.zip')
    assert not (tmp_path / 'evil.py').exists()


def test_symlink_rejected(tmp_path):
    info = zipfile.ZipInfo('link')
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    archive = _zip(tmp_path, [info])
    with pytest.raises(ArchiveRejected, match='Symlinks'):
        extract(archive, tmp_path / 'out', 'tool.zip')


def test_zip_bomb_rejected_while_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(safe_extract, 'MAX_FILE_BYTES', 1024)
    archive = _zip(tmp_path, [('big.txt', b'0' * 10_000)])
    with pytest.raises(ArchiveRejected, match='zu groß'):
        extract(archive, tmp_path / 'out', 'tool.zip')


def test_total_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(safe_extract, 'MAX_TOTAL_BYTES', 1500)
    archive = _zip(tmp_path, [(f'f{i}.txt', b'0' * 1000) for i in range(3)])
    with pytest.raises(ArchiveRejected, match='zu groß'):
        extract(archive, tmp_path / 'out', 'tool.zip')


def test_too_many_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(safe_extract, 'MAX_ENTRIES', 2)
    archive = _zip(tmp_path, [(f'f{i}', b'x') for i in range(3)])
    with pytest.raises(ArchiveRejected, match='zu viele'):
        extract(archive, tmp_path / 'out', 'tool.zip')


def test_encrypted_flag_rejected(tmp_path):
    archive = _zip(tmp_path, [('secret.txt', b'x')])
    # zipfile can't write encrypted entries - set the "encrypted" flag bit in both headers.
    data = bytearray(archive.read_bytes())
    for sig, offset in ((b'PK\x03\x04', 6), (b'PK\x01\x02', 8)):
        pos = data.index(sig) + offset
        data[pos] |= 0x1
    archive.write_bytes(bytes(data))
    with pytest.raises(ArchiveRejected, match='Passwort'):
        extract(archive, tmp_path / 'out', 'tool.zip')


def test_not_a_zip(tmp_path):
    path = tmp_path / 'a.zip'
    path.write_bytes(b'kein zip')
    with pytest.raises(ArchiveRejected):
        extract(path, tmp_path / 'out', 'tool.zip')


def test_duplicate_names_rejected(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('a.txt', b'1')
        zf.writestr('a.txt', b'2')
    path = tmp_path / 'dup.zip'
    path.write_bytes(buf.getvalue())
    with pytest.raises(ArchiveRejected):
        extract(path, tmp_path / 'out', 'tool.zip')


def test_7z_roundtrip_and_traversal(tmp_path):
    py7zr = pytest.importorskip('py7zr')
    good = tmp_path / 'g.7z'
    (tmp_path / 'm.py').write_text('print(1)')
    with py7zr.SevenZipFile(good, 'w') as z:
        z.write(tmp_path / 'm.py', 'src/m.py')
    extract(good, tmp_path / 'out', 'tool.7z')
    assert (tmp_path / 'out/src/m.py').exists()

    bad = tmp_path / 'b.7z'
    with py7zr.SevenZipFile(bad, 'w') as z:
        z.write(tmp_path / 'm.py', '../evil.py')
    with pytest.raises(ArchiveRejected):
        extract(bad, tmp_path / 'out2', 'tool.7z')


def test_other_extension_rejected(tmp_path):
    archive = _zip(tmp_path, [('a', b'x')])
    with pytest.raises(ArchiveRejected):
        extract(archive, tmp_path / 'out', 'tool.rar')


def _corrupt(path, needle, replacement):
    data = path.read_bytes()
    assert needle in data
    path.write_bytes(data.replace(needle, replacement, 1))


def test_bad_crc_rejected(tmp_path):
    archive = tmp_path / 'crc.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_STORED) as zf:
        zf.writestr('a.txt', b'hello world')
    _corrupt(archive, b'hello world', b'hellX world')
    with pytest.raises(ArchiveRejected):
        extract(archive, tmp_path / 'out', 'tool.zip')


def test_broken_deflate_stream_rejected(tmp_path):
    archive = tmp_path / 'deflate.zip'
    payload = bytes(range(256)) * 64
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('a.bin', payload)
    data = bytearray(archive.read_bytes())
    start = data.index(b'a.bin') + len(b'a.bin')
    for i in range(start, start + 40):
        data[i] ^= 0xFF
    archive.write_bytes(bytes(data))
    with pytest.raises(ArchiveRejected):
        extract(archive, tmp_path / 'out', 'tool.zip')


def test_deflate64_rejected(tmp_path):
    archive = _zip(tmp_path, [('a.txt', b'x')])
    # Compression method 9 (Deflate64) is not supported by zipfile -> NotImplementedError.
    data = bytearray(archive.read_bytes())
    for sig, offset in ((b'PK\x03\x04', 8), (b'PK\x01\x02', 10)):
        pos = data.index(sig) + offset
        data[pos:pos + 2] = (9).to_bytes(2, 'little')
    archive.write_bytes(bytes(data))
    with pytest.raises(ArchiveRejected, match='nicht unterstützt'):
        extract(archive, tmp_path / 'out', 'tool.zip')


def test_7z_bad_crc_rejected(tmp_path):
    py7zr = pytest.importorskip('py7zr')
    (tmp_path / 'm.txt').write_bytes(b'A' * 4096)
    archive = tmp_path / 'c.7z'
    with py7zr.SevenZipFile(archive, 'w', filters=[{'id': py7zr.FILTER_COPY}]) as z:
        z.write(tmp_path / 'm.txt', 'm.txt')
    _corrupt(archive, b'A' * 16, b'B' * 16)
    with pytest.raises(ArchiveRejected):
        extract(archive, tmp_path / 'out', 'tool.7z')


def test_extracted_files_lose_exec_bits(tmp_path):
    info = zipfile.ZipInfo('run.sh')
    info.external_attr = (stat.S_IFREG | 0o4777) << 16
    archive = tmp_path / 'x.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr(info, b'#!/bin/sh\n')
    extract(archive, tmp_path / 'out', 'tool.zip')
    assert stat.S_IMODE((tmp_path / 'out/run.sh').stat().st_mode) == 0o644
