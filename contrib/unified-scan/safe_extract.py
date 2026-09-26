"""Safe extraction of .zip/.7z archives before scanning (unified_scan.py, http_wrapper.py).

Rejects path traversal, absolute paths, links, encrypted archives and zip bombs (entry count,
per-file and total size). ZIP sizes are counted while writing - header sizes are not trusted.
7z decompression is bounded by the header sizes checked up front, plus py7zr's own
max_extract_size as a second limit. Extracted files get plain 0644/0755 modes: nothing from
the archive keeps an executable or setuid bit.
"""
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath

MAX_ENTRIES = 5000
MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 200 * 1024 * 1024
CHUNK = 1024 * 1024


class ArchiveRejected(Exception):
    """User-facing reason (German) why the archive can't be scanned."""


def _safe_relpath(name: str) -> PurePosixPath:
    name = name.replace('\\', '/')
    if not name or '\x00' in name:
        raise ArchiveRejected('Das Archiv enthält einen ungültigen Dateinamen.')
    path = PurePosixPath(name)
    if path.is_absolute() or name.startswith('/') or (len(name) > 1 and name[1] == ':'):
        raise ArchiveRejected('Das Archiv enthält absolute Pfade.')
    if any(part == '..' for part in path.parts):
        raise ArchiveRejected('Das Archiv enthält unzulässige Pfade („..“).')
    return path


def _target(dest: Path, rel: PurePosixPath) -> Path:
    target = (dest / Path(*rel.parts)).resolve()
    if dest.resolve() not in target.parents and target != dest.resolve():
        raise ArchiveRejected('Das Archiv enthält unzulässige Pfade.')
    return target


class _Budget:
    def __init__(self):
        self.total = 0

    def write(self, src, target: Path):
        target.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with open(target, 'xb') as out:
            while True:
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                self.total += len(chunk)
                if written > MAX_FILE_BYTES:
                    raise ArchiveRejected('Eine Datei im Archiv ist zu groß (max. 50 MB entpackt).')
                if self.total > MAX_TOTAL_BYTES:
                    raise ArchiveRejected('Das Archiv ist entpackt zu groß (max. 200 MB).')
                out.write(chunk)


def _extract_zip(archive: Path, dest: Path) -> None:
    try:
        zf = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as exc:
        raise ArchiveRejected('Die Datei ist kein gültiges ZIP-Archiv.') from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ArchiveRejected(f'Das Archiv enthält zu viele Dateien (max. {MAX_ENTRIES}).')
        budget = _Budget()
        for info in infos:
            if info.flag_bits & 0x1:
                raise ArchiveRejected('Passwortgeschützte Archive können nicht geprüft werden.')
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ArchiveRejected('Das Archiv enthält Verknüpfungen (Symlinks).')
            rel = _safe_relpath(info.filename)
            target = _target(dest, rel)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            with zf.open(info) as src:
                budget.write(src, target)


def _extract_7z(archive: Path, dest: Path) -> None:
    import py7zr

    try:
        zf = py7zr.SevenZipFile(archive, mode='r', max_extract_size=MAX_TOTAL_BYTES)
    except (py7zr.exceptions.ArchiveError, py7zr.exceptions.PasswordRequired) as exc:
        raise ArchiveRejected('Die Datei ist kein gültiges 7z-Archiv oder passwortgeschützt.') from exc
    with zf:
        if zf.needs_password():
            raise ArchiveRejected('Passwortgeschützte Archive können nicht geprüft werden.')
        files = zf.files
        if len(files) > MAX_ENTRIES:
            raise ArchiveRejected(f'Das Archiv enthält zu viele Dateien (max. {MAX_ENTRIES}).')
        declared = 0
        for f in files:
            if f.is_symlink or getattr(f, 'is_junction', False) or getattr(f, 'is_socket', False):
                raise ArchiveRejected('Das Archiv enthält Verknüpfungen (Symlinks).')
            _target(dest, _safe_relpath(f.filename))
            size = f.uncompressed or 0
            if size > MAX_FILE_BYTES:
                raise ArchiveRejected('Eine Datei im Archiv ist zu groß (max. 50 MB entpackt).')
            declared += size
        if declared > MAX_TOTAL_BYTES:
            raise ArchiveRejected('Das Archiv ist entpackt zu groß (max. 200 MB).')
        # Headers were checked above; extraction goes into a fresh dir and is re-checked below.
        try:
            zf.extractall(path=dest)
        except (py7zr.exceptions.ArchiveError, py7zr.exceptions.PasswordRequired) as exc:
            raise ArchiveRejected('Das 7z-Archiv konnte nicht entpackt werden (beschädigt oder zu groß).') from exc
    # py7zr applies the archive's own modes - a 0o000 directory would hide its files from the
    # re-check walk below, so normalize first.
    _normalize_modes(dest)
    total = 0
    count = 0
    for root, dirs, names in os.walk(dest):
        for n in dirs + names:
            p = Path(root) / n
            if p.is_symlink():
                raise ArchiveRejected('Das Archiv enthält Verknüpfungen (Symlinks).')
            if dest.resolve() not in p.resolve().parents:
                raise ArchiveRejected('Das Archiv enthält unzulässige Pfade.')
            if p.is_file():
                count += 1
                total += p.stat().st_size
    if count > MAX_ENTRIES or total > MAX_TOTAL_BYTES:
        raise ArchiveRejected('Das Archiv ist entpackt zu groß.')


def _normalize_modes(dest: Path) -> None:
    for root, dirs, names in os.walk(dest):
        for n in dirs:
            os.chmod(Path(root) / n, 0o755)
        for n in names:
            os.chmod(Path(root) / n, 0o644)


def safe_extract(archive: Path, dest: Path, filename: str) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    ext = os.path.splitext(filename.lower())[1]
    try:
        if ext == '.zip':
            _extract_zip(archive, dest)
        elif ext == '.7z':
            _extract_7z(archive, dest)
        else:
            raise ArchiveRejected('Nur .zip und .7z werden unterstützt.')
        _normalize_modes(dest)
    except ArchiveRejected:
        raise
    except FileExistsError as exc:
        raise ArchiveRejected('Das Archiv enthält doppelte Dateinamen.') from exc
    except OSError as exc:
        # e.g. the size-limited tmpfs ran full: a 7z whose headers lied about its sizes.
        raise ArchiveRejected('Das Archiv konnte nicht entpackt werden (zu groß oder beschädigt).') from exc
    except Exception as exc:  # noqa: BLE001
        # Untrusted input: zipfile.BadZipFile (CRC), zlib.error, NotImplementedError (Deflate64,
        # unknown methods), py7zr CRC/unsupported filter (BCJ2), EOFError, lzma.LZMAError, ... -
        # every way an archive can be broken is a rejection, never a crash.
        raise ArchiveRejected(
            'Das Archiv ist beschädigt oder nutzt ein nicht unterstütztes Kompressionsverfahren.'
        ) from exc
