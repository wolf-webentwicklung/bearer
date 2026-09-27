#!/usr/bin/env python3
"""Builds the offline index of known malicious packages (OSV MAL-* advisories) for PyPI and npm.

Runs at image build time (see Dockerfile / rebuild.sh), never at scan time: the scanner has no
egress to osv.dev. Only MAL-* entries are kept - vulnerabilities (CVE/GHSA) are trivy's job -
so the index stays small although npm's all.zip is ~200 MB.

    python3 build_osv_index.py /opt/osv/mal_index.json [--source-dir DIR]

--source-dir reads <DIR>/PyPI.zip and <DIR>/npm.zip instead of downloading (tests, air gap).
Index format: {"generated": iso, "source": url, "ecosystems": {"pypi": {name: [entry...]},
"npm": {...}}}, entry = {"id", "all_versions": bool, "versions": [...], "introduced": [...]}.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

SOURCE = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
ECOSYSTEMS = {"PyPI": "pypi", "npm": "npm"}


def norm_name(ecosystem: str, name: str) -> str:
    name = (name or "").strip().lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


def _entry(advisory: dict, affected: dict) -> dict:
    all_versions = False
    introduced: list[str] = []
    for rng in affected.get("ranges") or []:
        events = rng.get("events") or []
        starts = [e["introduced"] for e in events if "introduced" in e]
        closed = any("fixed" in e or "last_affected" in e or "limit" in e for e in events)
        if "0" in starts and not closed:
            all_versions = True
        elif starts and not closed:
            introduced += [s for s in starts if s != "0"]
    versions = sorted({str(v) for v in affected.get("versions") or []})
    if not versions and not introduced and (affected.get("ranges") in (None, [])):
        all_versions = True  # no version info at all: the package as such is malicious
    return {"id": advisory["id"], "all_versions": all_versions, "versions": versions,
            "introduced": sorted(set(introduced))}


def index_zip(path: Path, osv_ecosystem: str) -> dict[str, list[dict]]:
    eco = ECOSYSTEMS[osv_ecosystem]
    out: dict[str, list[dict]] = {}
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if not info.filename.startswith("MAL-") or not info.filename.endswith(".json"):
                continue
            advisory = json.loads(zf.read(info))
            if advisory.get("withdrawn"):
                continue
            for affected in advisory.get("affected") or []:
                pkg = affected.get("package") or {}
                if pkg.get("ecosystem") != osv_ecosystem or not pkg.get("name"):
                    continue
                out.setdefault(norm_name(eco, pkg["name"]), []).append(_entry(advisory, affected))
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    parser.add_argument("--source-dir")
    args = parser.parse_args()
    ecosystems: dict[str, dict] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for osv_eco, eco in ECOSYSTEMS.items():
            if args.source_dir:
                src = Path(args.source_dir) / f"{osv_eco}.zip"
            else:
                src = Path(tmp) / f"{osv_eco}.zip"
                urllib.request.urlretrieve(SOURCE.format(eco=osv_eco), src)
            ecosystems[eco] = index_zip(src, osv_eco)
            if not args.source_dir:
                src.unlink()
    total = sum(len(v) for v in ecosystems.values())
    if not args.source_dir and total < 1000:
        print(f"OSV index suspiciously small ({total} packages) - refusing", file=sys.stderr)
        return 1
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "source": SOURCE.format(eco="<ecosystem>"),
        "ecosystems": ecosystems,
    }, separators=(",", ":")))
    print(f"OSV MAL index: {', '.join(f'{k}={len(v)}' for k, v in ecosystems.items())} packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
