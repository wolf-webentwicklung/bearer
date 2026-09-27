"""Runs the REAL bearer binary (with the rules baked into the image) against the invented corpus
and checks that every finding recorded in fixtures/idv_corpus/bearer_results/ still appears.

The other policy tests use those recorded JSONs - they cannot notice a bearer or bearer-rules
bump that renames or drops a rule. This one can. It only runs where bearer is installed and
UNIFIED_SCAN_IMAGE_TEST=1 is set (rebuild.sh runs it inside the freshly built image):

    docker run --rm -e UNIFIED_SCAN_IMAGE_TEST=1 --entrypoint python <image> \
        -m pytest -q /opt/unified-scan/tests/test_corpus_real_bearer.py
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unified_scan  # noqa: E402

CORPUS = Path(__file__).resolve().parent / "fixtures" / "idv_corpus"
CASES = {"benign": CORPUS / "benign", "dangerous": CORPUS / "dangerous",
         "custom_benign": CORPUS / "custom" / "benign", "custom_dangerous": CORPUS / "custom" / "dangerous"}

# git/bearer parse English messages ("not a git repository"); a localized git breaks bearer's
# git detection. Only LC_ALL: bearer reads a LANGUAGE variable as its own --language option.
os.environ["LC_ALL"] = "C"

pytestmark = pytest.mark.skipif(
    os.environ.get("UNIFIED_SCAN_IMAGE_TEST") != "1" or shutil.which("bearer") is None,
    reason="needs the bearer binary + baked rules (UNIFIED_SCAN_IMAGE_TEST=1 inside the image)")


def _recorded(name):
    data = json.loads((CORPUS / "bearer_results" / f"{name}.json").read_text())
    return {(item["id"], item["filename"], item["line_number"])
            for items in data.values() if isinstance(items, list) for item in items}


@pytest.mark.parametrize("name", sorted(CASES))
def test_real_bearer_still_finds_the_recorded_findings(name):
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "src"
        shutil.copytree(CASES[name], work)
        raw_json = Path(tmp) / "bearer.json"
        _findings, meta = unified_scan.scan_bearer(work, raw_json, [])
        assert not meta.get("error"), meta
        # Bearer's raw report, before our own de-duplication of custom-rule findings.
        raw = json.loads(raw_json.read_text())
    got = {(item["id"], item["filename"], item["line_number"])
           for items in raw.values() if isinstance(items, list) for item in items}
    missing = _recorded(name) - got
    assert not missing, f"bearer no longer reports: {sorted(missing)}"
