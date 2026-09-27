"""Every bearer rule glob in severity_policy.json must match at least one reportable rule of the
bearer-rules version baked into the image (plus our own custom-rules/). A glob that matches
nothing is dead weight - usually a renamed rule after a rules bump, which would silently switch
the intended re-rating off.

Against the real image: BEARER_RULES_DIR=/opt/bearer-rules pytest tests/test_policy_globs.py
(rebuild.sh does that). Without it the committed id list of the pinned version is used."""
import fnmatch
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
FIXTURE = HERE / "tests" / "fixtures" / "bearer_rule_ids_v0.48.4.txt"
_ID = re.compile(r"^\s*id:\s*[\"']?([A-Za-z0-9_]+)", re.M)
_SHARED = re.compile(r"^type:\s*shared\b", re.M)


def _ids_from_dir(root: Path) -> set[str]:
    ids = set()
    for path in root.rglob("*.yml"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        m = _ID.search(text)
        if m and not _SHARED.search(text):
            ids.add(m.group(1))
    return ids


def _known_rule_ids() -> set[str]:
    rules_dir = os.environ.get("BEARER_RULES_DIR")
    if rules_dir:
        ids = _ids_from_dir(Path(rules_dir))
    else:
        ids = {line.strip() for line in FIXTURE.read_text().splitlines()
               if line.strip() and not line.startswith("#")}
    return ids | _ids_from_dir(HERE / "custom-rules")


def test_every_bearer_policy_glob_matches_a_rule():
    ids = _known_rule_ids()
    assert len(ids) > 400
    policy = json.loads((HERE / "severity_policy.json").read_text(encoding="utf-8"))
    dead = [r["match"] for r in policy["rules"] if r.get("tool", "bearer") == "bearer"
            and not any(fnmatch.fnmatchcase(i, r["match"]) for i in ids)]
    assert dead == []


def _severity(rule_id, rules):
    import unified_scan as us
    f = us.Finding(tool="bearer", severity="critical", rule_id=rule_id, title="t", file="a.py", line=1)
    us.apply_severity_policy(f, rules)
    return f.severity


def test_same_class_same_level_across_languages():
    import unified_scan as us
    rules = us.load_severity_policy()
    ids = _known_rule_ids()
    classes = {
        "medium": ["*_sql_injection", "*_sqli", "*_cross_site_scripting", "*_dangerous_insert_html",
                   "*_template_injection"],
        "high": ["*_os_command_injection", "*_exec_using_user_input", "*_subproc_*",
                 "*_insecure_http", "*_http_insecure", "*_insecure_ftp"],
        "critical": ["*_eval_using_user_input", "*_code_injection", "*_deserialization_of_user_input"],
    }
    for level, globs in classes.items():
        for g in globs:
            for rule_id in (i for i in ids if fnmatch.fnmatchcase(i, g)):
                assert _severity(rule_id, rules) == level, (rule_id, level)
