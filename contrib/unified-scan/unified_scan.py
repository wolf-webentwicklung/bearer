#!/usr/bin/env python3
"""
unified_scan.py — Bearer-Fork Erweiterung: kombinierter Malware- + Security-Scan
für "vibe coded" Anwendungen.

Zwei-Stufen-Pipeline:

  Stufe 0 (Malware-Gate, läuft ZUERST):
    - guarddog    (bösartige PyPI/npm-Pakete als Dependency: Typosquatting,
                   verdächtige Install-Scripts, Obfuskierung, Exfiltration)
      Findet ein high-risk-Paket -> Security-Scan (Stufe 1) läuft NICHT,
      Pipeline stoppt sofort mit Report nur zum Malware-Fund.

  Stufe 1 (Security-Scan, nur wenn Stufe 0 sauber durchläuft):
    - bearer      (SAST + Privacy/Datenfluss)   -> Kernstärke: wo fließen sensible Daten hin
    - trufflehog  (Secrets in Code + Git-History, falls Git-Repo vorhanden)
    - trivy       (Dependency-CVEs / SCA, braucht Lockfile; zusätzlich Docker-Base-Image-CVEs)
    - checkov     (IaC-Fehlkonfigurationen: Terraform/K8s/Docker/CloudFormation)
    - olevba      (Office-VBA-Makros: .doc*/.xls*/.ppt* — AutoExec, Shell/
                   PowerShell-Aufrufe, Obfuskierung; deckt eine Lücke ab, die
                   keines der anderen Tools abdeckt)

Alle Tools laufen lokal, kein Cloud-Call für den gescannten Code selbst. Einzige
Ausnahme: guarddog lädt zur Analyse die Paket-INHALTE (nicht euren Code) von
PyPI/npm herunter — wie ein normales `pip install`/`npm install` — und fragt
Metadaten bei der Registry ab (siehe Kommentar bei scan_guarddog()).

Ziel kann sein:
  - ein lokaler Ordner (mit oder OHNE Git — z.B. ein R-Shiny-Projekt, das
    nie in Git war, funktioniert genauso)
  - eine Git-URL (GitHub, GitLab, beliebiger Git-Host, https:// oder git@)
    -> wird automatisch geklont, danach gescannt, danach aufgeräumt
  - ein .zip-/.7z-Archiv
    -> wird sicher in ein Temp-Verzeichnis entpackt (safe_extract.py),
       danach gescannt, danach aufgeräumt

Ist das Ziel ein Git-Repo (lokal geklont oder direkt vorhanden), scannt
trufflehog zusätzlich die komplette Git-History (nicht nur den aktuellen
Stand) — der häufigste Fall ist ein Secret, das committed und später
"gelöscht" wurde, aber in der History für immer bleibt.

Output: zwei Report-Ebenen in einem JSON, plus lesbares Markdown je Ebene.

  1. "employee_findings"   -> was MUSS gefixt werden bevor live geht
                              (nur tatsächlich actionable Findings,
                               nach Severity sortiert, mit Datei:Zeile;
                               Test-/Beispielcode ist markiert, fließt
                               aber nicht in den Kritikalitäts-Score ein)

  2. "internal_criticality" -> interne Kritikalitäts-Einschätzung
                               (Scoring 0-100, Kategorie-Breakdown,
                                Ampel-Einschätzung für Go/No-Go,
                                Test-/Fixture-Code herausgerechnet)

Nutzung:
  python3 unified_scan.py /pfad/zum/projekt [--out report_dir]
  python3 unified_scan.py https://github.com/org/repo.git [--out report_dir]
  python3 unified_scan.py git@gitlab.com:org/repo.git [--out report_dir]
  python3 unified_scan.py tool.zip [--out report_dir]

Exit-Codes: 0 = ok, 1 = mind. ein critical-Finding, 2 = Ziel nicht auflösbar,
3 = Archiv abgelehnt (unsicher/ungültig, Grund auf stderr).

Erfordert im PATH: bearer, trufflehog, trivy, checkov, guarddog, olevba, git
(fehlende Tools werden übersprungen, nicht fatal - Report vermerkt das,
außer guarddog fehlt komplett — dann läuft das Malware-Gate leer durch
und wird im Report als nicht ausgeführt markiert, blockiert aber nicht).

Bekannte Grenze: Bearer's SAST-Engine deckt aktuell JS/TS, Python, Ruby,
Go, PHP, Java ab — KEIN R. Bei reinen R/Shiny-Projekten liefert bearer
daher keine oder kaum SAST-Findings; Secrets (trufflehog), Dependency-CVEs
(trivy, sofern renv.lock erkannt wird) und IaC (checkov) laufen trotzdem
normal, da die nicht auf Sprach-AST-Parsing angewiesen sind. Der Report
vermerkt das unter tools.bearer wenn effektiv nichts gefunden wurde.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from safe_extract import ArchiveRejected, safe_extract


# ---------------------------------------------------------------------------
# Datenmodell
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}

# Pfad-Fragmente, die auf Test-Code hindeuten. Findings darin fließen NICHT in
# den Kritikalitäts-Score ein (verzerren ihn sonst nach oben, obwohl es kein
# Code ist der live läuft), bleiben aber sichtbar im Mitarbeiter-Report, klar
# markiert. Bewusst NUR echte Test-Pfade: build/, dist/, vendor/, examples/
# o.ä. sind oft genau der Code, der ausgeliefert wird, und ein Ordnername ist
# vom Uploader frei wählbar - er darf keine Funde abschalten.
NOISE_PATH_PATTERNS = [
    "/test/", "/tests/", "/__tests__/", "/spec/", "/specs/",
    "/fixture/", "/fixtures/", "/testdata/", "/test-data/",
]
_NOISE_FILE_PATTERN = re.compile(
    r"(^test_.+\.py|.+_test\.py|.+_test\.go|.+\.(test|spec)\.[cm]?[jt]sx?|.+_spec\.rb)$",
    re.IGNORECASE,
)
# Diese Funde zählen IMMER, auch in Test-Pfaden: ein echtes Secret, Malware oder
# eine nicht prüfbare Datei ist dort genauso gefährlich wie anderswo.
NEVER_EXCLUDED_CATEGORIES = {"secret", "malware", "malicious-package", "unscannable"}


def _is_noise_path(path: str | None) -> bool:
    if not path:
        return False
    p = "/" + path.replace("\\", "/").strip("/") + "/"
    p_lower = p.lower()
    if any(pat in p_lower for pat in NOISE_PATH_PATTERNS):
        return True
    return bool(_NOISE_FILE_PATTERN.match(p.rstrip("/").rsplit("/", 1)[-1]))


def _excluded_from_score(severity: str, category: str, path: str | None) -> bool:
    if severity == "critical" or category in NEVER_EXCLUDED_CATEGORIES:
        return False
    return _is_noise_path(path)


@dataclass
class Finding:
    tool: str
    severity: str  # normalized: critical/high/medium/low/info
    rule_id: str
    title: str
    file: str | None = None
    line: int | None = None
    category: str = "other"  # security | privacy | secret | dependency | iac
    description: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    excluded_from_score: bool = False
    original_severity: str | None = None  # set when severity_policy.json changed the severity
    policy_reason: str | None = None
    # Dependency findings (trivy): lets a consumer group CVEs per package and suggest the update.
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None

    def __post_init__(self) -> None:
        self.excluded_from_score = _excluded_from_score(self.severity, self.category, self.file)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "title": self.title,
            "file": self.file,
            "line": self.line,
            "category": self.category,
            "description": self.description,
            "excluded_from_score": self.excluded_from_score,
            "original_severity": self.original_severity,
            "policy_reason": self.policy_reason,
            "package": self.package,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
        }


def _norm_severity(raw: str) -> str:
    s = (raw or "").strip().lower()
    if s in ("critical", "blocker"):
        return "critical"
    if s in ("high", "error"):
        return "high"
    if s in ("medium", "moderate", "warning"):
        return "medium"
    if s in ("low", "minor", "info", "informational", "unknown", ""):
        return "low"
    return "low"


# Tools whose exit code does NOT mean "the tool failed". Every other tool is called so that it
# exits 0 on success even with findings (bearer --exit-code 0, checkov --soft-fail, trufflehog/
# trivy/guarddog without --fail/--exit-code options), so a non-zero exit is a real failure and
# must surface as tools.<name>.error instead of an empty "clean" result. olevba returns codes
# like 8 for a crash but always prints JSON with the details - scan_olevba reads that instead.
_ANY_EXIT_CODE = {"olevba"}


def run_tool(name: str, cmd: list[str], cwd: Path, timeout: int = 900) -> tuple[bool, str, str]:
    """Run external tool, return (ok, stdout, stderr). Never raises."""
    if shutil.which(cmd[0]) is None:
        return False, "", f"{cmd[0]} not found in PATH"
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout
        )
        if proc.returncode != 0 and name not in _ANY_EXIT_CODE:
            tail = "\n".join((proc.stderr or proc.stdout or "").strip().splitlines()[-5:])
            return False, proc.stdout, f"{name} exit {proc.returncode}: {tail}"[:2000]
        return True, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return False, "", f"{name} timed out after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return False, "", f"{name} failed: {e}"


# ---------------------------------------------------------------------------
# Target-Auflösung: lokaler Ordner (Git oder nicht) ODER Git-URL
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(r"^(https?://|git@|ssh://)", re.IGNORECASE)


def _looks_like_git_url(target_arg: str) -> bool:
    return bool(_URL_PATTERN.match(target_arg.strip())) or target_arg.strip().endswith(".git")


def _reject_dash_prefixed(value: str, what: str) -> None:
    """Args starting with '-' can be parsed as flags by git/trivy instead of
    positional values (argument-injection class, e.g. `--upload-pack=...`
    smuggled in as a git 'URL' triggers local command execution). Reject
    outright rather than trying to rewrite/escape."""
    if value.strip().startswith("-"):
        raise RuntimeError(
            f"{what} beginnt mit '-' ('{value}') — abgelehnt, um Argument-Injection "
            f"in nachgelagerte CLI-Tools (git/trivy) zu verhindern."
        )


def is_git_repo(path: Path) -> bool:
    """True wenn path (oder ein Elternverzeichnis via `git rev-parse`) ein Git-Repo ist."""
    if (path / ".git").exists():
        return True
    ok, out, _err = run_tool(
        "git", ["git", "rev-parse", "--is-inside-work-tree"], cwd=path, timeout=15
    )
    return ok and out.strip() == "true"


ARCHIVE_SUFFIXES = (".zip", ".7z")

# Entries in an untrusted .git that make git read outside the repo or run commands.
_GIT_UNSAFE_PATHS = ("hooks", "config.worktree", "commondir",
                     "objects/info/alternates", "objects/info/http-alternates")
_GIT_CONFIG_KEEP = {
    "core": {"repositoryformatversion", "bare", "filemode", "ignorecase",
             "precomposeunicode", "logallrefupdates"},
    "extensions": {"objectformat", "refstorage"},
}


def _sanitize_git_config(text: str) -> str:
    """Keeps only harmless [core]/[extensions] keys - drops include, fsmonitor, filter/diff
    drivers, hooksPath and everything else that could run a command or point elsewhere."""
    out: list[str] = []
    section = None
    for line in text.splitlines():
        header = re.match(r"^\s*\[\s*([A-Za-z0-9.-]+)", line)
        if header:
            section = header.group(1).lower()
            if section in _GIT_CONFIG_KEEP and not re.search(r'"', line):
                out.append(f"[{section}]")
            else:
                section = None
            continue
        # Plain `key = simple-value` only: no continuation lines, quotes or odd syntax.
        key = re.match(r"^\s*([A-Za-z0-9-]+)\s*=\s*([A-Za-z0-9._-]+)\s*$", line)
        if section and key and key.group(1).lower() in _GIT_CONFIG_KEEP[section]:
            out.append(f"\t{key.group(1)} = {key.group(2)}")
    return "\n".join(out) + "\n"


def _sanitize_git_dirs(root: Path) -> None:
    """Archive content is untrusted: a `.git` *file* (gitdir: /elsewhere), alternates or a
    crafted config would let git/trufflehog read files outside the archive or run commands."""
    for git in sorted(root.rglob(".git"), key=lambda p: len(p.parts), reverse=True):
        if not git.is_dir():
            git.unlink(missing_ok=True)
            continue
        for rel in _GIT_UNSAFE_PATHS:
            victim = git / rel
            if victim.is_dir():
                shutil.rmtree(victim)
            elif victim.exists():
                victim.unlink()
        config = git / "config"
        if config.is_file():
            config.write_text(_sanitize_git_config(config.read_text(errors="ignore")))


def _harden_git_env(target: Path) -> None:
    """Belt and braces on top of _sanitize_git_dirs: command-line config wins over repo config."""
    overrides = {"core.fsmonitor": "false", "core.hooksPath": "/dev/null"}
    os.environ["GIT_CONFIG_COUNT"] = str(len(overrides))
    for i, (key, value) in enumerate(overrides.items()):
        os.environ[f"GIT_CONFIG_KEY_{i}"] = key
        os.environ[f"GIT_CONFIG_VALUE_{i}"] = value
    os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
    os.environ["GIT_CEILING_DIRECTORIES"] = str(target.parent)


def _relative_file(file: str | None, target: Path) -> str | None:
    """Tools report paths differently (absolute, `/Dockerfile`, `./x`, file://) - normalize to
    relative to the scan root, so reports never leak temp paths and stay comparable between
    runs (e.g. an archive re-uploaded after a fix)."""
    if not file:
        return file
    f = file.replace("\\", "/")
    if f.startswith("file://"):
        f = f[len("file://"):]
    roots = {str(target), str(target.resolve()), os.path.realpath(target)}
    for r in sorted(roots, key=len, reverse=True):
        r = r.rstrip("/") + "/"
        if f.startswith(r):
            return f[len(r):]
    if f.startswith("/") and (target / f.lstrip("/")).exists():
        return f.lstrip("/")
    if f.startswith("./"):
        return f[2:]
    return f


def _relativize_findings(findings: list[Finding], target: Path) -> None:
    for f in findings:
        f.file = _relative_file(f.file, target)
        f.excluded_from_score = _excluded_from_score(f.severity, f.category, f.file)


def resolve_target(target_arg: str) -> tuple[Path, tempfile.TemporaryDirectory | None, str]:
    """
    Gibt (lokaler_pfad, tempdir_handle_oder_None, quelle_beschreibung) zurück.
    Bei Git-URL wird geklont; tempdir_handle muss vom Aufrufer offengehalten
    werden, damit das Verzeichnis nicht vorzeitig aufgeräumt wird.
    """
    if _looks_like_git_url(target_arg):
        _reject_dash_prefixed(target_arg, "Git-Ziel")
        tmp = tempfile.TemporaryDirectory(prefix="unified-scan-clone-")
        clone_dir = Path(tmp.name) / "repo"
        ok, _out, err = run_tool(
            "git",
            ["git", "clone", "--depth", "1", "--", target_arg, str(clone_dir)],
            cwd=Path(tmp.name),
            timeout=600,
        )
        if not ok or not clone_dir.exists():
            tmp.cleanup()
            raise RuntimeError(f"git clone fehlgeschlagen für {target_arg}: {err}")
        return clone_dir, tmp, f"git-clone von {target_arg}"

    path = Path(target_arg).resolve()
    if path.is_file() and path.suffix.lower() in ARCHIVE_SUFFIXES:
        tmp = tempfile.TemporaryDirectory(prefix="unified-scan-archive-")
        extract_dir = Path(tmp.name) / "src"
        try:
            safe_extract(path, extract_dir, path.name)
            _sanitize_git_dirs(extract_dir)
        except BaseException:
            tmp.cleanup()
            raise
        _harden_git_env(extract_dir)
        return extract_dir, tmp, "archive"

    if not path.is_dir():
        raise RuntimeError(f"{path} ist kein Verzeichnis und keine erkennbare Git-URL")
    kind = "lokales Git-Repo" if is_git_repo(path) else "lokaler Ordner (kein Git)"
    return path, None, kind


# ---------------------------------------------------------------------------
# Verschachtelte Archive (nur trufflehog schaut hinein, alle anderen Tools nicht)
# ---------------------------------------------------------------------------

NESTED_ARCHIVE_EXTENSIONS = {
    ".zip", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".tbz", ".tbz2", ".xz", ".txz",
    ".zst", ".lz", ".lzma", ".rar", ".cab", ".iso", ".jar", ".war", ".ear", ".apk",
}
_ARCHIVE_MAGIC = (
    (0, b"PK\x03\x04"), (0, b"PK\x05\x06"), (0, b"7z\xbc\xaf\x27\x1c"), (0, b"\x1f\x8b"),
    (0, b"BZh"), (0, b"\xfd7zXZ\x00"), (0, b"Rar!\x1a\x07"), (0, b"\x28\xb5\x2f\xfd"),
    (0, b"MSCF"), (257, b"ustar"),
)
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_SKIP_DIRS = {".git"}


def _head(path: Path, size: int = 512) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(size)
    except OSError:
        return b""


def _zip_names(path: Path) -> list[str] | None:
    try:
        with zipfile.ZipFile(path) as zf:
            return zf.namelist()
    except Exception:  # noqa: BLE001 - broken zip: treat as opaque archive
        return None


def _is_office_or_odf_zip(names: list[str] | None) -> bool:
    """OOXML (.docx/.xlsm ...) and ODF documents are ZIP containers, but documents - not
    archives someone packed code into. Macros in them are olevba's job."""
    if not names:
        return False
    return "[Content_Types].xml" in names or "mimetype" in names


def _iter_files(target: Path):
    for path in target.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.relative_to(target).parts):
            continue
        if path.is_file() and not path.is_symlink():
            yield path


def scan_nested_archives(target: Path) -> tuple[list[Finding], dict[str, Any]]:
    """An archive inside the upload is opaque to bearer/trivy/checkov/guarddog/olevba - its
    content would pass as "checked". Detected by extension AND by magic bytes (renamed files)."""
    findings: list[Finding] = []
    meta: dict[str, Any] = {"tool": "unified-scan", "ran": True, "error": None}
    for path in _iter_files(target):
        head = _head(path)
        by_magic = any(head[off:off + len(sig)] == sig for off, sig in _ARCHIVE_MAGIC)
        by_ext = path.suffix.lower() in NESTED_ARCHIVE_EXTENSIONS
        if not (by_magic or by_ext):
            continue
        if head.startswith(b"PK") and _is_office_or_odf_zip(_zip_names(path)):
            continue
        rel = str(path.relative_to(target))
        findings.append(Finding(
            tool="unified-scan",
            severity="critical",
            rule_id="nested-archive",
            title=f"Verschachteltes Archiv: {rel}",
            file=rel,
            line=None,
            category="unscannable",
            description="Nested archive not scanned - upload its content unpacked instead.",
        ))
    meta["finding_count"] = len(findings)
    return findings, meta


# ---------------------------------------------------------------------------
# Bearer (SAST + Privacy)
# ---------------------------------------------------------------------------

# Bearer without rules still exits normally and writes an (empty) report - which would read as
# "no findings". Happens e.g. when BEARER_DISABLE_VERSION_CHECK=true also stops the default-rule
# download. Such a run must surface as tools.bearer.error, never as a clean result.
_BEARER_NO_RULES = re.compile(
    r"\b0 rules found\b|zero rules found|loading rules failed|default rules could not be downloaded",
    re.IGNORECASE,
)


def _bearer_rules_missing() -> str | None:
    """Pre-flight: default rules disabled but no usable external rule dir -> bearer checks nothing."""
    if os.environ.get("BEARER_DISABLE_DEFAULT_RULES", "").strip().lower() not in ("1", "true", "yes"):
        return None
    rule_dir = os.environ.get("BEARER_EXTERNAL_RULE_DIR", "").strip()
    if not rule_dir or not Path(rule_dir).is_dir():
        return f"bearer: default rules disabled and external rule dir missing ({rule_dir or 'unset'})"
    if not any(Path(rule_dir).rglob("*.yml")):
        return f"bearer: default rules disabled and no rules in {rule_dir}"
    return None


def _plain_summary(text: str, limit: int = 500) -> str:
    """First paragraph of a Markdown description as plain text (Bearer ships long Markdown docs
    per rule; the employee report only needs the gist - the full text stays in raw)."""
    if not text:
        return ""
    body = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    paragraphs = []
    for block in re.split(r"\n\s*\n", body):
        block = block.strip()
        if not block or block.startswith("#"):
            continue
        paragraphs.append(block)
        break
    summary = paragraphs[0] if paragraphs else body.strip()
    summary = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", summary)   # links/images -> text
    summary = re.sub(r"`([^`]*)`", r"\1", summary)                  # inline code
    summary = re.sub(r"(\*\*|__|\*|_)(\S.*?\S|\S)\1", r"\2", summary)  # bold/italic
    summary = re.sub(r"^\s*[-*+]\s+", "", summary, flags=re.MULTILINE)
    summary = re.sub(r"\s+", " ", summary).strip()
    return summary[:limit]


# ---------------------------------------------------------------------------
# Severity-Policy für Bearer (interne Mitarbeiter-Skripte statt Web-Apps)
# ---------------------------------------------------------------------------

SEVERITY_POLICY_FILE = Path(__file__).resolve().parent / "severity_policy.json"
_POLICY_MODES = {"set", "min"}


def load_severity_policy(path: Path | None = None) -> list[dict[str, Any]]:
    """Rules from severity_policy.json (see its _doc). [] when disabled via
    UNIFIED_SCAN_SEVERITY_POLICY=off. A broken policy file raises - silently scanning without
    it would change what blocks without anyone noticing."""
    if os.environ.get("UNIFIED_SCAN_SEVERITY_POLICY", "").strip().lower() in ("off", "0", "false"):
        return []
    path = path or Path(os.environ.get("UNIFIED_SCAN_SEVERITY_POLICY_FILE") or SEVERITY_POLICY_FILE)
    rules = json.loads(path.read_text(encoding="utf-8"))["rules"]
    for r in rules:
        if r.get("mode") not in _POLICY_MODES or r.get("severity") not in SEVERITY_ORDER \
                or not r.get("match"):
            raise ValueError(f"invalid severity policy rule: {r!r}")
    return rules


def apply_severity_policy(finding: Finding, rules: list[dict[str, Any]]) -> None:
    """First matching rule wins. Only for bearer, never for secret/malware/unscannable."""
    if finding.tool != "bearer" or finding.category in NEVER_EXCLUDED_CATEGORIES:
        return
    for r in rules:
        if not fnmatch.fnmatchcase(finding.rule_id, r["match"]):
            continue
        target = r["severity"]
        if r["mode"] == "min" and SEVERITY_ORDER.index(finding.severity) <= SEVERITY_ORDER.index(target):
            return  # already at least that severe
        if target != finding.severity:
            finding.original_severity = finding.severity
            finding.policy_reason = r.get("reason") or None
            finding.severity = target
            finding.excluded_from_score = _excluded_from_score(
                finding.severity, finding.category, finding.file)
        return


def parse_bearer_json(data: dict[str, Any],
                      policy: list[dict[str, Any]] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for sev_key in ("critical", "high", "medium", "low"):
        for item in data.get(sev_key, []) or []:
            fname = (item.get("filename") or item.get("full_filename") or "")
            line = None
            src = item.get("source") or {}
            if isinstance(src, dict):
                line = src.get("start")
            findings.append(Finding(
                tool="bearer",
                severity=_norm_severity(sev_key),
                rule_id=item.get("rule_id") or item.get("id") or "bearer.unknown",
                title=item.get("title") or item.get("rule_id") or "Bearer finding",
                file=fname or None,
                line=line,
                category="privacy" if "lang_" not in (item.get("rule_id") or "") and
                          any(k in (item.get("id") or "") for k in ("pii", "phi", "data"))
                          else "security",
                description=_plain_summary(item.get("description") or ""),
                raw=item,
            ))
    for f in findings:
        apply_severity_policy(f, policy or [])
    return findings


def scan_bearer(target: Path, tmp_json: Path,
                policy: list[dict[str, Any]] | None = None) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    meta = {"tool": "bearer", "ran": False, "error": None}

    missing = _bearer_rules_missing()
    if missing:
        meta["error"] = missing
        return findings, meta

    ok, out, err = run_tool(
        "bearer",
        ["bearer", "scan", str(target), "--format", "json",
         "--output", str(tmp_json), "--quiet", "--exit-code", "0"],
        cwd=target,
    )
    meta["ran"] = ok
    if not ok:
        meta["error"] = err
        return findings, meta

    no_rules = _BEARER_NO_RULES.search(f"{out}\n{err}")
    if no_rules:
        meta["error"] = f"bearer ran without rules ({no_rules.group(0)}) - nothing was checked"
        return findings, meta

    if not tmp_json.exists():
        meta["error"] = "bearer produced no output file"
        return findings, meta

    try:
        data = json.loads(tmp_json.read_text())
    except Exception as e:  # noqa: BLE001
        meta["error"] = f"could not parse bearer json: {e}"
        return findings, meta

    findings = parse_bearer_json(data, policy)
    meta["severity_policy_applied"] = bool(policy)
    meta["severity_policy_changed"] = sum(1 for f in findings if f.original_severity)
    meta["finding_count"] = len(findings)
    if not findings:
        meta["note"] = ("keine Findings — falls das Projekt in einer von bearer "
                         "nicht unterstützten Sprache ist (z.B. R), ist das erwartbar, "
                         "kein Fehler. Unterstützt: JS/TS, Python, Ruby, Go, PHP, Java.")
    return findings, meta


# ---------------------------------------------------------------------------
# Trufflehog (Secrets — mit Git-History wenn möglich, sonst Dateisystem)
# ---------------------------------------------------------------------------

def _parse_trufflehog_ndjson(out: str, git_mode: bool) -> list[Finding]:
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "SourceMetadata" not in item:
            continue  # progress/summary lines

        data = item.get("SourceMetadata", {}).get("Data", {})
        if git_mode and "Git" in data:
            meta_data = data["Git"]
        else:
            meta_data = data.get("Filesystem", {}) or data.get("Git", {})

        verified = item.get("Verified", False)
        commit = meta_data.get("commit")
        title = f"Exposed secret: {item.get('DetectorName', 'unknown')}"
        title += " (verified live)" if verified else " (unverified pattern)"
        if commit:
            title += f" — in Git-History (Commit {commit[:8]})"

        findings.append(Finding(
            tool="trufflehog",
            severity="critical" if verified else "high",
            rule_id=item.get("DetectorName", "secret"),
            title=title,
            file=meta_data.get("file"),
            line=meta_data.get("line"),
            category="secret",
            description="Hardcoded credential/secret gefunden. "
                         + ("Live gegen Provider-API verifiziert — sofort rotieren."
                            if verified else
                            "Musterbasiert erkannt, nicht live verifiziert — manuell prüfen.")
                         + (" ACHTUNG: liegt (auch) in der Git-History — Löschen im "
                            "aktuellen Stand reicht nicht, History muss bereinigt "
                            "oder das Secret rotiert werden." if commit else ""),
            raw=item,
        ))
    return findings


def _has_git_history(target: Path) -> bool:
    """History scan only for a real, readable repo at the scan root - a broken or empty .git
    (easy to put into an archive) must not change what gets scanned."""
    if not (target / ".git").is_dir():
        return False
    ok, _out, _err = run_tool(
        "git", ["git", "-C", str(target), "rev-parse", "--verify", "--quiet", "HEAD"],
        cwd=target, timeout=15,
    )
    return ok


def _dedupe_secrets(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.file, f.line, f.raw.get("Raw") or f.raw.get("RawV2"))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


# --no-verification: never send found credentials to their providers (AWS, GitHub, ...) to test
# them live - a real leaked key would leave the machine for that. Findings stay pattern-based.
def scan_trufflehog(target: Path) -> tuple[list[Finding], dict[str, Any]]:
    """Always scans the current file state; additionally the Git history if there is a valid
    repo. History alone would miss everything not committed (e.g. a zipped working copy)."""
    meta: dict[str, Any] = {"tool": "trufflehog", "ran": False, "error": None}
    ok, out, err = run_tool(
        "trufflehog",
        ["trufflehog", "filesystem", str(target), "--json", "--no-update", "--no-verification"],
        cwd=target,
    )
    meta["ran"] = ok
    if not ok:
        meta["error"] = err
        meta["mode"] = "filesystem"
        return [], meta
    findings = _parse_trufflehog_ndjson(out, git_mode=False)

    if _has_git_history(target):
        meta["mode"] = "filesystem+git-history"
        ok, out, err = run_tool(
            "trufflehog",
            ["trufflehog", "git", f"file://{target}", "--json", "--no-update", "--no-verification"],
            cwd=target,
        )
        if ok:
            findings += _parse_trufflehog_ndjson(out, git_mode=True)
        else:
            meta["error"] = f"git-history scan failed: {err}"
    else:
        meta["mode"] = "filesystem"
        if (target / ".git").exists():
            meta["note"] = "ungültiges/leeres .git - nur aktueller Dateistand geprüft."
        else:
            meta["note"] = ("kein Git-Repo erkannt — nur aktueller Dateistand geprüft, "
                             "History-Scan (z.B. bei gelöschten Secrets) nicht möglich.")

    findings = _dedupe_secrets(findings)
    meta["finding_count"] = len(findings)
    return findings, meta


# ---------------------------------------------------------------------------
# Trivy (Dependency-CVEs / SCA + Docker-Base-Image-CVEs)
# ---------------------------------------------------------------------------

def _trivy_package_fields(vuln: dict[str, Any]) -> dict[str, str | None]:
    # FixedVersion can list several branches ("2.2.5, 2.3.2") - kept as trivy reports it.
    return {
        "package": vuln.get("PkgName") or None,
        "installed_version": vuln.get("InstalledVersion") or None,
        "fixed_version": vuln.get("FixedVersion") or None,
    }


def scan_trivy(target: Path) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    meta = {"tool": "trivy", "ran": False, "error": None}

    ok, out, err = run_tool(
        "trivy",
        ["trivy", "fs", "--scanners", "vuln", "--format", "json", str(target)],
        cwd=target,
        timeout=600,
    )
    meta["ran"] = ok
    if not ok:
        meta["error"] = err
        return findings, meta

    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        meta["error"] = f"could not parse trivy json: {e}"
        return findings, meta

    for result in data.get("Results", []) or []:
        target_file = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(Finding(
                tool="trivy",
                severity=_norm_severity(vuln.get("Severity", "low")),
                rule_id=vuln.get("VulnerabilityID", "CVE-unknown"),
                title=f"{vuln.get('PkgName')}@{vuln.get('InstalledVersion')}: "
                      f"{vuln.get('VulnerabilityID')}",
                file=target_file,
                line=None,
                category="dependency",
                description=(vuln.get("Title") or vuln.get("Description") or "")[:500],
                raw=vuln,
                **_trivy_package_fields(vuln),
            ))
    meta["finding_count"] = len(findings)
    if not findings and not meta["error"]:
        meta["note"] = "no lockfile found or no vulnerable deps detected"
    return findings, meta


_SKIP_IMAGE_REFS = {"scratch"}


def _find_dockerfile_base_images(target: Path) -> list[str]:
    images: set[str] = set()
    stage_names: set[str] = set()
    for dockerfile in list(target.rglob("Dockerfile")) + list(target.rglob("Dockerfile.*")):
        if _is_noise_path(str(dockerfile.relative_to(target))):
            continue
        try:
            text = dockerfile.read_text(errors="ignore")
        except OSError:
            continue
        for match in re.finditer(
            r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$",
            text, re.IGNORECASE | re.MULTILINE,
        ):
            ref, stage_alias = match.group(1), match.group(2)
            if stage_alias:
                stage_names.add(stage_alias.lower())
            images.add(ref)
    # Multi-stage builds often `FROM builder-stage-name` in a later stage —
    # that's not a real pullable image, drop refs matching known stage aliases.
    images = {i for i in images if i.lower() not in stage_names and i.lower() not in _SKIP_IMAGE_REFS}
    return sorted(images)


def scan_trivy_docker_images(target: Path) -> tuple[list[Finding], dict[str, Any]]:
    """Scannt die in Dockerfiles referenzierten Base-Images auf bekannte CVEs.
    Baut NICHTS, zieht nur Metadaten/Layer der fertigen Basis-Images —
    kein beliebiger Code wird ausgeführt."""
    findings: list[Finding] = []
    meta = {"tool": "trivy-image", "ran": False, "error": None, "images_checked": []}

    images = _find_dockerfile_base_images(target)
    if not images:
        meta["note"] = "kein Dockerfile mit auswertbaren FROM-Zeilen gefunden"
        return findings, meta

    for image in images:
        if image.strip().startswith("-"):
            # Base-Image-Ref aus (fremdem, gescanntem!) Dockerfile-Inhalt
            # geparst — startet er mit '-', würde trivy ihn als Flag statt
            # als Image-Referenz interpretieren. Überspringen, nicht crashen.
            meta.setdefault("skipped_images", []).append(image)
            continue
        ok, out, err = run_tool(
            "trivy",
            ["trivy", "image", "--scanners", "vuln", "--format", "json", "--", image],
            cwd=target,
            timeout=300,
        )
        meta["images_checked"].append(image)
        if not ok:
            meta.setdefault("image_errors", {})[image] = err
            continue
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            meta.setdefault("image_errors", {})[image] = "could not parse trivy json"
            continue
        for result in data.get("Results", []) or []:
            for vuln in result.get("Vulnerabilities", []) or []:
                findings.append(Finding(
                    tool="trivy-image",
                    severity=_norm_severity(vuln.get("Severity", "low")),
                    rule_id=vuln.get("VulnerabilityID", "CVE-unknown"),
                    title=f"Base-Image {image}: {vuln.get('PkgName')}@"
                          f"{vuln.get('InstalledVersion')} — {vuln.get('VulnerabilityID')}",
                    file="Dockerfile",
                    line=None,
                    category="dependency",
                    description=(vuln.get("Title") or vuln.get("Description") or "")[:500],
                    raw=vuln,
                    **_trivy_package_fields(vuln),
                ))
    meta["ran"] = True
    meta["finding_count"] = len(findings)
    return findings, meta


# ---------------------------------------------------------------------------
# Checkov (IaC)
# ---------------------------------------------------------------------------

def scan_checkov(target: Path) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    meta = {"tool": "checkov", "ran": False, "error": None}

    ok, out, err = run_tool(
        "checkov",
        ["checkov", "-d", str(target), "--output", "json", "--quiet",
         "--compact", "--soft-fail"],
        cwd=target,
        timeout=600,
    )
    meta["ran"] = ok
    if not ok:
        meta["error"] = err
        return findings, meta

    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        meta["error"] = "could not parse checkov json (possibly no IaC files found)"
        return findings, meta

    reports = data if isinstance(data, list) else [data]
    for report in reports:
        for failed in report.get("results", {}).get("failed_checks", []) or []:
            findings.append(Finding(
                tool="checkov",
                severity=_norm_severity(failed.get("severity") or "medium"),
                rule_id=failed.get("check_id", "checkov.unknown"),
                title=failed.get("check_name", "IaC misconfiguration"),
                file=failed.get("file_path"),
                line=(failed.get("file_line_range") or [None])[0],
                category="iac",
                description=(failed.get("check_name") or "")[:500],
                raw=failed,
            ))
    meta["finding_count"] = len(findings)
    return findings, meta


# ---------------------------------------------------------------------------
# GuardDog (Stufe 0 — Malware-Gate: bösartige PyPI/npm-Pakete als Dependency)
# ---------------------------------------------------------------------------
#
# ACHTUNG Netzwerk: guarddog lädt zur Analyse die tatsächlichen Paket-Inhalte
# von PyPI/npm herunter (wie ein normales `pip install`/`npm install`) und
# fragt Metadaten bei der jeweiligen Registry ab. Das ist der einzige Schritt
# in dieser gesamten Pipeline mit Netzwerkzugriff zur Laufzeit (Trivy lädt nur
# vorab seine CVE-Datenbank). Es geht dabei NICHTS vom gescannten Zielcode
# selbst nach außen — nur Paketname+Version (aus requirements.txt/package.json)
# werden an die öffentliche Registry gesendet, exakt wie bei einer normalen
# Installation dieser Dependency auch.

_GUARDDOG_RISK_SEVERITY = {
    "high_risk": "critical",
    "suspicious": "high",
    "low": "low",
    "no_risks_detected": "info",
}


def _guarddog_risk_text(risk: Any) -> str:
    """One readable line per GuardDog risk. guarddog 3.x risk objects carry the text in
    threat_/capability_description and the place in *_location; the matched code snippet
    (often escaped bytes) is deliberately left out - it stays in raw."""
    if not isinstance(risk, dict):
        return str(risk)[:200]
    text = (risk.get("message") or risk.get("threat_description")
            or risk.get("capability_description") or risk.get("name") or "auffälliges Muster")
    where = risk.get("threat_location") or risk.get("capability_location") or risk.get("location")
    sev = risk.get("severity")
    out = str(text)
    if where:
        out += f" ({where})"
    if sev:
        out += f" [{sev}]"
    return out


def _parse_guarddog_json(out: str, ecosystem: str) -> tuple[list[Finding], str | None]:
    """Gibt (findings, parse_error_oder_None) zurück. Ein Parse-Fehler wird
    NICHT stillschweigend verschluckt — bei einem Malware-GATE muss ein
    kaputtes/unerwartetes Tool-Output sichtbar im Report auftauchen statt
    lautlos als 'keine Findings' (fail-open) durchzugehen."""
    findings: list[Finding] = []
    try:
        items = json.loads(out)
    except json.JSONDecodeError as e:
        return findings, f"could not parse guarddog json: {e}"
    if not isinstance(items, list):
        return findings, f"unexpected guarddog output shape (expected list, got {type(items).__name__})"

    for item in items:
        dep = item.get("dependency", "?")
        version = item.get("version", "?")
        result = item.get("result", {}) or {}
        risk = result.get("risk_score", {}) or {}
        label = risk.get("label", "no_risks_detected")
        if label not in _GUARDDOG_RISK_SEVERITY:
            # Unbekanntes Label (z.B. neue guarddog-Version) fail-closed als
            # 'high' behandeln statt still auf 'low' zu mappen — lieber ein
            # falscher Positiv-Fund als ein übersehener echter.
            severity = "high"
        else:
            severity = _GUARDDOG_RISK_SEVERITY[label]
        risks = result.get("risks") or []
        if label == "no_risks_detected" and not risks:
            continue  # kein Finding nötig, Paket unauffällig

        rule_ids = [r.get("rule_id") or r.get("threat_rule") or r.get("capability_rule")
                    or r.get("name") for r in risks if isinstance(r, dict)]
        rule_id = ", ".join(sorted(set(filter(None, rule_ids)))) or f"guarddog.{label}"
        findings.append(Finding(
            tool="guarddog",
            severity=severity,
            rule_id=rule_id,
            title=f"{ecosystem}-Paket {dep}@{version}: Risiko-Einstufung '{label}'",
            # result["path"] is guarddog's own temp download dir of the package (differs
            # every run, gone afterwards) - the package name is the stable location.
            file=f"{ecosystem}:{dep}",
            line=None,
            category="malware",
            description=(f"GuardDog-Score {risk.get('score', 0)}. "
                         + "; ".join(_guarddog_risk_text(r) for r in risks[:5])
                         )[:800],
            raw=item,
        ))
    return findings, None


# Control manifests with one well-known, harmless package each. If guarddog fails on the upload's
# manifest but succeeds on these, the failure is caused by the uploaded file; if it fails on these
# too, it's the network/proxy/registry. Decided by behaviour, not by parsing error text - error
# messages can echo manifest content, which the uploader controls.
_GUARDDOG_CONTROL = {"pypi": ("requirements.txt", "six==1.16.0\n"),
                     "npm": ("package.json", '{"dependencies": {"left-pad": "1.3.0"}}\n')}
_guarddog_control_cache: dict[str, bool] = {}


def _guarddog_control_ok(ecosystem: str) -> bool:
    if ecosystem not in _guarddog_control_cache:
        with tempfile.TemporaryDirectory(prefix="unified-scan-guarddog-control-") as tmp:
            name, content = _GUARDDOG_CONTROL[ecosystem]
            (Path(tmp) / name).write_text(content)
            ok, out, _err = run_tool(
                "guarddog",
                ["guarddog", ecosystem, "verify", "--output-format", "json", "--", tmp],
                cwd=Path(tmp), timeout=180,
            )
            _guarddog_control_cache[ecosystem] = ok and _parse_guarddog_json(out, ecosystem)[1] is None
    return _guarddog_control_cache[ecosystem]


_MANIFEST_NAMES = {"pypi": re.compile(r"^requirements.*\.txt$", re.IGNORECASE),
                   "npm": re.compile(r"^package\.json$")}


def _manifests(target: Path, ecosystem: str) -> list[str]:
    pattern = _MANIFEST_NAMES[ecosystem]
    return sorted(str(p.relative_to(target)) for p in _iter_files(target)
                  if pattern.match(p.name) and "node_modules" not in p.relative_to(target).parts)


def _broken_package_json(target: Path) -> list[str]:
    broken = []
    for rel in _manifests(target, "npm"):
        try:
            data = json.loads((target / rel).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            broken.append(rel)
            continue
        if not isinstance(data, dict):
            broken.append(rel)
    return broken


def _unscannable_manifest(rel: str, reason: str) -> Finding:
    return Finding(
        tool="guarddog",
        severity="critical",
        rule_id="unscannable.manifest",
        title=f"Abhängigkeitsliste nicht prüfbar: {rel}",
        file=rel,
        line=None,
        category="unscannable",
        description=f"Dependency manifest could not be checked for malicious packages - fix its "
                    f"syntax and upload again. ({reason})"[:800],
    )


def scan_guarddog(target: Path) -> tuple[list[Finding], dict[str, Any]]:
    """Prüft alle PyPI/npm-Dependencies im Projekt auf bösartige Pakete
    (Typosquatting, verdächtige Install-Scripts, Daten-Exfiltration-Muster,
    Obfuskierung) — unabhängig von bekannten CVEs (das deckt bereits Trivy ab).
    Läuft rekursiv über das ganze Zielverzeichnis, findet requirements.txt/
    package.json egal wo im Baum."""
    findings: list[Finding] = []
    meta: dict[str, Any] = {"tool": "guarddog", "ran": False, "error": None, "ecosystems_checked": []}

    if shutil.which("guarddog") is None:
        meta["error"] = "guarddog not found in PATH"
        return findings, meta

    flagged: set[str] = set()
    for rel in _broken_package_json(target):
        findings.append(_unscannable_manifest(rel, "package.json is not valid JSON"))
        flagged.add(rel)

    any_ran = False
    for ecosystem in ("pypi", "npm"):
        ok, out, err = run_tool(
            "guarddog",
            ["guarddog", ecosystem, "verify", "--output-format", "json", "--", str(target)],
            cwd=target,
            timeout=900,
        )
        if ok:
            parsed, parse_error = _parse_guarddog_json(out, ecosystem)
            if not parse_error:
                any_ran = True
                meta["ecosystems_checked"].append(ecosystem)
                findings += parsed
                continue
            err = parse_error
        # A failure caused by the uploaded manifest itself would otherwise switch off the
        # malware check per file - that blocks as "unscannable". Network/proxy trouble is
        # infrastructure and only gets reported as an error.
        manifests = _manifests(target, ecosystem)
        if not manifests or not _guarddog_control_ok(ecosystem):
            meta.setdefault("ecosystem_errors", {})[ecosystem] = err
            continue
        named = [m for m in manifests if m in (err or "")]
        for rel in named or manifests:
            if rel not in flagged:
                findings.append(_unscannable_manifest(rel, (err or "")[:300]))
                flagged.add(rel)
        meta.setdefault("manifest_errors", {})[ecosystem] = err

    meta["ran"] = any_ran or bool(flagged)
    if not meta["ran"]:
        meta["error"] = meta.get("error") or "weder pypi- noch npm-Scan liefen erfolgreich durch"
    meta["finding_count"] = len(findings)
    if any_ran and not findings:
        meta["note"] = "keine requirements.txt/package.json gefunden oder alle Pakete unauffällig"
    return findings, meta




# ---------------------------------------------------------------------------
# olevba (Office-VBA-Makro-Scan: .doc/.xls/.ppt-Familie mit Makros)
# ---------------------------------------------------------------------------
# Bearer/trufflehog/trivy/checkov/guarddog decken alle KEINE Office-Makros ab
# (Bearer parst kein VBA-AST, trufflehog würde nur Klartext-Secrets im Byte-
# Stream finden, nicht Makro-LOGIK). oletools/olevba ist ein dediziertes,
# offline laufendes Tool dafür (keine Cloud-Abfrage, reine lokale Analyse der
# OLE/OOXML-Struktur + VBA-P-Code-Dekompilierung).

_OFFICE_MACRO_EXTENSIONS = {
    ".doc", ".dot", ".docm", ".dotm",
    ".xls", ".xlt", ".xlsm", ".xltm", ".xlsb", ".xlam",
    ".ppt", ".pot", ".pps", ".pptm", ".potm", ".ppsm", ".ppam",
}

# Suspicious-Keywords, die olevba meldet, aber die für sich genommen sehr
# häufig FALSE POSITIVES in legitimen Business-Makros sind (Dateizugriff,
# Registry-Lesen etc.) vs. Keywords die praktisch nur in bösartigen Makros
# vorkommen (Shell-Ausführung, Remote-Download, Prozess-Injection,
# PowerShell-Aufruf). Grobes, aber begründetes Mapping statt "alles gleich
# hoch" (das würde den Report für jedes Makro mit z.B. nur Open/Write auf
# 'kritisch' hochziehen und den Report für Nutzer wertlos machen).
_OLEVBA_CRITICAL_KEYWORDS = {
    "shell", "wscript.shell", "shellexecute", "shellexecutea", "shell.application",
    "powershell", "start-process", "invoke-expression",
    "urldownloadtofilea", "net.webclient", "downloadfile", "downloadstring",
    "msxml2.xmlhttp", "microsoft.xmlhttp", "msxml2.serverxmlhttp",
    "createthread", "createuserthread", "virtualalloc", "virtualallocex",
    "writeprocessmemory", "rtlmovememory", "setcontextthread", "queueapcthread",
}
_OLEVBA_HIGH_KEYWORDS = {
    "createobject", "getobject", "new-object",
    "chr", "chrb", "chrw", "strreverse", "xor", "callbyname",
}


def _olevba_finding_severity(keyword_type: str, keyword: str) -> str | None:
    """None bedeutet: kein eigenes Finding (z.B. IOC — zu rauschanfällig,
    siehe unten)."""
    if keyword_type == "AutoExec":
        return "high"  # Makro läuft automatisch beim Öffnen — an sich schon
        # ein Warnsignal in einem "Dashboard mit echten Daten", das i.d.R.
        # gar keine Makros braucht.
    if keyword_type == "Suspicious":
        kw = (keyword or "").strip().lower()
        if kw in _OLEVBA_CRITICAL_KEYWORDS:
            return "critical"
        if kw in _OLEVBA_HIGH_KEYWORDS:
            return "high"
        return "medium"
    if keyword_type in ("Hex String", "Base64 String"):
        return "low"  # nur Hinweis auf Obfuskierung, kein direkter Beweis
    if keyword_type == "Dridex String":
        return "critical"  # Dridex ist eine reale Banking-Malware-Familie mit
        # spezifischen Obfuskierungsmustern, die olevba direkt erkennt — anders
        # als generisches Hex/Base64 ist das kein Rauschen, sondern ein
        # konkreter Malware-Signaturtreffer.
    return None  # IOC, VBA String etc. — nicht als Einzelfinding, siehe meta


def _find_office_macro_files(target: Path) -> list[Path]:
    """Case-insensitiver Vergleich der Datei-Endung (nicht rglob-Pattern-Matching):
    auf Linux ist rglob("*.docm") case-sensitiv und würde ein absichtlich groß
    geschriebenes 'Invoice.DOCM' (in Windows-Umgebungen üblich, z.B. E-Mail-
    Anhänge) unsichtbar am Scanner vorbeischleusen — verifiziert.
    Zusätzlich nach Inhalt: OLE-Container (D0CF11E0) und OOXML-ZIPs mit
    vbaProject.bin werden auch mit harmloser Endung (.bin/.dat/...) geprüft."""
    found: list[Path] = []
    for path in _iter_files(target):
        if path.suffix.lower() in _OFFICE_MACRO_EXTENSIONS:
            found.append(path)
            continue
        head = _head(path, 8)
        if head == _OLE_MAGIC:
            found.append(path)
        elif head.startswith(b"PK\x03\x04"):
            names = _zip_names(path) or []
            if any(n.lower().endswith("vbaproject.bin") for n in names):
                found.append(path)
    return sorted(set(found))


def scan_olevba(target: Path) -> tuple[list[Finding], dict[str, Any]]:
    """Scannt alle Office-Dateien mit Makro-fähiger Endung (.doc*/.xls*/.ppt*)
    im Zielverzeichnis auf VBA-Makros und deren verdächtige API-Aufrufe.
    Läuft pro Datei einzeln (olevba -r über einen ganzen Ordner würde JEDE
    Textdatei als Pseudo-Makro einlesen und massives Rauschen erzeugen —
    verifiziert; deshalb gezielte Dateisuche statt rekursivem Tool-Flag)."""
    findings: list[Finding] = []
    meta: dict[str, Any] = {
        "tool": "olevba", "ran": False, "error": None,
        "files_scanned": 0, "ioc_count_not_reported_as_findings": 0,
    }

    if shutil.which("olevba") is None:
        meta["error"] = "olevba not found in PATH"
        return findings, meta

    office_files = _find_office_macro_files(target)
    meta["ran"] = True
    if not office_files:
        meta["note"] = "keine Office-Dateien mit Makro-fähiger Endung gefunden"
        meta["finding_count"] = 0
        return findings, meta

    for office_file in office_files:
        rel_path = str(office_file.relative_to(target)) if office_file.is_relative_to(target) else str(office_file)
        ok, out, err = run_tool(
            "olevba", ["olevba", "-j", "--", str(office_file)],
            cwd=target, timeout=180,
        )
        meta["files_scanned"] += 1
        if not ok:
            meta.setdefault("file_errors", {})[rel_path] = err
            continue
        if not out.strip():
            meta.setdefault("file_errors", {})[rel_path] = f"olevba produced no output ({err.strip()[:200]})"
            continue
        try:
            entries = json.loads(out)
        except json.JSONDecodeError as e:
            meta.setdefault("file_errors", {})[rel_path] = f"could not parse olevba json: {e}"
            continue
        if not isinstance(entries, list):
            meta.setdefault("file_errors", {})[rel_path] = "unexpected olevba output shape"
            continue

        for entry in entries:
            if not isinstance(entry, dict) or entry.get("type") == "MetaInformation":
                continue
            if entry.get("type") == "msg":
                # olevba's own internal-crash channel (e.g. malformed/malicious OLE
                # header): valid JSON, but no 'macros'/'analysis' for this file at
                # all. Silently treating this as "no findings" would fail-open
                # exactly on the files most likely to be a deliberately broken
                # malware sample — must surface as a visible error instead.
                # NOTE: olevba also emits benign informational WARNING-level msg
                # entries on otherwise fully-successful scans (e.g. "VBA stomping
                # cannot be detected for files in memory") — verified these do
                # NOT indicate a failed scan (the same file still yields real
                # findings alongside them), so only ERROR+ level is a real failure.
                level = entry.get("level", "ERROR")
                if level == "WARNING":
                    continue
                msg = entry.get("msg", "unknown olevba internal message")
                meta.setdefault("file_errors", {})[rel_path] = f"olevba internal {level}: {msg}"
                continue
            if entry.get("error"):
                meta.setdefault("file_errors", {})[rel_path] = entry["error"]
                continue
            for item in (entry.get("analysis") or []):
                keyword_type = item.get("type", "")
                keyword = item.get("keyword", "")
                if keyword_type == "IOC":
                    meta["ioc_count_not_reported_as_findings"] += 1
                    continue
                severity = _olevba_finding_severity(keyword_type, keyword)
                if severity is None:
                    continue
                findings.append(Finding(
                    tool="olevba",
                    severity=severity,
                    rule_id=f"olevba.{keyword_type.lower().replace(' ', '_')}.{keyword}"[:120],
                    title=f"VBA-Makro in {rel_path}: {item.get('description', keyword_type)}",
                    file=rel_path,
                    line=None,
                    category="malware",
                    description=f"Keyword: {keyword!r} | {item.get('description', '')}"[:800],
                    raw=item,
                ))

    # An Office file olevba cannot analyse (crash, encrypted, timeout) hides its macros - that
    # blocks as "unscannable" instead of passing as a partly checked upload.
    for rel_path, reason in sorted((meta.get("file_errors") or {}).items()):
        findings.append(Finding(
            tool="olevba",
            severity="critical",
            rule_id="unscannable.office-file",
            title=f"Office-Datei nicht prüfbar: {rel_path}",
            file=rel_path,
            line=None,
            category="unscannable",
            description=f"Office file could not be analysed for macros - save it again as a normal "
                        f"unencrypted file and upload again. ({str(reason)[:300]})"[:800],
        ))

    meta["finding_count"] = len(findings)
    if meta["files_scanned"] and not findings:
        if meta.get("file_errors"):
            # Genau der Fall, den der Crash-Fix oben abfängt: irreführend, "note"
            # nach Fehlern klingen zu lassen wie "alles geprüft, sauber" — die
            # betroffene(n) Datei(en) wurden effektiv NICHT durchsucht.
            meta["note"] = ("Achtung: bei "
                             f"{len(meta['file_errors'])} Datei(en) ist olevba "
                             "abgebrochen (siehe tools.olevba.file_errors) — "
                             "'0 Findings' bezieht sich nur auf die restlichen, "
                             "erfolgreich gescannten Dateien, nicht auf diese.")
        else:
            meta["note"] = "Office-Dateien gefunden, keine AutoExec/Suspicious/obfuskierten Makro-Inhalte"
    return findings, meta


def compute_criticality(findings: list[Finding]) -> dict[str, Any]:
    scored = [f for f in findings if not f.excluded_from_score]
    excluded_count = len(findings) - len(scored)

    by_sev = {s: 0 for s in SEVERITY_ORDER}
    by_category: dict[str, int] = {}
    for f in scored:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1

    raw_score = sum(SEVERITY_WEIGHT[s] * n for s, n in by_sev.items())
    score = min(100, raw_score)

    if by_sev["critical"] > 0 or score >= 80:
        verdict = "RED — nicht live nehmen, kritische Findings zuerst fixen"
    elif by_sev["high"] > 0 or score >= 40:
        verdict = "GELB — vor Live-Gang fixen, dokumentierte Ausnahme sonst nötig"
    elif score >= 10:
        verdict = "GELB-GRÜN — vertretbar mit Nacharbeit, nicht blockierend"
    else:
        verdict = "GRÜN — keine blockierenden Funde"

    return {
        "score_0_100": score,
        "raw_weighted_score": raw_score,
        "verdict": verdict,
        "by_severity": by_sev,
        "by_category": by_category,
        "total_findings": len(scored),
        "total_findings_including_excluded": len(findings),
        "excluded_as_test_or_fixture_code": excluded_count,
        "has_exposed_secrets": by_category.get("secret", 0) > 0,
        "has_dependency_cves": by_category.get("dependency", 0) > 0,
        "has_iac_issues": by_category.get("iac", 0) > 0,
    }


# ---------------------------------------------------------------------------
# Report-Rendering
# ---------------------------------------------------------------------------

def render_employee_markdown(findings: list[Finding], target: str, source_kind: str) -> str:
    lines = [
        f"# Security Findings — {target}",
        f"_Quelle: {source_kind}_",
        f"_Generiert: {datetime.now(timezone.utc).isoformat()}_",
        "",
        "Alle Punkte hier müssen geprüft/gefixt werden bevor das Projekt live geht.",
        "Sortiert nach Schweregrad. Mit 🧪 markierte Punkte liegen in Test-/Beispiel-/",
        "Vendor-Code und fließen NICHT in den internen Kritikalitäts-Score ein — trotzdem",
        "einen Blick wert, aber nicht blockierend.",
        "",
    ]
    grouped: dict[str, list[Finding]] = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)

    if not findings:
        lines.append("Keine Findings. ✅")
        return "\n".join(lines)

    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    for sev in SEVERITY_ORDER:
        items = grouped.get(sev, [])
        if not items:
            continue
        lines.append(f"## {icon.get(sev,'')} {sev.upper()} ({len(items)})")
        lines.append("")
        for f in items:
            loc = f.file or "?"
            if f.line:
                loc += f":{f.line}"
            noise_tag = " 🧪" if f.excluded_from_score else ""
            lines.append(f"- **[{f.tool}/{f.category}] {f.title}**{noise_tag}")
            lines.append(f"  - Datei: `{loc}`")
            lines.append(f"  - Regel: `{f.rule_id}`")
            if f.description:
                desc = f.description.replace("\n", " ").strip()
                lines.append(f"  - {desc}")
            lines.append("")
    return "\n".join(lines)


def render_criticality_markdown(crit: dict[str, Any], target: str, source_kind: str) -> str:
    lines = [
        f"# Interne Kritikalitäts-Übersicht — {target}",
        f"_Quelle: {source_kind}_",
        f"_Generiert: {datetime.now(timezone.utc).isoformat()}_",
        "",
        f"## Score: {crit['score_0_100']}/100",
        f"## Einschätzung: {crit['verdict']}",
        "",
        "### Aufschlüsselung nach Schweregrad",
        "(ohne Test-/Beispiel-/Vendor-Code — siehe Hinweis unten)",
        "",
    ]
    for sev in SEVERITY_ORDER:
        n = crit["by_severity"].get(sev, 0)
        if n:
            lines.append(f"- {sev}: {n}")
    lines.append("")
    lines.append("### Aufschlüsselung nach Kategorie")
    lines.append("")
    for cat, n in sorted(crit["by_category"].items(), key=lambda x: -x[1]):
        lines.append(f"- {cat}: {n}")
    lines.append("")
    lines.append("### Risiko-Flags")
    lines.append(f"- Secrets im Code gefunden: {'JA ⚠️' if crit['has_exposed_secrets'] else 'nein'}")
    lines.append(f"- Bekannte Dependency-CVEs: {'JA ⚠️' if crit['has_dependency_cves'] else 'nein'}")
    lines.append(f"- IaC-Fehlkonfigurationen: {'JA ⚠️' if crit['has_iac_issues'] else 'nein'}")
    lines.append("")
    lines.append(f"Findings im Score: {crit['total_findings']}")
    lines.append(f"Findings gesamt (inkl. Test-/Beispielcode): "
                 f"{crit['total_findings_including_excluded']}")
    lines.append(f"Davon als Test-/Beispielcode ausgeschlossen: "
                 f"{crit['excluded_as_test_or_fixture_code']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target",
                         help="Lokaler Pfad ODER Git-URL (https://, git@, ssh://) — "
                              "GitHub, GitLab, jeder Git-Host funktioniert")
    parser.add_argument("--out", default="unified-scan-report",
                         help="Ausgabeverzeichnis (default: ./unified-scan-report)")
    parser.add_argument("--no-severity-policy", action="store_true",
                         help="Bearer-Schweregrade unverändert lassen (severity_policy.json "
                              "nicht anwenden, z.B. zum Vergleich)")
    args = parser.parse_args()
    policy = [] if args.no_severity_policy else load_severity_policy()

    try:
        target, tmp_handle, source_kind = resolve_target(args.target)
    except ArchiveRejected as e:
        print(f"Archiv abgelehnt: {e}", file=sys.stderr)
        return 3
    except RuntimeError as e:
        print(f"Fehler: {e}", file=sys.stderr)
        return 2

    try:
        out_dir = Path(args.out).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        print(f"[unified-scan] Ziel: {args.target}")
        print(f"[unified-scan] Quelle: {source_kind}")
        print(f"[unified-scan] Lokaler Arbeitspfad: {target}")
        print(f"[unified-scan] Output: {out_dir}")

        tool_meta: dict[str, Any] = {}

        nested_findings, m = scan_nested_archives(target)
        tool_meta["nested_archives"] = m
        if nested_findings:
            print(f"[unified-scan] {len(nested_findings)} verschachtelte(s) Archiv(e) — "
                  "deren Inhalt wird von den meisten Tools nicht geprüft.")

        print("[0/7] guarddog (Malware-Gate: bösartige PyPI/npm-Pakete)...")
        malware_findings, m = scan_guarddog(target)
        _relativize_findings(malware_findings, target)
        tool_meta["guarddog"] = m
        print(f"      -> {m.get('finding_count', 0)} findings"
              + (f" (ERROR: {m['error']})" if m.get("error") else ""))

        malware_findings = nested_findings + malware_findings
        malware_critical = [f for f in malware_findings
                            if f.severity == "critical" and f.category == "malware"]
        if malware_critical:
            print()
            print(f"[unified-scan] MALWARE-GATE FEHLGESCHLAGEN: "
                  f"{len(malware_critical)} bösartige(s) Paket(e) gefunden.")
            print("[unified-scan] Security-Scan wird NICHT ausgeführt — "
                  "erst Malware-Befunde klären.")
            for f in malware_critical:
                print(f"  - {f.title}")
            combined = {
                "target": args.target,
                "source_kind": source_kind,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "gate": "malware",
                "gate_passed": False,
                "tools": tool_meta,
                "employee_findings": [f.to_dict() for f in malware_findings],
            }
            (out_dir / "combined_report.json").write_text(json.dumps(combined, indent=2))
            (out_dir / "employee_findings.md").write_text(
                render_employee_markdown(malware_findings, args.target, source_kind))
            print(f"[unified-scan] Report in: {out_dir / 'employee_findings.md'}")
            return 1

        all_findings: list[Finding] = list(malware_findings)


        print("[1/7] bearer (SAST + Privacy)...")
        f, m = scan_bearer(target, out_dir / "_bearer_raw.json", policy)
        all_findings += f
        tool_meta["bearer"] = m
        print(f"      -> {m.get('finding_count', 0)} findings"
              + (f" (ERROR: {m['error']})" if m.get("error") else ""))

        print("[2/7] trufflehog (secrets, inkl. Git-History wenn möglich)...")
        f, m = scan_trufflehog(target)
        all_findings += f
        tool_meta["trufflehog"] = m
        print(f"      -> {m.get('finding_count', 0)} findings [{m.get('mode')}]"
              + (f" (ERROR: {m['error']})" if m.get("error") else ""))

        print("[3/7] trivy (dependency CVEs)...")
        f, m = scan_trivy(target)
        all_findings += f
        tool_meta["trivy"] = m
        print(f"      -> {m.get('finding_count', 0)} findings"
              + (f" (ERROR: {m['error']})" if m.get("error") else ""))

        print("[4/7] trivy (Docker-Base-Image-CVEs, falls Dockerfile vorhanden)...")
        f, m = scan_trivy_docker_images(target)
        all_findings += f
        tool_meta["trivy_docker_images"] = m
        print(f"      -> {m.get('finding_count', 0)} findings"
              + (f" [images: {', '.join(m.get('images_checked', [])) or '-'}]"))

        print("[5/7] checkov (IaC)...")
        f, m = scan_checkov(target)
        all_findings += f
        tool_meta["checkov"] = m
        print(f"      -> {m.get('finding_count', 0)} findings"
              + (f" (ERROR: {m['error']})" if m.get("error") else ""))

        print("[6/7] olevba (Office-VBA-Makros, falls .doc*/.xls*/.ppt* vorhanden)...")
        f, m = scan_olevba(target)
        all_findings += f
        tool_meta["olevba"] = m
        print(f"      -> {m.get('finding_count', 0)} findings"
              + (f" [{m.get('files_scanned', 0)} Datei(en) geprüft]"
                 if m.get("ran") else "")
              + (f" (ERROR: {m['error']})" if m.get("error") else ""))

        _relativize_findings(all_findings, target)
        criticality = compute_criticality(all_findings)

        combined = {
            "target": args.target,
            "source_kind": source_kind,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "gate": "malware",
            "gate_passed": True,
            "tools": tool_meta,
            "employee_findings": [f.to_dict() for f in all_findings],
            "internal_criticality": criticality,
        }

        (out_dir / "combined_report.json").write_text(json.dumps(combined, indent=2))
        (out_dir / "employee_findings.md").write_text(
            render_employee_markdown(all_findings, args.target, source_kind))
        (out_dir / "internal_criticality.md").write_text(
            render_criticality_markdown(criticality, args.target, source_kind))

        print()
        print(f"[unified-scan] Fertig. {len(all_findings)} Findings insgesamt "
              f"({criticality['excluded_as_test_or_fixture_code']} davon Test-/Beispielcode, "
              f"nicht im Score).")
        print(f"[unified-scan] Score: {criticality['score_0_100']}/100 — {criticality['verdict']}")
        print(f"[unified-scan] Reports in: {out_dir}")
        print(f"  - {out_dir / 'employee_findings.md'}")
        print(f"  - {out_dir / 'internal_criticality.md'}")
        print(f"  - {out_dir / 'combined_report.json'}")

        return 1 if criticality["by_severity"].get("critical", 0) > 0 else 0
    finally:
        if tmp_handle is not None:
            tmp_handle.cleanup()


if __name__ == "__main__":
    sys.exit(main())
