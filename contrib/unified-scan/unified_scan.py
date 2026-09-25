#!/usr/bin/env python3
"""
unified_scan.py — Bearer-Fork Erweiterung: kombinierter Security-Scan
für "vibe coded" Anwendungen.

Orchestriert:
  - bearer      (SAST + Privacy/Datenfluss)   -> Kernstärke: wo fließen sensible Daten hin
  - trufflehog  (Secrets in Code + Git-History)
  - trivy       (Dependency-CVEs / SCA, braucht Lockfile)
  - checkov     (IaC-Fehlkonfigurationen: Terraform/K8s/Docker/CloudFormation)

Alle vier laufen komplett lokal, kein Cloud-Call, kein Code verlässt die
Maschine (sofern man `bearer explain`/AI-Features NICHT nutzt, die sind
hier bewusst nicht eingebunden).

Output: zwei Report-Ebenen in einem JSON, plus lesbares Markdown je Ebene.

  1. "employee_findings"   -> was MUSS gefixt werden bevor live geht
                              (nur tatsächlich actionable Findings,
                               nach Severity sortiert, mit Datei:Zeile)

  2. "internal_criticality" -> interne Kritikalitäts-Einschätzung
                               (Scoring 0-100, Kategorie-Breakdown,
                                Ampel-Einschätzung für Go/No-Go)

Nutzung:
  python3 unified_scan.py /pfad/zum/projekt [--out report_dir]

Erfordert im PATH: bearer, trufflehog, trivy, checkov
(fehlende Tools werden übersprungen, nicht fatal - Report vermerkt das).
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Datenmodell
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}


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


def run_tool(name: str, cmd: list[str], cwd: Path, timeout: int = 900) -> tuple[bool, str, str]:
    """Run external tool, return (ok, stdout, stderr). Never raises."""
    if shutil.which(cmd[0]) is None:
        return False, "", f"{cmd[0]} not found in PATH"
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout
        )
        return True, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return False, "", f"{name} timed out after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return False, "", f"{name} failed: {e}"


# ---------------------------------------------------------------------------
# Bearer (SAST + Privacy)
# ---------------------------------------------------------------------------

def scan_bearer(target: Path, tmp_json: Path) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    meta = {"tool": "bearer", "ran": False, "error": None}

    ok, out, err = run_tool(
        "bearer",
        ["bearer", "scan", str(target), "--format", "json",
         "--output", str(tmp_json), "--quiet"],
        cwd=target,
    )
    meta["ran"] = ok
    if not ok:
        meta["error"] = err
        return findings, meta

    if not tmp_json.exists():
        meta["error"] = "bearer produced no output file"
        return findings, meta

    try:
        data = json.loads(tmp_json.read_text())
    except Exception as e:  # noqa: BLE001
        meta["error"] = f"could not parse bearer json: {e}"
        return findings, meta

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
                description=(item.get("description") or "")[:500],
                raw=item,
            ))
    meta["finding_count"] = len(findings)
    return findings, meta


# ---------------------------------------------------------------------------
# Trufflehog (Secrets)
# ---------------------------------------------------------------------------

def scan_trufflehog(target: Path) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    meta = {"tool": "trufflehog", "ran": False, "error": None}

    ok, out, err = run_tool(
        "trufflehog",
        ["trufflehog", "filesystem", str(target), "--json", "--no-update"],
        cwd=target,
    )
    meta["ran"] = ok
    if not ok:
        meta["error"] = err
        return findings, meta

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
        meta_data = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        verified = item.get("Verified", False)
        findings.append(Finding(
            tool="trufflehog",
            severity="critical" if verified else "high",
            rule_id=item.get("DetectorName", "secret"),
            title=f"Exposed secret: {item.get('DetectorName', 'unknown')}"
                  + (" (verified live)" if verified else " (unverified pattern)"),
            file=meta_data.get("file"),
            line=meta_data.get("line"),
            category="secret",
            description="Hardcoded credential/secret found in source. "
                         + ("Confirmed valid against provider API."
                            if verified else
                            "Pattern-matched, not live-verified — check manually."),
            raw=item,
        ))
    meta["finding_count"] = len(findings)
    return findings, meta


# ---------------------------------------------------------------------------
# Trivy (Dependency CVEs / SCA)
# ---------------------------------------------------------------------------

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
            ))
    meta["finding_count"] = len(findings)
    if not findings and not meta["error"]:
        meta["note"] = "no lockfile found or no vulnerable deps detected"
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
         "--compact"],
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
# Kritikalitäts-Scoring (Ebene 2: interne Einschätzung)
# ---------------------------------------------------------------------------

def compute_criticality(findings: list[Finding]) -> dict[str, Any]:
    by_sev = {s: 0 for s in SEVERITY_ORDER}
    by_category: dict[str, int] = {}
    for f in findings:
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
        "total_findings": len(findings),
        "has_exposed_secrets": by_category.get("secret", 0) > 0,
        "has_dependency_cves": by_category.get("dependency", 0) > 0,
        "has_iac_issues": by_category.get("iac", 0) > 0,
    }


# ---------------------------------------------------------------------------
# Report-Rendering
# ---------------------------------------------------------------------------

def render_employee_markdown(findings: list[Finding], target: str) -> str:
    lines = [
        f"# Security Findings — {target}",
        f"_Generiert: {datetime.now(timezone.utc).isoformat()}_",
        "",
        "Alle Punkte hier müssen geprüft/gefixt werden bevor das Projekt live geht.",
        "Sortiert nach Schweregrad.",
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
            lines.append(f"- **[{f.tool}/{f.category}] {f.title}**")
            lines.append(f"  - Datei: `{loc}`")
            lines.append(f"  - Regel: `{f.rule_id}`")
            if f.description:
                desc = f.description.replace("\n", " ").strip()
                lines.append(f"  - {desc}")
            lines.append("")
    return "\n".join(lines)


def render_criticality_markdown(crit: dict[str, Any], target: str) -> str:
    lines = [
        f"# Interne Kritikalitäts-Übersicht — {target}",
        f"_Generiert: {datetime.now(timezone.utc).isoformat()}_",
        "",
        f"## Score: {crit['score_0_100']}/100",
        f"## Einschätzung: {crit['verdict']}",
        "",
        "### Aufschlüsselung nach Schweregrad",
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
    lines.append(f"Gesamtanzahl Findings: {crit['total_findings']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", help="Pfad zum zu scannenden Projekt")
    parser.add_argument("--out", default="unified-scan-report",
                         help="Ausgabeverzeichnis (default: ./unified-scan-report)")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"Fehler: {target} ist kein Verzeichnis", file=sys.stderr)
        return 2

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[unified-scan] Ziel: {target}")
    print(f"[unified-scan] Output: {out_dir}")

    all_findings: list[Finding] = []
    tool_meta: dict[str, Any] = {}

    print("[1/4] bearer (SAST + Privacy)...")
    f, m = scan_bearer(target, out_dir / "_bearer_raw.json")
    all_findings += f
    tool_meta["bearer"] = m
    print(f"      -> {m.get('finding_count', 0)} findings"
          + (f" (ERROR: {m['error']})" if m.get("error") else ""))

    print("[2/4] trufflehog (secrets)...")
    f, m = scan_trufflehog(target)
    all_findings += f
    tool_meta["trufflehog"] = m
    print(f"      -> {m.get('finding_count', 0)} findings"
          + (f" (ERROR: {m['error']})" if m.get("error") else ""))

    print("[3/4] trivy (dependency CVEs)...")
    f, m = scan_trivy(target)
    all_findings += f
    tool_meta["trivy"] = m
    print(f"      -> {m.get('finding_count', 0)} findings"
          + (f" (ERROR: {m['error']})" if m.get("error") else ""))

    print("[4/4] checkov (IaC)...")
    f, m = scan_checkov(target)
    all_findings += f
    tool_meta["checkov"] = m
    print(f"      -> {m.get('finding_count', 0)} findings"
          + (f" (ERROR: {m['error']})" if m.get("error") else ""))

    criticality = compute_criticality(all_findings)

    combined = {
        "target": str(target),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tools": tool_meta,
        "employee_findings": [f.to_dict() for f in all_findings],
        "internal_criticality": criticality,
    }

    (out_dir / "combined_report.json").write_text(json.dumps(combined, indent=2))
    (out_dir / "employee_findings.md").write_text(
        render_employee_markdown(all_findings, str(target)))
    (out_dir / "internal_criticality.md").write_text(
        render_criticality_markdown(criticality, str(target)))

    print()
    print(f"[unified-scan] Fertig. {len(all_findings)} Findings insgesamt.")
    print(f"[unified-scan] Score: {criticality['score_0_100']}/100 — {criticality['verdict']}")
    print(f"[unified-scan] Reports in: {out_dir}")
    print(f"  - {out_dir / 'employee_findings.md'}")
    print(f"  - {out_dir / 'internal_criticality.md'}")
    print(f"  - {out_dir / 'combined_report.json'}")

    return 1 if criticality["by_severity"].get("critical", 0) > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
