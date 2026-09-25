# unified-scan

Erweiterung dieses Bearer-Forks: kombiniert Bearer mit drei weiteren
Open-Source-Scannern zu einem einzigen Kommando mit zwei Report-Ebenen.

## Warum

Bearer allein deckt SAST + Privacy/Datenfluss ab (seine Kernstärke), aber
nicht:
- Secrets in Code/Git-History
- bekannte CVEs in Dependencies (SCA)
- IaC-Fehlkonfigurationen (Terraform/K8s/Docker/CloudFormation)

Genau das sind die häufigsten Lecks bei schnell mit AI-Tools gebauten Apps
(ChatGPT/Claude-Dashboards etc.), die live mit echten Daten laufen.

## Was läuft

| Tool | Zweck | Läuft lokal? |
|---|---|---|
| [bearer](https://github.com/bearer/bearer) | SAST + Privacy/Datenfluss (PII/PHI) | ja |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | Secrets im Code + Git-History | ja |
| [trivy](https://github.com/aquasecurity/trivy) | Dependency-CVEs (SCA) | ja (CVE-DB-Sync via Netz) |
| [checkov](https://github.com/bridgecrewio/checkov) | IaC-Fehlkonfigurationen | ja |

Kein Tool hier braucht eine Cloud-API oder ein LLM. Kein Code verlässt die
Maschine. Fehlende Tools werden übersprungen (nicht fatal), Fehler landen
im Report unter `tools.<name>.error`.

## Installation der Abhängigkeiten

```bash
# bearer (dieser Fork oder offizielles Release)
curl -sfL https://raw.githubusercontent.com/bearer/bearer/main/contrib/install.sh | sh

# trufflehog
curl -sSL https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_<version>_linux_amd64.tar.gz | tar xz
sudo mv trufflehog /usr/local/bin/

# trivy
curl -sSL https://github.com/aquasecurity/trivy/releases/latest/download/trivy_<version>_Linux-64bit.tar.gz | tar xz
sudo mv trivy /usr/local/bin/

# checkov
pip install checkov
```

## Nutzung

```bash
python3 contrib/unified-scan/unified_scan.py /pfad/zum/projekt --out ./report
```

Erzeugt in `./report/`:

- **`employee_findings.md`** — Ebene 1: was muss gefixt werden bevor live
  geht. Nach Schweregrad sortiert, mit Datei:Zeile, Regel-ID, Beschreibung.
  Zum Teilen mit dem Entwickler/Mitarbeiter gedacht.

- **`internal_criticality.md`** — Ebene 2: interne Kritikalitäts-Skala
  (Score 0-100, Ampel-Verdict RED/GELB/GRÜN, Kategorie-Breakdown,
  Risiko-Flags für Secrets/CVEs/IaC). Nicht zum Teilen gedacht, für die
  eigene Go/No-Go-Entscheidung.

- **`combined_report.json`** — beide Ebenen als strukturierte Daten für
  eigene Weiterverarbeitung (CI-Gate, Dashboard, etc.).

Exit-Code `1` wenn mindestens ein `critical`-Finding vorliegt (CI-tauglich),
sonst `0`.

## Beispiel-Score-Logik

```
score = min(100, Σ severity_weight(finding))
  critical = 40, high = 20, medium = 8, low = 2

RED    : mind. 1 critical, oder Score >= 80
GELB   : mind. 1 high, oder Score >= 40
GELB-GRÜN: Score >= 10
GRÜN   : sonst
```

Score-Gewichtung ist bewusst simpel und in `compute_criticality()`
zentral anpassbar (z.B. andere Gewichte pro Team-Risikoappetit).
