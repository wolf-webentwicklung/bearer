# unified-scan

Erweiterung dieses Bearer-Forks: kombiniert Bearer mit drei weiteren
Open-Source-Scannern zu einem einzigen Kommando mit zwei Report-Ebenen.

## Warum

Bearer allein deckt SAST + Privacy/Datenfluss ab (seine Kernstärke), aber
nicht:
- Secrets in Code/Git-History
- bekannte CVEs in Dependencies (SCA) + Docker-Base-Images
- IaC-Fehlkonfigurationen (Terraform/K8s/Docker/CloudFormation)

Genau das sind die häufigsten Lecks bei schnell mit AI-Tools gebauten Apps
(ChatGPT/Claude-Dashboards, R/Shiny-Dashboards etc.), die live mit echten
Daten laufen.

## Was läuft

| Tool | Zweck | Läuft lokal? |
|---|---|---|
| [bearer](https://github.com/bearer/bearer) | SAST + Privacy/Datenfluss (PII/PHI) | ja |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | Secrets im Code + Git-History | ja |
| [trivy](https://github.com/aquasecurity/trivy) | Dependency-CVEs (SCA) + Docker-Base-Image-CVEs | ja (CVE-DB-Sync via Netz) |
| [checkov](https://github.com/bridgecrewio/checkov) | IaC-Fehlkonfigurationen | ja |

Kein Tool hier braucht eine Cloud-API oder ein LLM. Kein Code verlässt die
Maschine. Fehlende Tools werden übersprungen (nicht fatal), Fehler landen
im Report unter `tools.<name>.error`.

## Ziel: lokaler Ordner, Git oder nicht, oder eine Git-URL

Das Script ist nicht auf GitHub oder auf Git überhaupt festgelegt:

- **Lokaler Ordner, kein Git** — z.B. ein R/Shiny-Projekt, das nie in
  Versionskontrolle war. Läuft genauso, nur `trufflehog` scannt dann nur
  den aktuellen Dateistand (kein History-Scan möglich, logisch, da keine
  History existiert).
- **Lokaler Ordner, ist ein Git-Repo** — `trufflehog` scannt automatisch
  die komplette Git-History mit, nicht nur den aktuellen Stand.
- **Git-URL** (`https://`, `git@`, `ssh://`) — GitHub, GitLab (auch
  selbstgehostet), Bitbucket, jeder Git-Host. Wird automatisch in ein
  Temp-Verzeichnis geklont, gescannt, danach automatisch aufgeräumt.

```bash
# lokaler Ordner (Git oder nicht, wird automatisch erkannt)
python3 contrib/unified-scan/unified_scan.py /pfad/zum/projekt --out ./report

# Git-URL, egal welcher Host
python3 contrib/unified-scan/unified_scan.py https://github.com/org/repo.git --out ./report
python3 contrib/unified-scan/unified_scan.py https://gitlab.com/org/repo.git --out ./report
python3 contrib/unified-scan/unified_scan.py git@gitlab.company.com:team/repo.git --out ./report
```

## Sprachgrenze von Bearer

Bearers SAST-Engine deckt aktuell JS/TS, Python, Ruby, Go, PHP, Java, C#
ab — **kein R**. Bei reinen R/Shiny-Projekten liefert `bearer` daher keine
oder kaum SAST-Findings, das ist erwartet und kein Fehler (steht im Report
unter `tools.bearer.note`). Secrets (trufflehog), Dependency-CVEs (trivy,
sofern `renv.lock` o.ä. erkannt wird) und IaC (checkov) laufen unabhängig
davon normal weiter, da die nicht auf Sprach-Parsing angewiesen sind.

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

# checkov (venv empfohlen — kollidiert gern mit System-pyOpenSSL)
python3 -m venv ~/.venvs/checkov
~/.venvs/checkov/bin/pip install checkov
sudo ln -sf ~/.venvs/checkov/bin/checkov /usr/local/bin/checkov

# git (für Git-URL-Ziele und History-Scan)
```

## Nutzung

```bash
python3 contrib/unified-scan/unified_scan.py <pfad-oder-git-url> --out ./report
```

Erzeugt in `./report/`:

- **`employee_findings.md`** — Ebene 1: was muss gefixt werden bevor live
  geht. Nach Schweregrad sortiert, mit Datei:Zeile, Regel-ID, Beschreibung.
  Zum Teilen mit dem Entwickler/Mitarbeiter gedacht. Findings in Test-/
  Beispiel-/Vendor-Code sind mit 🧪 markiert (bleiben sichtbar, fließen
  aber nicht in den Score ein, siehe unten).

- **`internal_criticality.md`** — Ebene 2: interne Kritikalitäts-Skala
  (Score 0-100, Ampel-Verdict RED/GELB/GRÜN, Kategorie-Breakdown,
  Risiko-Flags für Secrets/CVEs/IaC). Nicht zum Teilen gedacht, für die
  eigene Go/No-Go-Entscheidung.

- **`combined_report.json`** — beide Ebenen als strukturierte Daten für
  eigene Weiterverarbeitung (CI-Gate, Dashboard, etc.).

Exit-Code `1` wenn mindestens ein `critical`-Finding vorliegt (CI-tauglich),
sonst `0`.

## Test-/Beispielcode-Filter

Findings in Pfaden wie `test/`, `tests/`, `__tests__/`, `spec/`,
`fixtures/`, `vendor/`, `node_modules/`, `examples/`, `demo/`, `dist/`,
`build/` etc. verzerren die Kritikalitäts-Einschätzung nach oben, obwohl es
kein Code ist, der live läuft (z.B. absichtlich unsichere Übungs-Snippets
in Test-Repos). Diese Findings werden im Mitarbeiter-Report weiter
angezeigt (mit 🧪 markiert), fließen aber nicht in `internal_criticality`
ein. Die Pfad-Liste steht zentral in `NOISE_PATH_PATTERNS` im Script und
ist dort anpassbar.

Hinweis: Bearer filtert Test-Pfade oft schon selbst intern raus, bevor
Findings überhaupt bei uns ankommen — der Filter hier greift zusätzlich
für Tools wie Checkov, die das nicht selbst tun.

## Docker-Base-Image-Scan

Wenn `Dockerfile`/`Dockerfile.*` im Projekt liegen, werden die dort
referenzierten Base-Images (`FROM ...`-Zeilen) automatisch mit
`trivy image` auf bekannte CVEs geprüft — ohne irgendetwas zu bauen oder
auszuführen, nur Image-Metadaten/Layer werden gezogen. Multi-Stage-Builds
werden erkannt (Stage-Aliase wie `AS builder` fließen nicht als Image-Ref
ein). Relevant weil viele AI-gebaute Dashboards mit veralteten Docker-
Base-Images deployed werden (z.B. `python:3.9-slim`, `node:12-alpine`),
die selbst Dutzende bekannte CVEs mitbringen, unabhängig vom eigenen Code.

## Beispiel-Score-Logik

```
score = min(100, Σ severity_weight(finding))   # ohne Test-/Beispielcode
  critical = 40, high = 20, medium = 8, low = 2

RED    : mind. 1 critical, oder Score >= 80
GELB   : mind. 1 high, oder Score >= 40
GELB-GRÜN: Score >= 10
GRÜN   : sonst
```

Score-Gewichtung ist bewusst simpel und in `compute_criticality()`
zentral anpassbar (z.B. andere Gewichte pro Team-Risikoappetit).

## Sicherheit des Scan-Ziels selbst

Der `target`-Parameter (Git-URL oder lokaler Pfad) kommt von außen und wird
entsprechend behandelt: Git-URLs, die mit `-` beginnen (z.B.
`--upload-pack=...`), werden abgelehnt statt an `git clone` weitergereicht —
sonst könnte ein böswillig gewählter "Ziel-String" von Gits eigenem
Optionsparser als Flag statt als Repo-Adresse interpretiert werden
(Argument-Injection, potenziell mit lokaler Codeausführung). Zusätzlich wird
überall ein `--`-Separator vor dem eigentlichen Wert übergeben (`git clone`,
`trivy image`), auch für aus Dockerfile-Inhalten geparste Image-Referenzen.
`subprocess.run` läuft grundsätzlich mit Listen-Argumenten, nie `shell=True`
— klassische Shell-Injection über Metazeichen ist dadurch bereits
ausgeschlossen, das Dash-Problem ist eine eigene, git-/CLI-spezifische
Angriffsklasse, unabhängig von der Shell.

## Verifiziert gegen

- OWASP Juice Shop (lokal geklont): 552 kombinierte Findings über alle
  vier Tools, korrektes Scoring.
- OWASP NodeGoat (per Git-URL, ohne manuellen Klon): 212 Findings,
  inkl. 68 CVEs allein aus dem `node:12-alpine`-Base-Image.
- Lokaler Ordner ohne Git (simuliertes R/Shiny-Projekt): Secret im
  Filesystem-Modus gefunden, bearer korrekt leer (Sprache nicht
  unterstützt), sauber im Report vermerkt.
- Git-Repo mit Secret, das committed und in einem Folgecommit wieder
  "entfernt" wurde: trufflehog findet es weiterhin über den
  Git-History-Scan, Report warnt explizit dass Löschen im aktuellen
  Stand nicht reicht.
- Test-/Beispielcode-Filter: Findings in `test/`-Pfaden korrekt aus dem
  Score ausgeschlossen, im Mitarbeiter-Report aber weiter sichtbar
  markiert.
