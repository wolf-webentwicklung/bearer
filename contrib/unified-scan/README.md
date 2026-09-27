# unified-scan

Erweiterung dieses Bearer-Forks: kombiniert Bearer mit fünf weiteren
Open-Source-Scannern zu einem einzigen Kommando mit zwei Report-Ebenen,
vorgelagert durch ein Malware-Gate.

## Warum

Bearer allein deckt SAST + Privacy/Datenfluss ab (seine Kernstärke), aber
nicht:
- bösartige PyPI/npm-Pakete als Dependency (Malware-Gate, läuft ZUERST)
- Secrets in Code/Git-History
- bekannte CVEs in Dependencies (SCA) + Docker-Base-Images
- IaC-Fehlkonfigurationen (Terraform/K8s/Docker/CloudFormation)
- bösartige VBA-Makros in Office-Dateien (.doc*/.xls*/.ppt*)

Genau das sind die häufigsten Lecks bei schnell mit AI-Tools gebauten Apps
(ChatGPT/Claude-Dashboards, R/Shiny-Dashboards etc.), die live mit echten
Daten laufen.

## Pipeline

```
Malware-Gate
  ├─ guarddog  -> Heuristiken auf PyPI/npm-Abhängigkeiten (Install-Scripts,
  │               Obfuskierung, Exfiltration). high_risk = critical/malware,
  │               suspicious = high/suspicious-package (begründbar)
  ├─ osv       -> bekannte Schadpakete (OSV MAL-*, Offline-Index aus dem
  │               Image-Bau) = critical/malware
  └─ verschachtelte Archive = critical/unscannable

  Ein critical-Fund mit Kategorie malware: gate_passed: false, Exit-Code 1,
  Ergebnis gesperrt. Die übrigen Prüfungen laufen trotzdem, damit alle
  Probleme auf einmal sichtbar sind – kein Tool führt Code aus dem Upload aus.

Code- und Konfigurations-Prüfung (läuft immer)
  ├─ bearer      -> SAST + Privacy/Datenfluss (Schweregrade per Policy)
  ├─ trufflehog  -> Secrets im aktuellen Dateistand, zusätzlich Git-History
  ├─ trivy       -> Dependency-CVEs (SCA) + Docker-Base-Image-CVEs
  ├─ checkov     -> IaC-Fehlkonfigurationen
  └─ olevba      -> Office-VBA-Makros (.doc*/.xls*/.ppt*) und VBA/VBScript-
                     Quelltexte (.bas/.cls/.frm/.vba/.vbs)
```

## Was läuft

| Tool | Zweck | Läuft lokal? |
|---|---|---|
| [guarddog](https://github.com/DataDog/guarddog) | Malware-Gate: Heuristiken auf PyPI/npm-Pakete | größtenteils (lädt Paket-Inhalte + Metadaten von der Registry, siehe unten) |
| [OSV](https://osv.dev) malicious-packages | Malware-Gate: bekannte Schadpakete (MAL-*) | ja (Index wird beim Image-Bau erzeugt) |
| [bearer](https://github.com/bearer/bearer) | SAST + Privacy/Datenfluss (PII/PHI) | ja |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | Secrets im Code + Git-History | ja |
| [trivy](https://github.com/aquasecurity/trivy) | Dependency-CVEs (SCA) + Docker-Base-Image-CVEs | ja (CVE-DB-Sync via Netz) |
| [checkov](https://github.com/bridgecrewio/checkov) | IaC-Fehlkonfigurationen | ja |
| [oletools/olevba](https://github.com/decalage2/oletools) | Office-VBA-Makros: AutoExec, Shell/PowerShell, Obfuskierung | ja |

Kein Tool hier braucht eine Cloud-API oder ein LLM. Der gescannte
**Zielcode selbst geht bei keinem Tool nach außen.** Einzige Ausnahme:
`guarddog` lädt zur Analyse die tatsächlichen **Paket-Inhalte** (nicht
euren Code, sondern die Dependency selbst, z.B. `requests` von PyPI) und
fragt Metadaten bei der Registry ab — exakt wie ein normales
`pip install`/`npm install` das auch täte. Fehlende Tools werden
übersprungen, Fehler landen im Report unter `tools.<name>.error` und im
HTTP-Wrapper unter `failed_tools` bzw. `core_failed_tools`.


## Ziel: lokaler Ordner, Git oder nicht, eine Git-URL oder ein Archiv

Das Script ist nicht auf GitHub oder auf Git überhaupt festgelegt:

- **Lokaler Ordner, kein Git** — z.B. ein R/Shiny-Projekt, das nie in
  Versionskontrolle war. Läuft genauso, nur `trufflehog` scannt dann nur
  den aktuellen Dateistand (kein History-Scan möglich, logisch, da keine
  History existiert).
- **Lokaler Ordner, ist ein Git-Repo** — `trufflehog` scannt immer den
  aktuellen Dateistand und zusätzlich die komplette Git-History. Die History
  wird nur gescannt, wenn im Wurzelordner ein gültiges `.git` mit Commits
  liegt; ein kaputtes oder leeres `.git` (z.B. in einem Archiv) ändert
  nichts am Dateistand-Scan.
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

# .zip-/.7z-Archiv (z.B. ein hochgeladenes Skript)
python3 contrib/unified-scan/unified_scan.py tool.zip --out ./report
```

## Archiv als Ziel (.zip/.7z)

Ein Archiv wird mit `safe_extract.py` in ein Temp-Verzeichnis entpackt,
gescannt und danach wieder gelöscht, auch bei Fehlern. Beim Entpacken wird
abgelehnt, was unsicher oder kaputt ist:

- Pfade mit `..`, absolute Pfade (`/etc/...`, `C:/...`), Symlinks
- passwortgeschützte Archive
- ZIP-Bomben: max. 5000 Einträge, 50 MB pro Datei, 200 MB insgesamt.
  Bei ZIP wird beim Schreiben gezählt, den Größen im Header wird nicht
  vertraut. Bei 7z begrenzen die geprüften Header-Größen die
  Dekompression, dazu `max_extract_size` von py7zr.
- beschädigte Archive (CRC, kaputter Deflate-Stream) und nicht
  unterstützte Verfahren (Deflate64, BCJ2, ...)

Entpackte Dateien bekommen immer die Rechte `0644`/`0755`. Aus dem Archiv
bleibt also kein Ausführ- oder Setuid-Bit übrig.

Ein Archiv kann ein manipuliertes `.git` enthalten, das `git`/`trufflehog`
dazu bringt, Dateien außerhalb des Archivs zu lesen oder Befehle
auszuführen. Deshalb gilt im Archiv-Modus:

- `.git` als Datei (`gitdir: /anderswo`) wird gelöscht.
- `hooks/`, `objects/info/alternates`, `commondir` und `config.worktree`
  werden gelöscht.
- `.git/config` wird auf harmlose `[core]`/`[extensions]`-Werte reduziert,
  also ohne `include`, `fsmonitor`, Filter oder Diff-Treiber.
- Zusätzlich setzt das Script per Umgebung `core.fsmonitor=false` und
  `core.hooksPath=/dev/null`.

Alle `file`-Angaben im Report sind relativ zum Archiv-Wurzelverzeichnis,
also z.B. `src/main.py` statt `/tmp/unified-scan-archive-x/src/main.py`.
Das gilt für alle Tools und auch für lokale Ordner. GuardDog-Funde haben
`pypi:<paket>` bzw. `npm:<paket>` als Ort.

Exit-Codes: `0` ok, `1` mind. ein critical-Finding, `2` Ziel nicht
auflösbar, `3` Archiv abgelehnt (Grund auf stderr, Zeile
`Archiv abgelehnt: ...`).

## HTTP-Wrapper (interner Scanner-Dienst)

`http_wrapper.py` (nur Standardbibliothek) macht aus dem Script einen
kleinen internen Dienst, z.B. für ein Webformular, das Skripte als ZIP
annimmt:

| Anfrage | Antwort |
|---|---|
| `POST /scan`, Body = rohes Archiv, Header `X-Filename: tool.zip` | `200` mit dem Inhalt von `combined_report.json` |
| | `422 {"error": "..."}`: Archiv abgelehnt (unsicher, kaputt, zu groß, falscher Typ). Der Text ist für Endnutzer gedacht. |
| | `5xx {"error": "..."}`: Scan fehlgeschlagen, `504` bei Zeitüberschreitung. Der Aufrufer darf es erneut versuchen. |
| `GET /health` | `200 {"ok": true, "tools": {...}}`, antwortet auch während eines Scans |

Zusätzlich zum normalen Report liefert der Wrapper:

- `target`: der Dateiname aus `X-Filename`, ohne Pfad.
- `incomplete` / `failed_tools`: `true` bzw. die Liste der Tools, die für
  dieses Archiv nicht oder nur teilweise gelaufen sind. Das sind `error`,
  `image_errors` oder `ecosystem_errors` unter `tools.<name>`.
- `core_failed_tools`: die Teilmenge davon unter den Kern-Tools `bearer`,
  `trufflehog`, `guarddog`, `osv`, deren Ausfall **nicht** an Registry/Netz
  liegt (GuardDog: Kontrolllauf klappt; Netzprobleme stehen in
  `tools.guarddog.infra_errors` und fehlen hier). Empfehlung an den
  Verbraucher: ist der Scanner gesund und diese Liste nicht leer, sperren –
  ohne Kern-Tool sagt das Ergebnis nichts über Code bzw. Pakete aus.
- `unscanned_files` / `unscanned_file_count`: Code-Dateien, die kein Tool auf
  Sicherheitsprobleme prüft (`.ps1`, `.bat`, `.sh`, `.sql`, `.cs`, `.r` …),
  abgeleitet aus dem Archiv-Inhalt (Liste auf 100 gekürzt).
- `dependency_manifests`: gefundene Abhängigkeitslisten/Lockfiles
  (`requirements*.txt`, `package.json`, `package-lock.json`, `poetry.lock`,
  `pom.xml` …). Leer = keine Paketprüfung möglich.
- NUL-Zeichen werden aus allen Texten entfernt. `line` ist entweder ein
  int zwischen 1 und 10.000.000 oder `null`.
- Paket-Funde: `guarddog` mit `category: "malware"` (high_risk, critical,
  nie begründbar) oder `"suspicious-package"` (suspicious, high,
  begründbar); `osv` mit `rule_id` `osv.malicious-package` (critical,
  `malware`) oder `osv.malicious-versions` (high, `suspicious-package`: nur
  einzelne Versionen bösartig, Version nicht festgelegt). Schlägt das
  Malware-Gate an (`gate_passed: false`), läuft der Rest trotzdem.
- `unified-scan`/`dependency-unpinned` (low, `dependency`): Abhängigkeiten
  ohne feste Version – geprüft wurde die aktuelle Version.
- olevba-Funde: `category: "macro"` (high/medium/low, begründbar), echte
  Malware-Muster `category: "malware"` (critical).

Jeder Job läuft in einem eigenen Ordner unter `UNIFIED_SCAN_WORKDIR`, der
auch als `TMPDIR` für alle Tools dient. Er wird vor der Antwort gelöscht.
Bei einer Zeitüberschreitung wird die ganze Prozessgruppe beendet, also
auch die Scanner selbst. Reste eines Absturzes werden beim Start entfernt.

| Umgebungsvariable | Standard | Bedeutung |
|---|---|---|
| `UNIFIED_SCAN_PORT` | `8080` | Port |
| `UNIFIED_SCAN_TIMEOUT_SECONDS` | `600` | harte Gesamtzeit pro Job |
| `UNIFIED_SCAN_MAX_UPLOAD_BYTES` | `52428800` (50 MB) | max. Archivgröße |
| `UNIFIED_SCAN_MAX_PARALLEL` | `1` | gleichzeitige Scans, weitere warten |
| `UNIFIED_SCAN_WORKDIR` | Temp-Verzeichnis | Ort der Job-Ordner |

### Docker

```bash
docker build -t unified-scan contrib/unified-scan

docker network create --internal scan   # kein Internet, siehe unten
docker run -d --name unified-scan --network scan \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1g \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 3g --cpus 2 --pids-limit 256 \
  -e UNIFIED_SCAN_TIMEOUT_SECONDS=600 \
  unified-scan
```

Das Image enthält bearer (mit eingebauten bearer-rules), trufflehog,
trivy, checkov, guarddog und oletools/olevba in festen Versionen
(Build-Args im `Dockerfile`), läuft als Nutzer ohne Root-Rechte und
schreibt nur nach `/tmp`.

**Was im Image für ein schreibgeschütztes Dateisystem und ohne
Telefon-nach-Hause eingestellt ist:**
- **Bearer-Regeln eingebaut** (`BEARER_RULES_VERSION`, liegen unter
  `/opt/bearer-rules`, `BEARER_EXTERNAL_RULE_DIR` +
  `BEARER_DISABLE_DEFAULT_RULES=true`). Hintergrund:
  `BEARER_DISABLE_VERSION_CHECK=true` schaltet auch den Download der
  Standard-Regeln ab. Bearer lief dann mit „0 rules found" und lieferte
  einen leeren Report, der wie „keine Findings" aussah. `unified_scan.py`
  meldet einen Lauf ohne Regeln jetzt als `tools.bearer.error` (also
  `incomplete`), nie als sauberes Ergebnis.
- **GuardDog-Cache nach `/tmp`** (`GUARDDOG_TOP_PACKAGES_CACHE_LOCATION`):
  GuardDog schreibt seine Top-Paket-Listen sonst ins eigene
  Paketverzeichnis und stürzt bei schreibgeschütztem Dateisystem ab. Das
  `entrypoint.sh` füllt den Cache beim Start mit den mitgelieferten Listen.
- **trufflehog mit `--no-verification`:** Gefundene Schlüssel werden nicht
  live beim Anbieter (AWS, GitHub, …) getestet. Sonst würde ein echter,
  geleakter Schlüssel dafür die Maschine verlassen.
- Telemetrie aus: `TRIVY_DISABLE_TELEMETRY`, `DO_NOT_TRACK`,
  `BC_SKIP_MAPPING` (checkov).

**Regelmäßig neu bauen – `rebuild.sh` (z.B. wöchentlich per cron/systemd-Timer):**
Ein Neubau aktualisiert die trivy-Datenbank, den OSV-Index bekannter
Schadpakete und die Debian-Pakete des Basis-Images (`--pull`). Die Tool-
Versionen und die **Bearer-Regeln bleiben gepinnt** – neue Regeln nur mit
`BEARER_RULES_VERSION=latest rebuild.sh …` (oder einer festen Version),
weil ein Regel-Update Regeln umbenennen kann. Vor dem Umschalten läuft ein
Selbsttest im neuen Image: echtes bearer gegen `tests/fixtures/idv_corpus/`
(`test_corpus_real_bearer.py`) und jeder Policy-Glob muss eine Regel treffen
(`test_policy_globs.py`). Nur wenn beides grün ist, wird das Image zu
`<name>:current`; das alte bleibt als `<name>:previous` für den Rückweg.
Danach den Scanner-Dienst neu starten.

Größen: checkov und guarddog (semgrep) brauchen jeweils mehrere hundert MB
RAM. Ein tmpfs zählt zum Speicherlimit des Containers. Deshalb eher 3 GB
RAM und 1 GB tmpfs, nicht weniger.

**Netzwerk:** Zwei Schritte brauchen zur Laufzeit Internet (der OSV-Index
und die trivy-DB liegen im Image):
1. `guarddog` lädt die zu prüfenden Pakete von PyPI/npm.
2. `trivy image` holt die Base-Images aus Dockerfiles.

In einem `--internal`-Netz scheitern beide. Sie stehen dann in
`failed_tools`, und der Report hat `incomplete: true`. Die
trivy-Schwachstellen-Datenbank wird standardmäßig beim Build ins Image
gelegt (`TRIVY_BAKE_DB=1`), das Image muss also regelmäßig neu gebaut
werden, damit sie aktuell bleibt. Mit `--build-arg TRIVY_BAKE_DB=0` lädt
trivy sie stattdessen zur Laufzeit, das braucht ebenfalls Internet.

Möglichkeiten:
- **Kein Internet:** maximale Abschottung, dafür ohne GuardDog und
  Base-Image-Scan.
- **Ausgang nur über einen Proxy mit Allowlist** (empfohlen), gesetzt über
  `HTTPS_PROXY`. Der Container darf interne Dienste (DB, App) trotzdem
  nicht erreichen. Nur `CONNECT` auf Port 443 zu diesen Hosts, private
  Zieladressen gesperrt (erprobte squid-Liste):

  | Zweck | Hosts |
  |---|---|
  | GuardDog: Pakete | `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org` |
  | GuardDog: PyPI-Top-Liste (Typosquatting) | `hugovk.github.io`, `hugovk.dev` |
  | trivy-DB (nur mit `TRIVY_BAKE_DB=0`) | `ghcr.io`, `pkg-containers.githubusercontent.com`, `mirror.gcr.io` |
  | `trivy image` (Base-Images) | `registry-1.docker.io`, `auth.docker.io`, `index.docker.io`, `production.cloudflare.docker.com`, `quay.io`, `cdn01.quay.io`, `cdn02.quay.io`, `cdn03.quay.io` |

  Bewusst **nicht** freigegeben: `api.github.com`, `check.trivy.dev`,
  `api.cycode.com` (Versions-Checks/Telemetrie), `github.com` und
  `packages.ecosyste.ms` (GuardDogs Abgleich mit Quell-Repo/Metadaten —
  schwächt nur diese eine Heuristik, `github.com` wäre aber ein möglicher
  Abflusskanal).

  **Restrisiko, ehrlich:** Auch über die freigegebenen Hosts ließen sich
  Daten hinausschaffen – z.B. `npm publish` an registry.npmjs.org oder ein
  Push nach Docker Hub/ghcr.io/quay.io mit eigenem Account. Das setzt
  Codeausführung im Scanner voraus (kein Tool führt Upload-Code aus;
  read-only, `noexec`-tmpfs, keine Capabilities, kein root). Ein Proxy mit
  SNI-Prüfung verhindert Domain-Fronting, nicht diese Wege.

## Sprachgrenze von Bearer

Bearers SAST-Engine deckt aktuell JS/TS, Python, Ruby, Go, PHP, Java, C#
ab — **kein R**. Bei reinen R/Shiny-Projekten liefert `bearer` daher keine
oder kaum SAST-Findings, das ist erwartet und kein Fehler (steht im Report
unter `tools.bearer.note`). Secrets (trufflehog), Dependency-CVEs (trivy,
sofern `renv.lock` o.ä. erkannt wird) und IaC (checkov) laufen unabhängig
davon normal weiter, da die nicht auf Sprach-Parsing angewiesen sind.

R hat aktuell keinen dedizierten SAST-Scanner in dieser Pipeline — geprüft
wurde Semgrep (R ist dort experimentell gelistet), aber `metavariable-regex`
funktioniert für die R-Sprachintegration nicht zuverlässig (feuert auch bei
einer nie-treffenden Regex), sodass ein robustes eigenes R-Regelset aktuell
nicht sinnvoll wartbar wäre. Wird nicht ergänzt, bis es eine belastbarere
Grundlage gibt.

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

# guarddog (venv empfohlen — kollidiert sonst mit checkov/semgrep-Abhängigkeiten,
# z.B. unterschiedliche boto3/packaging/termcolor-Versionen)
python3 -m venv ~/.venvs/guarddog
~/.venvs/guarddog/bin/pip install guarddog
sudo ln -sf ~/.venvs/guarddog/bin/guarddog /usr/local/bin/guarddog

# oletools/olevba (venv empfohlen, gleiches Muster wie guarddog/checkov)
python3 -m venv ~/.venvs/oletools
~/.venvs/oletools/bin/pip install oletools
sudo ln -sf ~/.venvs/oletools/bin/olevba /usr/local/bin/olevba

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

## Schweregrade für interne Skripte (`severity_policy.json`)

Bearers Standard-Schweregrade gehen von einer Web-App mit fremden Nutzern aus. Bei kleinen
internen Tools (CLI-Skripte, Excel/CSV-Verarbeitung, Datei-Tools) schlagen dadurch Regeln
auf völlig normalen Code an, z.B. `open(pfad)` mit einem Funktionsparameter als „high –
path traversal“. `severity_policy.json` stuft Bearer-Funde für diesen Einsatz um:

Gleiche Regelklasse = gleiche Stufe in allen Sprachen:

- **bleibt kritisch:** `eval`/`exec` mit Eingaben, Code-Injection, Deserialisierung fremder
  Daten
- **high (blockiert, begründbar):** OS-Befehle/Prozessaufrufe (`*_os_command_injection`,
  `*_dynamic_os_command`, `*_exec_using_user_input`, `*_subproc_*` – schlagen auch bei festen
  Befehlslisten an), unverschlüsselte Verbindungen (`*_insecure_http`, `*_http_insecure`,
  `*_insecure_ftp`, Websockets – im internen Netz verbreitet), Pickle, abgeschaltete
  TLS-Prüfung (mindestens high), hartcodierte Secrets (mindestens high)
- **medium (blockiert, begründbar):** jede SQL-/NoSQL-Injection (`*_sql_injection`, `*_sqli`),
  jede XSS-/HTML-Injection (`*_cross_site_scripting`, `*_dangerous_insert_html`,
  `*_template_injection` – bei Bearer XSS-Regeln …), Open Redirect/SSRF, Dateipfad aus einer
  Web-Anfrage (`*_path_using_user_input`), unverschlüsseltes SMTP (`starttls()` per
  Konfiguration sieht Bearer nicht), schwache Passwort-Hashes (mindestens medium)
- **low (nur Hinweis):** Dateipfade aus Aufruf/Konfiguration (`*_path_traversal`,
  `*_non_literal_fs_filename`), einfacher Zufall (`*_weak_random`,
  `*_insufficiently_random_values`), Log-Ausgaben, Exceptions, Cookie-/CORS-/Header-Härtung
- **Zeilenprüfung für `*_code_injection`:** liegt der kritische Fund auf einer Zeile mit
  `setattr`/`getattr`/`delattr` und keinem Code-Ausführungs-Muster (`eval`, `exec`, `compile`,
  `__import__`, `importlib.import_module`, `os.exec*`/`os.spawn*`, `globals()[…]`, `getattr`
  auf `builtins`/`os`/`subprocess`), wird er high (begründbar). Steckt in
  `refine_code_injection()`, weil es die Quellzeile liest
- **Checkov-Hygiene (nur Hinweis):** Dockerfile-/Workflow-Checks ohne Sicherheitslücke im Code
  (`CKV_DOCKER_2/3/4/5/7/9` – HEALTHCHECK, USER, ADD, apt, `latest`; `CKV2_GHA_1`, `CKV_GHA_7`).
  Regeln mit `"tool": "checkov"` gelten nur für Checkov, alle anderen nur für Bearer
- **GuardDog (`guarddog`-Abschnitt):** Nur ein `suspicious`-Ergebnis (Heuristik) auf einem
  Paket unter den `trusted_top_n` (5000) meistgeladenen der Registry – laut GuardDogs eigener
  `top_<ökosystem>_packages.json` – wird zum Hinweis; GuardDogs Code-Muster schlagen bei großen
  Paketen (pandas, SQLAlchemy, `@prisma/client` …) ständig an. **`high_risk` bleibt immer
  critical**, egal wie beliebt das Paket ist: echte Supply-Chain-Angriffe (kompromittierte
  Releases von chalk/debug, ultralytics, ua-parser-js) trafen genau die populären Pakete.
  `suspicious` auf anderen Paketen ist high + `suspicious-package` (begründbar), damit ein
  einzelner Heuristik-Treffer auf einem Nischenpaket keine Sackgasse ist. Bekannte
  Schadpakete und -Versionen meldet zusätzlich der OSV-Index deterministisch
- **Exceptions mit Daten (`*_exception`) nur Hinweis:** betrifft Fehlermeldungen in Web-Antworten;
  schlug in mehreren Projekten auf harmlosen Zeilen an (z.B. `super().__init__`)
- **olevba:** siehe „Office-Makro-Scan im Detail“
- **nicht gelistete Regeln** behalten Bearers Schweregrad

Regeln werden von oben nach unten geprüft, der erste passende `match` (Glob auf die
Bearer-Regel-ID) gewinnt; `mode: "set"` ersetzt, `mode: "min"` hebt nur an. Gilt nur für
`tool == "bearer"` (bzw. `"checkov"` bei Regeln mit `"tool": "checkov"`), nie für
`secret`/`malware`/`malicious-package`/`unscannable`. `tests/test_policy_globs.py` schlägt fehl,
wenn ein Glob keine Regel der gepinnten bearer-rules-Version trifft (tote Regel nach einem
Regel-Update), und prüft, dass jede Klasse in allen Sprachen dieselbe Stufe bekommt. Geänderte
Funde tragen `original_severity` und `policy_reason` (deutsch, zum Anzeigen gedacht);
Score und Ampel rechnen mit dem neuen Schweregrad.

Abschalten zum Vergleich: `--no-severity-policy` bzw. `UNIFIED_SCAN_SEVERITY_POLICY=off`
(auch im HTTP-Wrapper). Eigene Datei: `UNIFIED_SCAN_SEVERITY_POLICY_FILE=/pfad.json`. Eine
kaputte Policy-Datei bricht den Lauf ab, statt still ohne Policy zu scannen.

Gemessen an einem erfundenen Korpus typischer interner Skripte
(`tests/fixtures/idv_corpus/`, bearer-rules v0.48.4): von 16 harmlosen Skripten blockierten
vorher 7 (13 blockierende Funde, 3 davon kritisch), nachher 2 – beide nur noch begründbar
(lokaler Pickle-Cache, `subprocess.run` mit fester Liste). Alle gefährlichen Beispiele
(`eval` mit Eingabe, `shell=True` mit Eingabe, `os.system`, Pickle aus dem Netz,
`verify=False`, MD5 für Passwörter) blockieren weiter; `eval` bleibt kritisch.

Bekannte Lücken von Bearer selbst (nicht von der Policy): im Korpus nicht erkannt wurden ein
hartcodiertes Passwort in einem Connection-String, zusammengesetztes SQL mit `sqlite3`,
`yaml.load` mit unsicherem Loader und `child_process.exec`/`eval` in Node.

## Paket-Felder bei Dependency-Funden

trivy-Funde (`trivy`, `trivy-image`) tragen zusätzlich `package`, `installed_version` und
`fixed_version` (so wie trivy sie meldet, z.B. `"2.2.5, 2.3.2"` bei mehreren Versionszweigen,
`null` wenn es noch keinen Fix gibt). Damit kann ein Verbraucher die CVEs pro Paket bündeln
und die nötige Update-Version anzeigen. Bei allen anderen Tools sind die Felder `null`.

## Eigene Bearer-Regeln (`custom-rules/`)

Für Muster, die die Standardregeln von Bearer nicht erkennen, liegen eigene Regeln im
Bearer-Regelformat unter `custom-rules/`. Das Image kopiert sie nach `/opt/bearer-rules/idv/`,
also in dasselbe Verzeichnis wie die Standardregeln. Das ist nötig, weil Bearer `imports`
(geteilte Regeln wie `python_shared_lang_import1`) nur innerhalb eines Regelverzeichnisses
auflöst; ein zweites `--external-rule-dir` sieht sie nicht.

| Regel | Findet | Schweregrad / Kategorie |
|---|---|---|
| `idv_python_db_password_in_code` | Passwort im Connection-String oder als `password=` an `connect()`/`create_engine()` (pyodbc, psycopg2, SQLAlchemy-URL) | high / `secret` (nie begründbar) |
| `idv_javascript_db_password_in_code` | Passwort in einem Connection-String | high / `secret` |
| `idv_python_sql_string_building` | SQL an `execute()` per `+`, `%`, `.format()` oder f-String | medium (begründbar) |
| `idv_python_yaml_unsafe_load` | `yaml.load` ohne `SafeLoader`, `yaml.unsafe_load`/`full_load` | high |
| `idv_javascript_child_process_dynamic` | `exec`/`execSync` mit nicht festem Befehl | high |
| `idv_javascript_eval_dynamic` | `eval`/`new Function` mit nicht festem Code | critical |

Passwörter aus Umgebung oder Konfiguration schlagen nicht an: Bearer setzt für Werte, die
es nicht auflösen kann, ein Platzhalterzeichen außerhalb von ASCII ein; die Regeln verlangen
direkt nach `PWD=`/`password=` ein normales Passwortzeichen.

Meldet eine Standardregel dieselbe Schwachstelle (gleiche CWE) in derselben Zeile, wird der
Fund der eigenen Regel verworfen (`_drop_duplicate_custom_findings`), damit nichts doppelt
erscheint.

**C#:** Bearer kann kein C#. Für genau ein Muster, ein Klartext-Passwort in einem
Connection-String-Literal (`"...;Password=geheim;..."`), gibt es einen kleinen eigenen Check in
`unified_scan.py` (`scan_csharp_db_passwords`, Regel-ID `idv_csharp_db_password_in_code`,
high / `secret`). Interpolierte Strings (`$"...Password={pw}"`) zählen nicht.

Korpus mit gefährlichen und harmlosen Varianten: `tests/fixtures/idv_corpus/custom/`.

**trufflehog-Platzhalter:** Die Connection-String-Detektoren von trufflehog halten Platzhalter
wie `Password={pw}` oder `${DB_PASSWORD}` für ein Passwort. Solche Funde (Wert `{…}`, `${…}`,
`%s`, `%(x)s`, `$VAR`, `<…>`, `***`) werden verworfen. Meldet trufflehog in derselben Zeile ein
Secret wie eine eigene Passwort-Regel, bleibt nur der trufflehog-Fund (`drop_secret_duplicates`).

## Score (`internal_criticality`)

Jede Regelgruppe zählt **einmal** mit ihrem höchsten Schweregrad, egal an wie vielen Stellen
sie vorkommt (Gruppe = Tool + Regel-ID, bei trivy Tool + Paket). Gewichte: critical 40,
high 20, medium 8, low 2, info 0. low und info zusammen höchstens 5 Punkte, allein also nie
über GRÜN hinaus. Echter Testcode zählt nicht (siehe Test-Code-Filter). Begründete Ausnahmen
kennt der Score nicht – er bewertet den Upload, nicht die Entscheidung darüber.

| Verdict | Bedingung |
|---|---|
| RED | mindestens eine critical-Gruppe („kritische Findings zuerst fixen“) oder Score ≥ 80 („viele blockierende Findings“) |
| GELB | mindestens eine high-Gruppe oder Score ≥ 40 |
| GELB-GRÜN | Score ≥ 10 |
| GRÜN | sonst |

`by_severity` zählt Gruppen, `rule_groups` ist ihre Anzahl, `total_findings` zählt weiterhin
die einzelnen Stellen.

## Test-Code-Filter

Ein Fund gilt nur dann als Testcode (`excluded_from_score: true`, im Report mit 🧪), wenn
**beides** zutrifft:

1. der Pfad sieht nach Test aus (`test/`, `tests/`, `__tests__/`, `spec/`, `fixtures/`,
   `testdata/` sowie Dateien wie `test_*.py`, `*_test.py`, `*_test.go`, `*.test.ts`,
   `*.spec.js`, `*_spec.rb`), **und**
2. die Datei nutzt tatsächlich ein Test-Framework (Python: `import pytest`/`unittest`/`nose`;
   JS/TS: Import von jest/vitest/mocha/…/`node:test` oder `describe(`/`it(`/`test(`;
   Go: `"testing"`; Ruby: rspec/minitest; Java: JUnit/TestNG; PHP: PHPUnit)
   (`refine_test_exemption()`, läuft nach allen Umstufungen).

Ein Ordnername allein ist vom Uploader frei wählbar und schaltet nichts ab. `build/`, `dist/`,
`vendor/`, `examples/` usw. zählen nie als Testcode. **Nie ausgeschlossen**, auch in echtem
Testcode: Schweregrad `critical` und die Kategorien `secret`, `malware`, `malicious-package`
und `unscannable`. Restrisiko: wer gezielt `import pytest` in eine Datei unter `tests/`
schreibt, bekommt high/medium-Funde dort als Testcode gewertet – der Fund bleibt sichtbar.

## Exit-Codes der Tools

Alle Tools werden so aufgerufen, dass sie auch mit Funden mit 0 enden
(`bearer --exit-code 0`, `checkov --soft-fail`; trufflehog, trivy und
guarddog ohne `--fail`/`--exit-code`). Ein anderer Exit-Code ist deshalb ein
echter Fehler und landet unter `tools.<name>.error` (→ `incomplete: true` im
HTTP-Wrapper) statt als leeres, "sauberes" Ergebnis. Einzige Ausnahme:
olevba liefert auch bei einem Absturz (z.B. Exit 8) JSON mit Details, das
ausgewertet wird.

## Nicht prüfbare Inhalte (Kategorie `unscannable`)

Manche Inhalte kann die Pipeline nicht (vollständig) prüfen. Statt sie still
als "keine Funde" durchgehen zu lassen, entsteht ein `critical`-Fund mit
Kategorie `unscannable` (nie aus dem Score ausgeschlossen):

| `rule_id` | `tool` | Wann |
|---|---|---|
| `nested-archive` | `unified-scan` | Archiv im Archiv (`.zip`, `.7z`, `.tar`, `.gz`, `.rar`, `.jar`, `.apk` …), erkannt an Endung **und** Magic Bytes (also auch umbenannt). Nur trufflehog schaut hinein, alle anderen Tools nicht. Ausgenommen sind nur echte Office-/ODF-Dokumente: OOXML mit `[Content_Types].xml` **und** Hauptteil (`word/document.xml`, `xl/workbook.xml`, `ppt/presentation.xml` …), ODF mit `mimetype` als erstem Eintrag **und** `content.xml` – und ohne Skripte/Programme/Archive darin. Eine ZIP mit einer Dummy-`[Content_Types].xml` zählt als Archiv. |
| `unscannable.manifest` | `guarddog` | `package.json` ist kein gültiges JSON, oder guarddog scheitert an einer Abhängigkeitsliste (`requirements*.txt`, `package.json`), während ein Kontrolllauf mit einer bekannten, harmlosen Liste (`six` / `left-pad`) klappt. |
| `unscannable.office-file` | `olevba` | olevba kann eine Office-Datei nicht analysieren (Absturz, verschlüsselt, Timeout, keine Ausgabe). |

Scheitert auch der Kontrolllauf, liegt es an Netzwerk/Proxy/Registry, also
an der Infrastruktur: das landet unter `tools.guarddog.ecosystem_errors` und
`tools.guarddog.infra_errors` (nicht in `core_failed_tools`). Eine
Zeitüberschreitung (`UNIFIED_SCAN_GUARDDOG_TIMEOUT`, Standard 240 s pro
Ökosystem, weit unter dem 600-s-Gesamtlimit) steht in `tools.guarddog.timed_out`
und zählt als Kern-Tool-Ausfall. Entschieden wird über
das Verhalten, nicht über den Fehlertext — der kann Inhalt der hochgeladenen
Liste enthalten und wäre damit vom Uploader steuerbar. Das Malware-Gate schlägt nur bei echten
Malware-Funden (Kategorie `malware`) fehl, nicht bei `unscannable`.

olevba wählt Dateien nicht nur nach Endung aus, sondern auch nach Inhalt:
OLE-Container (`D0 CF 11 E0`) und OOXML-ZIPs mit `vbaProject.bin` werden
auch als `.bin`/`.dat`/… geprüft.

## Priorität im HTTP-Wrapper

Der Wrapper startet jeden Scan mit `nice -n 10` und, falls vorhanden,
`ionice -c 3`, damit ein langer Scan andere Dienste auf demselben Host nicht
ausbremst.

## Docker-Base-Image-Scan

Wenn `Dockerfile`/`Dockerfile.*` im Projekt liegen, werden die dort
referenzierten Base-Images (`FROM ...`-Zeilen) automatisch mit
`trivy image` auf bekannte CVEs geprüft — ohne irgendetwas zu bauen oder
auszuführen, nur Image-Metadaten/Layer werden gezogen. Multi-Stage-Builds
werden erkannt (Stage-Aliase wie `AS builder` fließen nicht als Image-Ref
ein). Relevant weil viele AI-gebaute Dashboards mit veralteten Docker-
Base-Images deployed werden (z.B. `python:3.9-slim`, `node:12-alpine`),
die selbst Dutzende bekannte CVEs mitbringen, unabhängig vom eigenen Code.

Jeder Fund trägt `image` (das Basis-Image, aus dem er stammt). Schweregrad per
`base_image`-Abschnitt in `severity_policy.json`: Basis-Image-Lücken sind nur ein **Hinweis
(`low`)** – sie liegen in den OS-Paketen des Images, nicht im hochgeladenen Code, und fast
jedes Image hat Dutzende. **Ausnahme:** `critical` **mit** vorhandener `fixed_version` bleibt
blockierend, weil ein Neubauen des Images sie behebt. Mit abgeschalteter Policy bleiben die
Schweregrade von trivy.

## Doppelte Funde

`drop_duplicate_findings()` meldet identische Funde nur einmal: gleiches Tool, gleiche Regel,
gleiche Datei und Zeile (Bearer meldet eine Stelle teils pro Datenfluss mehrfach). Bei
`trivy-image` zählt dieselbe CVE im selben Image nur einmal – auch wenn sie mehrere OS-Pakete
betrifft (`libc6`, `libc-bin` …) oder mehrere `FROM`-Zeilen dasselbe Image nutzen. Bei `trivy`
(Lockfiles) bleibt dieselbe CVE in verschiedenen Paketen getrennt.

## Malware-Gate im Detail

**guarddog** prüft alle `requirements.txt`/`package.json`-Dateien im Projekt (rekursiv) mit
Heuristiken: verdächtige Install-Scripts, Obfuskierung, Netzwerk-Exfiltration, Typosquatting.
Labels: `high_risk` → critical, Kategorie `malware` (Gate schlägt an, nie begründbar);
`suspicious` → high, `suspicious-package` (begründbar; bei Top-5000-Paketen nur Hinweis);
`low` → low. Unbekannte Labels (neue guarddog-Version) → high + `malware` (fail closed).

**OSV** (`tool: "osv"`) gleicht dieselben Abhängigkeiten deterministisch gegen die bekannten
Schadpakete der OSV-Datenbank ab (MAL-*-Einträge des OpenSSF-Projekts malicious-packages,
auch kompromittierte Versionen populärer Pakete). Der Index (`/opt/osv/mal_index.json`, einige
MB) entsteht beim Image-Bau mit `build_osv_index.py` und wird bei jedem Neubau aktualisiert;
zur Scan-Zeit geht nichts ins Netz. Versionen kommen aus `==`-Pins in `requirements*.txt`,
aus `package-lock.json` oder aus exakten Versionen in `package.json`:

| Treffer | Fund |
|---|---|
| alle Versionen bösartig, oder genau die festgelegte Version | `osv.malicious-package`, critical, `malware` |
| nur einzelne Versionen bösartig, Version nicht festgelegt | `osv.malicious-versions`, high, `suspicious-package` |

Fehlt der Index, steht das unter `tools.osv.error` (→ `core_failed_tools`).

**Nicht festgelegte Versionen:** Ohne `==`-Pin bzw. Lockfile prüfen guarddog, OSV und trivy die
jeweils aktuelle Version, nicht unbedingt die, die später installiert wird. Dafür gibt es pro
Abhängigkeitsliste einen Hinweis `dependency-unpinned` (low) mit den betroffenen Paketen.

Ohne `requirements.txt`/`package.json` (z.B. reines R-Projekt) finden beide naturgemäß nichts –
kein Fehler.

## Office-Makro-Scan im Detail

`olevba` scannt gezielt Dateien mit Office-Makro-fähiger Endung
(`.doc`/`.dot`/`.docm`/`.dotm`, `.xls`/`.xlt`/`.xlsm`/`.xltm`/`.xlsb`/`.xlam`,
`.ppt`/`.pot`/`.pps`/`.pptm`/`.potm`/`.ppsm`/`.ppam`) sowie VBA-Quelltexte im Zielverzeichnis,
jede Datei einzeln. **Bewusst kein rekursiver `olevba -r` über den ganzen
Ordner** — verifiziert, dass das JEDE Textdatei (auch `.py`, `.txt`) als
Pseudo-Makro einliest und massives Rauschen erzeugt; die gezielte
Dateisuche vermeidet das.

Excel-VBA ist der Kernfall interner Tools – Shell-Aufrufe, `CreateObject`, XMLHTTP-Abfragen
oder PowerShell stecken in sehr vielen legitimen Makros. Deshalb:

- **AutoExec** (`high`) — Makro läuft automatisch (`Workbook_Open`, `AutoOpen`, `_Layout`,
  `_Painted` …). Button-Handler (`*_Click`, `*_DblClick`) sind nur ein Hinweis (`low`).
- **Suspicious**:
  - `high` (begründbar) — Programme starten (`Shell`, `WScript.Shell`, `ShellExecute`,
    PowerShell), Netzabfragen/Downloads (`MSXML2.XMLHTTP`, `URLDownloadToFileA`,
    `Net.WebClient`), `CreateObject`/`GetObject`, Obfuskierungs-Funktionen (`Chr`,
    `StrReverse`, `Xor`, `CallByName`)
  - `critical` (nie begründbar) — Speicher-/Prozess-Manipulation (`VirtualAlloc`,
    `WriteProcessMemory`, `CreateThread`, `RtlMoveMemory` …), Kategorie `malware`
  - `medium` — alles andere (z.B. Datei-Zugriff) — für sich harmlos, aber meldenswert
- **Dridex-Verschleierung** (`critical`, `malware`) — Signatur einer realen Malware-Familie.
- **Kombination** `olevba.combo.autoexec_download_execute` (`critical`, `malware`): startet
  automatisch **und** lädt eine Datei herunter bzw. speichert sie (`URLDownloadToFile`,
  `Net.WebClient`, `ADODB.Stream`/`SaveToFile` …) **und** startet ein Programm (`Shell`,
  `WScript.Shell`, PowerShell …) – im selben Makro-Projekt. Jedes Teil allein ist in
  Business-Makros üblich, die Kette nicht. Eine reine XMLHTTP-Abfrage (REST lesen) zählt nicht
  als Download.
- Titel sind deutsch und nennen den Dateityp (Excel-Datei, Word-Dokument, VBA-Quelltext …).

Neben Office-Dateien (auch nach Inhalt erkannt, siehe oben) prüft olevba VBA-/VBScript-
Quelltexte: `.bas`, `.cls`, `.frm`, `.vba`, `.vbs`, `.vbe`.
- **Hex/Base64-String-Erkennung** (`low`) — reiner Hinweis auf
  Obfuskierung, kein direkter Beweis für Bösartigkeit.
- **IOC** (URLs/IPs/Pfade im dekompilierten Code) wird bewusst **nicht**
  als Einzelfinding gemeldet — verifiziert an einem realen Testfall mit
  267 IOC-Treffern in einer einzigen Datei, das wäre nur Rauschen. Die
  Anzahl landet als Zähler in `tools.olevba.ioc_count_not_reported_as_findings`,
  für den Fall dass jemand tiefer graben will.

Keine Office-Dateien im Projekt gefunden: `olevba` meldet das im Report
(`tools.olevba.note`), kein Fehler, keine Blockade.

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
- Malware-Gate: sauberes Projekt (unauffällige Deps) durchläuft Gate mit
  0 Findings, komplette Security-Pipeline läuft danach normal durch.
  Simulierter `high_risk`-Fund (guarddog gemockt, da reale bekannte
  Malware-Pakete längst von PyPI/npm entfernt und nicht mehr für Tests
  installierbar sind) lässt das Gate fehlschlagen (`gate_passed: false`,
  Exit-Code 1); die übrigen Tools laufen trotzdem, damit alle Funde auf
  einmal sichtbar sind.
- Office-Makro-Scan: echte `.docm`-Testdatei mit 2 AutoExec-Makros
  (ActiveX-Events) + Hex-String-Obfuskierung (aus dem offiziellen
  oletools-Test-Corpus) korrekt als 2× `high` + 1× `medium` + 1× `low`
  gemeldet; identische, makrofreie `.docm`-Datei im selben Lauf korrekt
  mit 0 Findings; Datei mit Office-Endung aber ohne olevba im PATH löst
  sauberen `error`-Eintrag statt Absturz aus; volle Pipeline (`[0/7]`
  bis `[6/7]`) end-to-end gegen ein gemischtes Git-Repo (Python-Datei +
  2 Office-Dateien) durchlaufen, Score/Verdict korrekt aus den
  olevba-Findings berechnet.

## Validierung an öffentlichen Projekten

Neun öffentliche Projekte (Python-CLI, pandas-Report, Node-CLI, Flask mit Dockerfile, Express,
PowerShell-Sammlung, Office-Makro-Beispiele, zwei absichtlich verwundbare Lern-Apps) liefen durch
den Scanner. Übergreifende Fehlalarm-Muster, die daraus in die Policy kamen: GuardDog auf
Top-Paketen, Checkov-Dockerfile-Hygiene, `*_exception`, olevba-Button-Handler und
„Hex Strings“. Die verwundbaren Apps blockieren weiter (SQL-Injection, MD5-Passwörter, `yaml.load`,
alte Pakete mit kritischen CVEs, Paket mit Netzwerkzugriff bei der Installation).

Ergebnis mit dem Stand von PR #10 (Image `e8b87fda`):

| Projekt | Funde roh | blockierende Zeilen | gesperrt |
|---|---|---|---|
| PowerShell-Sammlung | 0 | 0 | nein (PowerShell prüft kein Tool → `unscanned_files`) |
| cowsay (Python) | 5 | 0 | nein |
| tldr-python-client | 1 | 0 | nein |
| quantstats (pandas-Report) | 6 | 0 | nein |
| microblog (Flask) | 129 | 4 | ja, begründbar |
| oletools (Makro-Beispiele) | 14 | 1 | ja, begründbar |
| node-express-realworld | 73 | 5 | ja (hartcodierte Secrets) |
| Vulnerable-Flask-App (Gegenprobe) | 1020 | 6 | ja |
| dvpwa (Gegenprobe) | 109 | 3 | ja |

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install pytest py7zr oletools pyyaml
.venv/bin/python -m pytest -q contrib/unified-scan/tests
```

`pyyaml` braucht `test_custom_rules.py` (liest die Regeldateien), `oletools`/`py7zr` die
Makro- und Archiv-Tests. `test_corpus_real_bearer.py` läuft nur mit echtem bearer
(`UNIFIED_SCAN_IMAGE_TEST=1`, im Image – `rebuild.sh` macht das), sonst wird er übersprungen.
`test_policy_globs.py` prüft gegen die gespeicherte Regel-ID-Liste der gepinnten
bearer-rules-Version oder, mit `BEARER_RULES_DIR=/opt/bearer-rules`, gegen die echten Regeln.
