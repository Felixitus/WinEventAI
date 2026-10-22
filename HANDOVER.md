# WinEventAI — Uebergabestand

**Version 1.3.0 · 241 Tests gruen · ruff sauber · Stand 13.09.2026**

Diese Datei ist der vollstaendige Wissensstand fuer eine Weiterentwicklung
ausserhalb der urspruenglichen Sitzung. Der Arbeitsvertrag steht in
`AGENTS.md`; hier stehen Umfang, Begruendungen und offene Punkte.

---

## 1. Umfang

~11.360 Zeilen Python in 73 Modulen, 8 PowerShell-Skripte, 30 Regeln in
6 YAML-Dateien, 241 Tests in 15 Dateien.

| Paket | Zeilen | Aufgabe |
|---|---:|---|
| `gui/` | 1909 | PySide6-Oberflaeche |
| `collect/` | 1709 | Erhebung, PowerShell, Laufverzeichnis |
| `probes/` | 1511 | Kontext-Sonden |
| `ai/` | 1419 | Ollama, Bundles, Redaction, Belegpruefung |
| `report/` | 722 | HTML/Markdown/JSON |
| `enrich/` | 709 | Dedup, Burst, Boot, Korrelation, Retention |
| `rules/` | 572 | Regelschema, Loader, Engine |
| `security/` | 410 | Sicherheitsmodus |
| `normalize/` | 372 | Event-Schema, Maskierung |
| `config/` | 361 | Modell, Layering, `config init` |
| `kb/` | 307 | Wissensbasis |
| `evidence/` | 207 | Evidenz-Bundle |
| `cli.py` | 736 | Typer |
| `analyze.py` | 219 | Pipeline-Verdrahtung |

Tests je Datei: ai 20, gui 24, probes 29, rules 17, evidence/config 15,
enrich 14, report 12, config_init 11, ollama_status 10, collect_shell 8,
security 8, normalize 6, end_to_end 6.

## 2. Abhaengigkeiten

`pydantic>=2.6`, `PyYAML>=6.0`, `Jinja2>=3.1`, `typer>=0.12`.
Optional `[gui]`: `PySide6>=6.6`. Dev zusaetzlich `pytest`, `ruff`.

Der Ollama-Client benutzt bewusst `urllib` aus der Standardbibliothek statt
`requests` — eine Abhaengigkeit weniger im PyInstaller-Bundle, und der
Proxy-Umgang muss ohnehin von Hand gesteuert werden.

`tiktoken` wurde ausdruecklich verworfen: es laedt beim ersten Aufruf ein
Encoding aus dem Netz und braeche damit "vollstaendig offline". Die
Token-Schaetzung kalibriert sich stattdessen selbst an `prompt_eval_count`
aus der Ollama-Antwort.

## 3. Pipeline

```
collect ──► raw/*.ndjson ──► normalize ──► enrich ──► rules ──► kb
                                                                 │
                        report ◄── probes ◄── ai ◄───────────────┘
```

### 3.1 collect

- Ein PowerShell-Skript je Quellart, Aufruf ueber `-File`.
  `get_events.ps1` ist der Streaming-Collector: `ForEach-Object` +
  `ConvertTo-Json -Compress -Depth 4`, eine Zeile je Record. Zeitstempel
  formatiert das Skript selbst als `yyyy-MM-ddTHH:mm:ss.fffffffZ` — die
  PowerShell-eigene DateTime-Serialisierung unterscheidet sich zwischen 5.1
  und 7.
- Letzte Zeile ist immer `{"__status": {...}}` mit `records`, `truncated` und
  `exception` als .NET-**Typname**.
- `collect/shell.py` trennt `read_ndjson` (kennt nur Zeilen) von `run_script`
  (kennt Prozesse). Das ist die Testgrenze: der gesamte Collector ist ohne
  Windows testbar.
- `SourceResult` traegt `covered_from_utc` / `covered_to_utc` und
  `coverage_gap` je Quelle.
- Grenzen: 120 s Wall-Clock je Kanal, `max_retained_per_channel` (Default
  200.000) auf **behaltene** Rohdaten, harter Abbruch ueber 5 Mio. Records.
- **Fehler-Sweep** (`collect/sweep.py`, `sweep_errors.ps1`): alle aktiven
  Administrative-/Operational-Kanaele ausser den konfigurierten, serverseitig
  auf Level 1/2 gefiltert. EIN PowerShell-Prozess fuer alle Kanaele, weil
  hunderte Prozessstarts die Laufzeit dominieren wuerden. Damit das
  gemeinsame Zeitlimit (600 s) nichts verschluckt, schreibt das Skript zuerst
  `{"__plan": ...}` und nach jedem Kanal `{"__channel": ...}`. Kanaele im Plan
  ohne Abschlusszeile sind "abgebrochen", nie "keine Treffer". Kanaele ohne
  Treffer werden nur in der Uebersichtszeile `sweep:uebersicht` gezaehlt;
  jeder Kanal mit Treffern oder unvollstaendiger Erhebung bekommt eine eigene
  Zeile `sweep:<Kanal>`. Bei `.evtx`-Auswertung laeuft kein Sweep (die
  Kanalliste des Quellrechners fehlt) — Status "kanal fehlt" mit Vermerk.

### 3.2 normalize

`EventRecord` mit numerischem `level`/`task`/`opcode`/`keywords`,
`properties` als positionaler Vektor, `event_data` nur wenn XML angefordert
wurde. `masking.py` ersetzt GUID, SID, MAC, IP, UNC, Pfad, Hex und Zahlen —
in dieser Reihenfolge, Spezifisches vor Allgemeinem, Zahlen zuletzt.

### 3.3 enrich

Ein einziger Durchlauf ueber den mit `heapq.merge(..., reverse=True)`
zusammengefuehrten, absteigenden Strom erledigt Fingerprint, Zaehler,
Stundenhistogramm, Boot-Session, Kontextfenster und Retention. Dadurch haengt
der Speicherbedarf an der Zahl verschiedener Fingerprints, nicht an der Zahl
der Events.

Weil der Strom absteigend laeuft, wird aus "Kontext vor dem Absturz" technisch
eine Vorwaertspufferung.

Retention: Prioritaets-Reservoir P1 Regeltreffer, P2 Kontext, P3 Level ≤ 2 bei
60 %, P4 Reservoir-Sampling mit festem Seed.

### 3.4 rules

30 Regeln in `core_application`, `core_system`, `hardware`, `noise`,
`security`, `storage`. Overlay aus `%PROGRAMDATA%\WinEventAI\rules`.

Regel-IDs:
`application-error-1000 application-hang-1002 wer-report minidump-vorhanden
kernel-power-41 eventlog-6008 bugcheck-1001 scm-dienst-beendet
scm-dienst-startet-nicht eventlog-boot-marker whea-korrigiert
whea-nicht-korrigiert kernel-pnp-219 windowsupdate-fehler dcom-10016
dhcp-warnung-1003 perflib-1008 dns-client-1014 sec-protokoll-geloescht
sec-protokoll-geloescht-104 sec-audit-policy-geaendert
sec-anmeldefehler-serie sec-remote-anmeldung sec-konto-und-gruppe
sec-neuer-dienst sec-powershell-scriptblock sec-prozesserstellung
disk-io-fehler storahci-reset-129 ntfs-dateisystemschaden`

Der Schema-Validator lehnt eine Regel ohne `provider` ab und verlangt bei
`message_regex` ein `locale:`-Feld.

### 3.5 kb

SQLite. Schluessel ist `provider` + `event_id`, nicht die ID allein.
`confidence` hat eine **Folge im Code**: nur `sicher` wird in den Prompt
eingebettet; alles andere erscheint im Bericht als "keine gesicherte Bedeutung
hinterlegt". Nicht abgedeckte Paare landen in `unknown_ids.csv` als
Arbeitsliste. Die KB verlinkt Quellen, statt fremden Text zu kopieren.

### 3.6 ai

- Strukturierte Ausgabe: JSON-Schema im `format`-Feld von Ollama.
- Jede Aussage traegt `evidence` als strukturierte Felder (Provider, ID,
  Zeitstempel). `verify.py` prueft jede Aussage einzeln gegen die Eingabe und
  verwirft nur die ungedeckten — nicht die ganze Antwort.
- Redaction mit stabilen Pseudonymen. Die Zuordnungstabelle liegt neben dem
  Bericht und geht **nicht** mit (`--report-redacted`).
- `num_ctx` wird gegen `/api/show` begrenzt.
- `OllamaStatus` trennt `reachable` von `model_present`.
- Lokale Adressen umgehen den Proxy aus der Umgebung.

### 3.7 probes (neu in 1.2.0)

| Sonde | Haengt an | Misst |
|---|---|---|
| `netz` | DNS-Client 1014, Dhcp-Client 1003, Tcpip 4227/4231, NetBT 4321 | Ping an DNS/Gateway/DHCP **plus echte Namensabfrage** |
| `dienst` | SCM 7000/7009/7024/7031/7034/7043 | Zustand, Starttyp, Konto, Exit-Code |
| `datentraeger` | disk 7/11/51/52/153, storahci/stornvme/iaStorA 129, Ntfs 55/98/137, volsnap 25, volmgr 46 | Gesundheit, Zuverlaessigkeitszaehler, SMART, freier Platz |

Dateien: `base.py` (Begriffe), `shell.py` (Aufruf + NDJSON),
`network.py`, `services.py`, `storage.py`, `runner.py`,
`scripts/probe_{network,services,storage}.ps1`.

Datenmodell:

```python
class ProbeStatus(StrEnum):
    OK = "unauffaellig";       WARN = "auffaellig"
    FAILED = "fehlgeschlagen"; NOT_APPLICABLE = "nicht anwendbar"
    NO_PERMISSION = "keine rechte"; TIMED_OUT = "abgebrochen"
    DISABLED = "abgeschaltet"; UNAVAILABLE = "nicht messbar"

class ProbeBearing(StrEnum):
    SUPPORTS = "stuetzt den Befund"
    WEAKENS  = "spricht dagegen"
    INCONCLUSIVE = "sagt dazu nichts"
```

`NO_MEASUREMENT` ist die Menge der Zustaende, in denen **nicht gemessen
wurde** — `ProbeResult.measured` leitet sich daraus ab. Ein "unauffaellig" ist
eine Messung; alles andere ist das Fehlen einer Messung und darf im Bericht nie
wie eine Entwarnung aussehen.

Jede Sonde implementiert `target_for(finding) -> str | None` und
`run(targets: dict[str, list[Finding]]) -> list[ProbeResult]`.
Der Runner sammelt alle Ziele und startet jede Sonde **genau einmal**.

### 3.8 report

`ReportModel` ist die einzige Quelle fuer HTML, Markdown und JSON — die drei
entstehen aus dem Modell, nicht auseinander. Das HTML ist eine einzige Datei
ohne externe Ressourcen: kein CDN, keine nachgeladene Schrift. Eine
HTML-Datei, die beim Oeffnen ins Netz greift, ist auf einem untersuchten
Rechner das falsche Signal.

### 3.9 gui

PySide6 statt FastAPI+HTML (Entscheidung des Auftraggebers). Lauf im `QThread`.
Kein QtWebEngine (~150 MB Chromium); der HTML-Bericht oeffnet im
System-Browser. `theme.py` teilt die Palette mit dem Bericht, `delegates.py`
zeichnet Schweregrad und Quellstatus als Chips — Farbe allein waere die
einzige Unterscheidung, und rund acht Prozent der Maenner halten Rot und
Orange nicht auseinander.

## 4. Laufverzeichnis

```
%PROGRAMDATA%\WinEventAI\runs\2026-09-10T14-22-03Z_WS-4711\
  run.json                 Zeitfenster, Host, Konto, Tool-Version, TZ-Offset
  sources.json             je Quelle: Status, abgedeckter Zeitraum, Zahlen
  raw\*.ndjson             ein Record je Zeile, absteigend nach Zeit
  derived\groups.json      Fingerprint-Gruppen
  derived\findings.json    Regeltreffer (enthaelt jetzt "sonden")
  derived\bundles\*.json   exakt das, was an das Modell ging (nach Redaction)
  derived\ai\*.json        exakt das, was zurueckkam, plus Pruefergebnis
  report\bericht.html|md|json
  unknown_ids.csv          Arbeitsliste fuer die Wissensbasis
  applog.jsonl             eigenes Anwendungslog, getrennt vom Material
```

## 5. Konfiguration

Schichtung: mitgelieferte Vorgaben → `%PROGRAMDATA%\WinEventAI\wineventai.yaml`
→ `--config` → CLI-Schalter. Listen werden **ersetzt**, nicht zusammengefuehrt.

`config init` schreibt die Datei **vollstaendig auskommentiert**. Wirksam wird
nur, was jemand einkommentiert. Grund: Eine Datei, die niemand angelegt hat,
liest auch niemand — friert aber trotzdem Werte ein.

**Dokumentierte Falle im Dateikopf:** Wer nur `#   days: 7` einkommentiert,
ohne den Elternschluessel `collect:`, landet bei einem Top-Level-`days`, und
pydantic lehnt das ab. Dafuer gibt es einen eigenen Test
(`test_vergessener_elternschluessel_bricht_sichtbar_ab`).

Abschnitte: `collect`, `enrich`, `rules`, `ai`, `probes`, `report`,
`log_level`.

## 6. Auslieferung

- Entwicklung ueber pip, Auslieferung ueber PyInstaller **one-dir**.
- Zwei EXE aus einer Analyse: `wineventai.exe` (`console=True`) und
  `wineventai-gui.exe` (`console=False`). QtWebEngine, QML, Quick, Charts sind
  ausgeschlossen. `upx=False`.
- Kein Codesigning-Zertifikat. Verteilung ueber internen Share mit
  dokumentiertem SHA-256.
- `resources.py` ist der einzige Ort, der `_MEIPASS`, das EXE-Verzeichnis und
  `importlib.resources` kennt.

## 7. Evidenz

ZIP mit den **originalen `.evtx`**. Der Hash geht ueber das Original, nicht
ueber den Auszug. Das Bundle ist **nicht redigiert** — es ist Evidenz; die
Redaction betrifft ausschliesslich den Pfad zum Sprachmodell, und die
Zuordnungstabelle wird nicht mit exportiert.

## 8. Behobene Fehler (mit der Lehre dahinter)

| Version | Fehler | Lehre |
|---|---|---|
| — | Burst feuerte nie bei konzentrierten Ereignissen: Median der belegten Stunden = 64, wenn alle 64 Events in einer Stunde liegen | Basislinie ueber das ganze Fenster, nicht ueber belegte Stunden |
| — | 1400× DCOM 10016 fuellte das P1-Kontingent | Rauschregeln zaehlen nicht als Regeltreffer |
| — | YAML-Listeneintrag mit `": "` wurde Mapping | 5 Stellen in Anfuehrungszeichen |
| 1.0.1 | Fehlendes Modell meldete sich als "Ollama nicht erreichbar" | 404 von `/api/show` ist nicht "unerreichbar"; `OllamaStatus` trennt beides |
| 1.0.1 | `urllib` nahm `HTTP_PROXY` auch fuer localhost | `ProxyHandler({})` fuer lokale Adressen |
| 1.0.2 | Benutzerkonfiguration entstand nie | `config init`, vollstaendig auskommentiert |
| 1.1.0 | `GuiLogStream` haengte das **prozessweite** Log an das Signal EINES Workers; nach dessen Tod warf jeder Log-Aufruf "Signal source has been deleted" und riss 13 fremde Tests mit | Der Stream faengt `RuntimeError`, der Worker loest das globale Log im `finally` |
| 1.1.1 | `pip install "wineventai[gui]"` schlug fehl | Dokumentationsfehler — das Paket liegt nicht auf PyPI; `install.ps1` entfernt eine vorhandene Installation zuerst |
| 1.1.1 | Schweregrad-Chips rechts abgeschnitten | `sizeHint` verbreitert, Clip gelockert |
| 1.3.0 | System, Application und Setup meldeten auf einem echten Windows 11 "keine Treffer, 0 gelesen". `-XmlForIds "1001,4624,..."` scheiterte ueber `-File` an der `[int[]]`-Umwandlung, das Skript lief nie, und null Zeilen ohne Statuszeile wurden als leer gewertet | Listen gehen als `\|`-getrennte Zeichenkette an jedes Skript (`shell.LIST_SEPARATOR`); fehlt die Statuszeile, ist die Quelle `FAILED` mit der FullyQualifiedErrorId aus stderr - nie `EMPTY` |
| 1.3.0 | Dasselbe bei den Sonden: `-Role "dns,gateway"` kam als EIN Element an (`-contains 'dns'` still falsch), `-DisplayName a b c` band nur den ersten Namen | dieselbe Listen-Konvention |
| 1.3.0 | Ein fehlender Kanal (`Kernel-Power/Operational` gibt es auf Windows 11 nicht) erschien als "keine Treffer" | Unterscheidung ueber die sprachneutrale FullyQualifiedErrorId: `NoMatchingEventsFound` = leer, `NoMatchingLogsFound` = Kanal fehlt (`base.ERROR_ID_STATUS`) |
| 1.3.0 | `doctor` meldete vorhandene Kanaele als "FEHLT": `-ListLog * -ErrorAction Stop` brach ohne Adminrechte beim ersten nicht lesbaren Kanal ab | `list_channels.ps1` prueft jeden konfigurierten Namen einzeln und trennt fehlend / nicht lesbar |
| 1.3.0 | Status-Chips in der Abdeckungstabelle doppelt beschriftet | `QStyledItemDelegate.paint` fuellt den Text intern neu; Hintergrund wird jetzt direkt ueber `drawControl` gezeichnet |
| 1.3.0 | Hinweise je Quelle standen nur im Tooltip | eigene Spalte "Hinweis" |

## 9. Offene Punkte

**Braucht echtes Windows:**

1. **Die neun `.ps1`-Dateien sind unbewiesen.** Die Auswertung ab
   `read_ndjson` / `read_payloads` / `parse_sweep` ist vollstaendig getestet,
   die Skripte selbst nicht. Konkret unsicher:
   - `sweep_errors.ps1` **auf Windows 11 26200 / PS 5.1 ohne Adminrechte
     gelaufen**: 146 Kanaele im Plan, 4145 Fehler in 6 s. `-ListLog *` mit
     `SilentlyContinue` laeuft weiter; nicht lesbare Kanaele (56) erscheinen
     gar nicht in der Liste, sondern nur als `LogInfoUnavailable` in
     `-ErrorVariable` - die `RecordCount`-Frage stellt sich damit nicht.
     Unbestaetigt: mit Adminrechten, unter PowerShell 7, auf Server.
   - Entscheidung zur Pruefung: Nicht lesbare Kanaele machen die
     Uebersichtszeile NICHT unvollstaendig, sondern stehen dort nur als Zahl.
     Ohne Adminrechte waere der Sweep sonst immer "unvollstaendig" und die
     Markierung verloere ihre Aussage. Die Namen dieser Kanaele kennt das
     Skript nicht.
   - Liefert `Win32_NetworkAdapterConfiguration.DHCPServer` auf Server-Systemen
     zuverlaessig einen Wert?
   - Existiert `MSStorageDriver_FailurePredictStatus` ausserhalb von Hyper-V?
   - Greift `Resolve-DnsName -QuickTimeout` unter PowerShell 5.1 wie erwartet?
2. **Einwand E02:** Sind `Microsoft-Windows-WHEA-Logger` und `storahci`
   wirklich nur Provider im System-Kanal und keine eigenen Kanaele?
   `wineventai doctor` gleicht das ab — braucht eine echte Maschine.
3. **Durchsatz des Collectors ungemessen.** An einem echten Security-Log
   messen, bevor ueber `pywin32` als Alternative entschieden wird.
4. ~~"Keine Ereignisse gefunden" nicht typisiert~~ — **geklaert in 1.3.0**
   (Windows 11 26200, de-AT, PS 5.1): Typ ist immer `System.Exception`, aber
   die FullyQualifiedErrorId unterscheidet `NoMatchingEventsFound` (leer) von
   `NoMatchingLogsFound` (Kanal fehlt). **Neue Falle:** Security ohne
   Adminrechte liefert ebenfalls `NoMatchingEventsFound`; davor schuetzt nur
   die `requires_admin`-Pruefung. Unbestaetigt fuer PowerShell 7 und Server.

**Noch nicht gebaut:**

5. **`kb bench`** — Abnahmetest fuer die Modellwahl ist spezifiziert, aber
   nicht implementiert. Solange ist die Modellwahl offen; Default steht auf
   `qwen2.5:14b-instruct`.
6. **Weitere Sonden**, aber nur nach demselben Kriterium (jede Sonde muss
   einen Befund erklaeren oder ausschliessen):
   - Domaenencontroller zu Netlogon 5719 — braucht eine belastbare Quelle fuer
     die DC-Adresse ohne `nltest`. Ungeloest.
   - Zeitsynchronisierung zu W32Time 36/47 — plausibler Kandidat.

## 10. Entscheidungen, die bewusst NICHT getroffen wurden

- **Kein Internet-Speedtest.** Er braeche drei Zusagen gleichzeitig: "offline
  lauffaehig", "keine Telemetrie" (die eigene IP ginge an den Anbieter) und
  "read-only" (er saettigt die Leitung und erzeugt auf einem gestoerten
  Rechner genau die Stoerung, die man sucht).
- **Kein automatisches Verkleinern des Zeitfensters bei Datenmengen.** Das
  Ergebnis waere still unvollstaendig, und jemand liest "keine Befunde" fuer
  einen Zeitraum, der nie analysiert wurde.
- **Keine Sondenergebnisse im Prompt.** Sie tragen keine Event-IDs, also kann
  die Belegpruefung sie nicht gegen die Eingabe halten. Alles Unpruefbare im
  Bundle ist eine Einladung zum Erfinden. Deshalb laufen die Sonden in
  `analyze_run` nach dem KI-Layer — strukturell, nicht per Konvention.
- **Keine Messung auf einem fremden Rechner.** Der Runner vergleicht
  `RunMeta.host` mit dem lokalen Namen und misst bei Abweichung nichts.
- **Kein `nltest`, kein `fsutil dirty`, kein Selbsttest.** Alles entweder nicht
  read-only oder nicht verlaesslich verfuegbar.
