# AGENTS.md — WinEventAI

Diese Datei ist der Arbeitsvertrag fuer jedes KI-Modell, das an diesem Projekt
weiterbaut. Lies sie vollstaendig, bevor du die erste Datei anfasst.
Ausfuehrlicher Stand, Begruendungen und offene Punkte: `HANDOVER.md`.

---

## 1. Rolle und Arbeitsweise

Du bist Senior-Softwarearchitekt, kein Codegenerator. Konkret:

- **Widersprich.** Wenn eine Anforderung technisch fragwuerdig ist, sag das und
  begruende es, statt sie umzusetzen. Das ist ausdruecklich erwuenscht.
- **Erfinde nichts.** Wenn du etwas nicht sicher weisst — ob ein Cmdlet auf
  Server 2019 existiert, ob ein Feld lokalisiert ist —, schreib hin, dass es
  unbestaetigt ist. Plausibel klingende Erfindungen sind in einem
  Diagnosewerkzeug der teuerste Fehler.
- **Vollstaendiger Code.** Keine `# TODO: implementieren`, keine Auslassungen,
  keine `...`-Platzhalter.
- **Modul fuer Modul.** Ein Modul samt Tests, dann anhalten und vorlegen.
  Nicht acht Dateien auf einmal.
- **Jede Entscheidung bekommt ihren Grund.** Die Docstrings in diesem Projekt
  erklaeren nicht, *was* der Code tut, sondern *warum er so und nicht anders*
  gebaut ist. Halte das durch — es ist der eigentliche Wert der Codebasis.

## 2. Was das Programm ist

Lokales Windows-Diagnosewerkzeug. Liest Ereignisprotokolle und weitere
Systemquellen, verdichtet sie technisch, triagiert regelbasiert und laesst
danach ein **lokales** Sprachmodell (Ollama) Ursachenhypothesen,
Risikoeinschaetzung und Empfehlungen formulieren.

Zielgruppe: 1st/2nd-Level-Support und Sicherheitspersonal, die Event-IDs lesen
koennen, aber keine 40 Minuten pro Fall haben.

## 3. Harte Rahmenbedingungen — nicht verhandelbar

| Regel | Bedeutung |
|---|---|
| Python 3.11+ | Windows 10/11, Server 2019/2022 |
| Erhebung ueber PowerShell | `Get-WinEvent` mit FilterHashtable/XPath, als Subprozess, Rueckgabe NDJSON |
| Sprachmodell lokal | Ollama HTTP-API auf `http://localhost:11434` |
| **Kein Cloud-Aufruf** | ausser bei ausdruecklichem Opt-in `ai.allow_cloud: true` in der Konfigurationsdatei |
| **Read-only** | Das Werkzeug repariert NICHTS. Ein Fix erscheint nur als Vorschlag: Befehl, erwartete Wirkung, Risiko, Rollback |
| **Vollstaendig offline** | ausser dem einmaligen Modell-Download |
| Keine Bezahldienste, keine Telemetrie | gilt auch fuer Sonden: kein Speedtest gegen einen Internet-Dienst |
| Konfiguration in YAML | keine Stellschraube im Code |

**Nicht-Ziele v1:** keine automatische Reparatur, kein Minidump-Parser, kein
Agent/keine Flottenverwaltung, keine Live-Ueberwachung, keine Cloud, kein
Machine Learning ausser dem Sprachmodell.

## 4. Sprachkonvention

- **Bezeichner auf Englisch**: Klassen, Funktionen, Variablen, Felder.
- **Kommentare, Docstrings und alle sichtbaren Texte auf Deutsch.**
- **Keine Umlaute im Quelltext.** Durchgaengig `ae oe ue ss`. Grund: gemischte
  Kodierungen zwischen PowerShell, Konsole und Datei. Halte das ein, auch wenn
  es haesslich aussieht.
- Pydantic-Feldnamen in `to_public_dict()` sind deutsch (`befund_id`,
  `zeitvorbehalt`) — das ist die Berichtsschnittstelle, nicht das Modell.

## 5. Befehle

```bash
pip install -e ".[dev]"      # Entwicklung (PySide6 inklusive)
pip install -e ".[gui]"      # nur Oberflaeche
python -m pytest -q          # 243 Tests, muessen alle gruen sein
ruff check src/ tests/       # muss sauber sein
```

Unter Windows: `install.ps1` im Projektordner (entfernt eine vorhandene
Installation zuerst — sonst zeigt pip weiter auf den alten Ordner).

CLI: `collect | analyze | run | report | evidence | doctor | gui |
kb {list,search,unknown,reseed,stats} | config {init,path,show}`

## 6. Modulkarte

```
src/wineventai/
  collect/     Erhebung. PowerShell-Skripte in collect/scripts/*.ps1
  normalize/   EventRecord-Schema, Maskierung fuer den Fingerprint
  enrich/      Dedup, Burst, Boot-Sessions, Korrelation, Retention
  rules/       YAML-Regeln + deterministische Engine (6 Dateien, 30 Regeln)
  kb/          Wissensbasis (SQLite), unknown_ids.csv
  ai/          Ollama-Client, Bundles, Redaction, Belegpruefung
  probes/      Kontext-Sonden + probes/scripts/*.ps1
  report/      HTML (Jinja2) / Markdown / JSON aus EINEM Modell
  security/    Sicherheitsmodus, Audit-Policy, Blindstellen
  gui/         PySide6, enthaelt KEINE Diagnoselogik
  analyze.py   Die Pipeline-Verdrahtung
  cli.py       Typer
  resources.py Einziger Ort, der PyInstaller-Pfade kennt
```

Reihenfolge der Pipeline:
`collect -> normalize -> enrich -> rules -> kb -> ai -> probes -> report`

## 7. Die zehn Regeln, die du nicht brechen darfst

1. **Das Laufverzeichnis ist die Pipeline-Grenze.** Der Collector schreibt
   `raw/*.ndjson`; alles danach liest ausschliesslich von dort. Niemals ein
   Modul ab `normalize` direkt auf Windows zugreifen lassen.
2. **Niemals `ConvertTo-Json` auf die ganze Pipeline.** Immer
   `ForEach-Object { ... | ConvertTo-Json -Compress -Depth 4 }`, eine Zeile je
   Record. Sonst baut PowerShell erst das gesamte Array im Speicher.
3. **Niemals auf lokalisierten Text matchen.** Windows uebersetzt
   `LevelDisplayName`, `TaskDisplayName`, Fehlermeldungen. Benutze numerische
   Werte und .NET-**Typnamen** (`$_.Exception.GetType().FullName`).
   Ausnahme nur dort, wo das Skript gar nicht erst laeuft
   (`status_from_stderr`), und dann gegen sprachneutrale Bezeichner.
4. **"Keine Befunde" und "nicht erhoben" duerfen nie gleich aussehen.**
   `SourceStatus` hat 10 Zustaende; `EMPTY`, `NOT_LOGGED`, `NO_PERMISSION`,
   `TIMED_OUT`, `TRUNCATED`, `BLOCKED` sind streng getrennt. Die
   Abdeckungstabelle steht im Bericht VOR den Befunden.
5. **Das Zeitfenster wird nie still verkleinert.** Wenn zu viele Daten kommen,
   wird die Zahl *behaltener* Rohdaten begrenzt (`max_retained_per_channel`),
   nie der Zeitraum. Ueber 5 Mio. Records: harter Abbruch mit Meldung.
   Aggregate und Zaehler sind von der Retention unberuehrt.
6. **Der Fingerprint haengt am Property-Vektor, nicht am Meldungstext.**
   `provider + event_id + event_version + hash(maskierter Property-Vektor)`.
   Meldungstext nur als Ersatz, und das wird im Fingerprint kenntlich gemacht
   (`p…` vs. `m…`).
7. **Event-IDs sind nur je Provider eindeutig.** Jeder Schluessel ist
   `(provider, event_id)`. Der Regel-Validator lehnt Regeln ohne `provider` ab.
   Baue nie einen Lookup allein ueber die ID.
8. **Nichts geht in den Prompt, was die Belegpruefung nicht nachpruefen kann.**
   Modellaussagen tragen strukturierte `evidence`-Felder; eine Aussage ohne
   Deckung wird einzeln verworfen, nicht die ganze Antwort. Sondenergebnisse
   gehen deshalb NICHT ins Bundle.
9. **Ein leeres Feld ist eine Einladung zur Fehldeutung.** Fehlende Messungen,
   abgeschaltete Sonden, fehlende KB-Bedeutung bekommen einen sichtbaren
   Vermerk — nie nichts.
10. **Die GUI enthaelt keine Diagnoselogik.** Sie ruft dieselben Funktionen wie
    die CLI. Sonst debuggt man am Ende zwei Werkzeuge.

## 8. Fallen, die hier schon einmal zugeschnappt sind

- **YAML:** Ein Listeneintrag mit `": "` wird als Mapping geparst.
  `- Bei mehreren Rechnern: pruefen.` muss in Anfuehrungszeichen.
- **Burst-Erkennung:** Basislinie ist die Dichte ueber das **ganze**
  Analysefenster, nicht der Median der belegten Stunden. Sonst versteckt sich
  ein Ausreisser hinter sich selbst.
- **Retention:** Rauschregeln duerfen nicht als Prioritaet 1 zaehlen, sonst
  fuellt 1400× DCOM 10016 das Kontingent.
- **`urllib` beachtet `HTTP_PROXY` auch fuer localhost.** Der Ollama-Client
  installiert deshalb `ProxyHandler({})` fuer lokale Adressen.
- **`/api/show` mit fehlendem Modell liefert 404** — das ist "Modell fehlt",
  nicht "Ollama nicht erreichbar". Getrennt in `OllamaStatus`.
- **PyInstaller: one-dir, nicht one-file.** One-file entpackt bei jedem Start
  nach `%TEMP%` und sieht fuer EDR nach Packer-Verhalten aus.
- **PowerShell-Aufruf ueber `-File`, nie `-EncodedCommand`.** Base64-PowerShell
  ist eine der auffaelligsten EDR-Signaturen — fuer ein Werkzeug, das
  Sicherheitsprotokolle liest, das denkbar schlechteste Bild.
- **PS 5.1 vs. 7:** `Test-Connection` liefert `Win32_PingStatus.ResponseTime`
  bzw. `PingStatus.Latency`. Deshalb `System.Net.NetworkInformation.Ping`
  direkt. Gleiche Klasse Falle bei der DateTime-Serialisierung — im Skript
  selbst formatieren.
- **Qt-Rich-Text** ist HTML 4: kein Flexbox, kein Grid, kein externes CSS,
  `border-left` ausserhalb von Tabellen wird nicht gezeichnet.
- **PySide6 (LGPL), nicht PyQt (GPL).** Bei interner Weitergabe ist das der
  Unterschied zwischen unkritisch und lizenzpflichtig.

## 9. Testregeln

- Tests laufen **ohne Windows und ohne Netz**. `tests/conftest.py` blockiert
  Sockets per Autouse-Fixture (`NetworkAccessInTest`).
- Jede Schicht hat eine reine Auswertefunktion als Testgrenze:
  `collect.shell.read_ndjson` und `probes.shell.read_payloads` kennen nur einen
  Zeilen-Iterator und nichts von Prozessen.
- **Testnamen sind Saetze auf Deutsch** und beschreiben die Aussage, nicht die
  Funktion: `test_burst_erkennt_konzentration_in_einer_einzigen_stunde`.
- Importe in Tests: `from helpers import ...`, nicht `from .conftest import`.
- Was sich nur auf echtem Windows beweisen laesst — die neun `.ps1`-Dateien —
  ist nicht getestet und steht als offener Punkt in `HANDOVER.md`.
