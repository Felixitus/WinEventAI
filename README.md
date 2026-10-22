# WinEventAI

Lokales Diagnosewerkzeug fuer Windows. Liest Ereignisprotokolle und weitere
Systemquellen, verdichtet sie technisch, triagiert regelbasiert und laesst
anschliessend ein **lokales** Sprachmodell die Befunde erklaeren.

**Read-only.** Das Werkzeug repariert nichts. Ein Fix wird nur als Vorschlag
ausgegeben: Befehl, erwartete Wirkung, Risiko, Rueckbau.

**Offline.** Ausser dem einmaligen Modell-Download geht nichts ins Netz. Ein
Aufruf ausserhalb von `localhost` ist ohne ausdrueckliches `ai.allow_cloud: true`
gesperrt.

---

## Was das Werkzeug leistet

| Stufe | Modul | Aufgabe |
|---|---|---|
| 1 | `collect` | Rohe Records je Quelle in ein Laufverzeichnis, streamend |
| 2 | `normalize` | Einheitliches Event-Schema, sprachneutral |
| 3 | `enrich` | Dedup, Burst, Boot-Sessions, Zeitfenster-Korrelation |
| 4 | `rules` | Deterministische Triage, Regeln in YAML |
| 5 | `ai` | Erklaerer und Korrelator auf dem verdichteten Befund |
| 6 | `probes` | Kontext-Sonden: messen zu einem Befund den aktuellen Zustand |
| 7 | `report` | HTML, Markdown, JSON aus einem gemeinsamen Modell |
| 8 | `cli` | Typer-Kommandozeile |

Der Bericht entsteht **vollstaendig auch ohne Sprachmodell**. Die KI liefert die
letzten zwanzig Prozent; Dedup, Rauschfilter und Wissensbasis sind der Kern.

## Installation

WinEventAI liegt **nicht auf PyPI**. Installiert wird aus dem entpackten
Projektordner - dem Verzeichnis, in dem `pyproject.toml` liegt.

```powershell
cd C:\pfad\zu\winevent-ai        # dort liegt pyproject.toml
py -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -e .                   # nur Kommandozeile
pip install -e ".[gui]"            # mit grafischer Oberflaeche
pip install -e ".[dev]"            # mit Tests und Linter (enthaelt die GUI)
```

Der Punkt am Ende ist wichtig: Er bedeutet "das Paket in diesem Verzeichnis".
Ohne ihn sucht pip auf PyPI und findet dort nichts oder etwas Fremdes.

Kuerzer geht es mit dem mitgelieferten Skript, das zusaetzlich eine alte
Installation aus dem Weg raeumt und die Python-Version prueft:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1          # mit Oberflaeche
powershell -ExecutionPolicy Bypass -File .\install.ps1 -NoGui   # nur CLI
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Venv    # in .venv
```

**Auf eine neue Fassung wechseln.** Die alte Installation zeigt sonst weiter
auf den alten Ordner:

```powershell
pip uninstall -y wineventai
cd C:\pfad\zur\neuen\fassung
pip install -e ".[gui]"
wineventai --version               # muss die neue Nummer zeigen
```

Ohne `-e` wird kopiert statt verlinkt; dann braucht jede Aenderung am Code
eine erneute Installation. Fuer den reinen Einsatz ist das in Ordnung, beim
Weiterentwickeln nicht.

## Schnellstart

```powershell
wineventai doctor                      # Umgebung pruefen, BEVOR etwas ausgewertet wird
wineventai run                         # Erhebung + Auswertung, 7 Tage
wineventai run --days 30 --no-ai       # laengeres Fenster, ohne Modell
wineventai run --security              # Sicherheitsmodus (braucht Adminrechte)
wineventai analyze --run <verzeichnis> # Neuauswertung ohne Neuerhebung
wineventai evidence --run <verzeichnis> --channel System --channel Security
```

`wineventai doctor` zuerst: Es prueft die konfigurierten Kanaele gegen
`Get-WinEvent -ListLog *`. Ein Filter auf einen nicht existierenden Kanal wuerde
sonst "keine Befunde" melden - die schlimmste Fehlerart in diesem Werkzeug.

## Grafische Oberflaeche

```powershell
pip install -e ".[gui]"    # im Projektordner, in dem pyproject.toml liegt
wineventai gui
```

PySide6 (Qt, LGPL) ist eine **optionale** Abhaengigkeit. Die Kommandozeile
laeuft ohne Qt - sie ist der Weg fuer Server, Softwareverteilung und Sitzungen
ohne grafische Anmeldung.

Das Fenster ist eine Huelle: Es ruft dieselben Funktionen wie die
Kommandozeile und enthaelt keine eigene Diagnoselogik. Sonst driften GUI und
CLI auseinander, und man debuggt am Ende zwei Werkzeuge.

Aufbau, in dieser Reihenfolge und aus denselben Gruenden wie im Bericht:

| Element | Zweck |
|---|---|
| Startleiste | Zeitfenster, Sicherheitsmodus, Sprachmodell an/aus, Start und Abbruch |
| Kopfzeile | Der eine Satz, der zuerst gelesen wird |
| Warnbanner | Erscheint, wenn der Zeitraum nicht vollstaendig erhoben wurde |
| Reiter *Abdeckung* | Unvollstaendige Quellen zuoberst, gelb hinterlegt, mit Luecken-Markierung |
| Reiter *Befunde* | Liste links (Schwere, Name, Anzahl, zuletzt), Detail rechts - mit den Sondenergebnissen zum ausgewaehlten Befund |
| Reiter *Protokoll* | Das Anwendungslog live waehrend des Laufs |
| Statusleiste | PowerShell, Adminrechte, Ollama-Zustand; Langfassung im Tooltip |

Zwei Entscheidungen, die man im Fenster nicht sieht:

- **Der Lauf laeuft in einem eigenen Thread.** Ein Lauf dauert Minuten; im
  Hauptthread wuerde Windows das Fenster als "reagiert nicht" markieren.
- **Kein QtWebEngine.** Das waeren rund 150 MB Chromium fuer eine Oberflaeche,
  die Text und Tabellen zeigt. Der vollstaendige HTML-Bericht wird stattdessen
  im System-Browser geoeffnet (*Datei › Bericht im Browser oeffnen*) - dort
  gehoert er hin, denn er wird weitergegeben.

Faellt der Zeitraum unvollstaendig aus, springt das Fenster nach dem Lauf von
selbst auf den Reiter *Abdeckung*. Wer "keine Befunde" liest, ohne die Luecke
gesehen zu haben, zieht den falschen Schluss.

## Kontext-Sonden

Eine Sonde misst den **aktuellen** Zustand zu einem **konkreten Befund**. Sie
ist kein freistehendes Werkzeug im Menue: Wer selbst weiss, welchen Knopf er
druecken muss, braucht dieses Programm nicht.

| Sonde | Haengt an | Misst |
|---|---|---|
| `netz` | DNS-Client 1014, Dhcp-Client 1003, Tcpip 4227/4231, NetBT 4321 | Ping an DNS-Server, Standardgateway, DHCP-Server; dazu eine echte Namensabfrage |
| `dienst` | SCM 7000/7009/7031/7034 | Zustand, Starttyp, Konto und letzter Exit-Code des betroffenen Dienstes |
| `datentraeger` | disk 7/51/153, storahci/stornvme 129, Ntfs 55, volsnap 25 | Gesundheit, Zuverlaessigkeitszaehler, SMART-Gesamtstatus, freier Platz |

Fuenf Zusagen, die den Umfang bestimmen:

- **Kein Internet.** Kein Speedtest gegen einen fremden Dienst. Der braeche
  "offline lauffaehig", "keine Telemetrie" (die eigene IP ginge an den Anbieter)
  und "read-only" auf einmal - er saettigt die Leitung und erzeugt auf einem
  gestoerten Rechner genau die Stoerung, die man sucht.
- **Nur lokal, und zwar erzwungen.** Das Skript nimmt keine Zieladresse von
  aussen entgegen; es liest die Adressen selbst aus der IP-Konfiguration und
  ueberspringt jede, die ausserhalb der privaten Bereiche liegt. Wer 8.8.8.8 als
  DNS-Server eingetragen hat, bekommt dafuer keine Messung, sondern den Vermerk.
- **Nur auf dem erhobenen Rechner.** Wer den Lauf eines Servers am Arbeitsplatz
  auswertet, bekommt keine Messung, sondern den Satz, dass sie den falschen
  Rechner beschreiben wuerde.
- **Der Zeitabstand hat eine Folge im Code.** Eine Sonde misst JETZT, der Befund
  entstand DAMALS. Jedes Ergebnis traegt den Abstand als Feld und den Vorbehalt
  als Satz; ein "spricht dagegen" wird zu "sagt dazu nichts" abgestuft, sobald
  mehr als eine Stunde dazwischen liegt. Ein "stuetzt den Befund" wird nicht
  abgestuft - ein Dienst, der heute noch steht, stuetzt den Ausfall von
  vorgestern sehr wohl.
- **Sonden gehen nicht in den Prompt.** Ein Messergebnis traegt keine
  Event-IDs, also kann die Belegpruefung es nicht gegen die Eingabe halten.
  Alles, was im Bundle steht und nicht pruefbar ist, ist eine Einladung zum
  Erfinden.

Abschalten: `--no-probes` oder `probes.enabled: false` in der Konfiguration.
Eine einzeln abgeschaltete Sonde bleibt in der Befundkarte sichtbar - ein "hier
wurde nichts gemessen" ist eine Information, ein leeres Feld eine Einladung, es
fuer ein Messergebnis zu halten.

Was eine Sonde ausdruecklich **nicht** leistet: Ein sauberer SMART-Status ist
kein Gesundheitszeugnis, und ein DNS-Server, der auf Ping antwortet, kann einen
toten DNS-Dienst haben. Beides steht so im Ergebnistext und beides fuehrt zu
"sagt dazu nichts", nicht zu "spricht dagegen".

## Das Laufverzeichnis

Der Collector schreibt nicht in Objekte, sondern in ein Verzeichnis; alles
danach liest nur von dort.

```
%PROGRAMDATA%\WinEventAI\runs\2026-09-10T14-22-03Z_WS-4711\
  run.json                 Zeitfenster, Host, Konto, Tool-Version, TZ-Offset
  sources.json             je Quelle: Status, abgedeckter Zeitraum, Zahlen
  raw\*.ndjson             ein Record je Zeile, absteigend nach Zeit
  derived\groups.json      Fingerprint-Gruppen
  derived\findings.json    Regeltreffer
  derived\bundles\*.json   exakt das, was an das Modell ging (nach Redaction)
  derived\ai\*.json        exakt das, was zurueckkam, plus Pruefergebnis
  report\bericht.html|md|json
  unknown_ids.csv          Arbeitsliste fuer die Wissensbasis
  applog.jsonl             eigenes Anwendungslog, getrennt vom Material
```

Damit sind Live-Erhebung und mitgebrachter `.evtx`-Export derselbe Code,
`analyze --run` laeuft ohne Neuerhebung, und das Evidenz-Manifest entsteht aus
Dateien, die ohnehin dort liegen.

## Die drei Lagen, die niemals gleich aussehen duerfen

| Status | Bedeutung |
|---|---|
| `keine treffer` | Erhoben, im Zeitfenster nichts gefunden. **Das** ist "kein Befund". |
| `nicht protokolliert` | Windows erhebt die Quelle auf diesem System gar nicht. |
| `keine rechte` | Quelle existiert, der Lauf hatte keine Berechtigung. |
| `abgebrochen` / `unvollstaendig` | Nur ein Teil des Zeitraums liegt vor. |

Die Abdeckungstabelle steht im Bericht **vor** den Befunden, mit angefordertem
und tatsaechlich abgedecktem Zeitraum je Quelle.

## Konfiguration

```powershell
wineventai config path     # wo wird gesucht, was ist vorhanden
wineventai config init     # Benutzerkonfiguration anlegen
wineventai config show     # WIRKSAME Werte nach dem Zusammenfuehren
```

Die Datei in `%PROGRAMDATA%\WinEventAI\` entsteht **nicht von selbst**. Das ist
Absicht: Eine Datei, die niemand angelegt hat, liest auch niemand - und friert
trotzdem Werte ein.

`config init` schreibt sie **vollstaendig auskommentiert**. Wirksam wird nur, was
Sie einkommentieren; alles uebrige bleibt an den mitgelieferten Vorgaben und
wandert mit kuenftigen Versionen mit. `--full` schreibt stattdessen alle Werte
aktiv - bequemer, aber es friert die Vorgaben des Installationstags ein.

YAML-Falle beim Einkommentieren: Der **Elternschluessel muss mit**. Aus

```yaml
# collect:
#   days: 7
```

wird

```yaml
collect:
  days: 30
```

Nur die Wertzeile einzukommentieren setzt `days` auf oberster Ebene, und der
Start bricht mit "Extra inputs are not permitted" ab. Das ist gewollt: Ein
Tippfehler in der Konfiguration darf nicht still wirkungslos bleiben.

Rangfolge, schwaechste zuerst: mitgelieferte Vorgaben →
`%PROGRAMDATA%\WinEventAI\wineventai.yaml` → `--config <datei>` → CLI-Schalter.

Wichtige Werte:

```yaml
collect:
  days: 7
  max_retained_per_channel: 200000   # Grenze fuer BEHALTENE Rohdaten
  abort_above_records: 5000000       # harter Abbruch mit Vorschlag
  channel_timeout_seconds: 120       # je Kanal, danach "abgebrochen"
ai:
  base_url: "http://localhost:11434"
  model: "qwen2.5:14b-instruct"
  num_ctx: 16384                     # immer explizit, nie der Ollama-Default
  temperature: 0.1
  allow_cloud: false
```

Das Zeitfenster wird **nie automatisch verkleinert**. Ein still verkleinertes
Fenster laesst jemanden "keine Befunde" fuer einen Zeitraum lesen, der nie
analysiert wurde.

## Regeln erweitern

Mitgelieferte Regeln liegen im Paket, eigene in
`%PROGRAMDATA%\WinEventAI\rules\*.yaml`. Zusammengefuehrt wird nach `id`; die
Herkunft steht im Bericht.

```yaml
- id: eigene-regel
  name: Beispiel
  match:
    channel: System
    provider: Service Control Manager   # PFLICHT
    event_id: [7031, 7034]
  severity: fehler
  bedeutung: Was hier vorliegt.
  typische_ursachen: [Ursache A, Ursache B]
  empfohlene_checks: [Was als Naechstes zu pruefen ist]
  threshold: { count_min: 1, escalate_above: 20, escalate_to: kritisch }
```

`provider` ist Pflicht und wird vom Schema-Validator erzwungen: Event-IDs sind
nur je Provider eindeutig. 1001 ist BugCheck im System-Kanal **und** Windows
Error Reporting im Application-Kanal.

`message_regex` verlangt zusaetzlich eine `locale`-Angabe, weil Meldungstexte
uebersetzt sind. Vorzuziehen sind `data:`-Bedingungen auf benannte
EventData-Felder - deren Namen kommen aus dem Provider-Manifest und sind
sprachneutral.

## Wissensbasis

SQLite mit FTS5 unter `%PROGRAMDATA%\WinEventAI\kb.sqlite`, Schluessel ist
`provider + event_id`.

```powershell
wineventai kb list
wineventai kb search "Stopcode"
wineventai kb unknown --run <verzeichnis>   # Arbeitsliste aus echten Faellen
wineventai kb reseed
```

`confidence` hat eine Konsequenz im Code: Ein Eintrag ohne gesicherte Bedeutung
wird **nicht** in den Prompt eingebettet, und der Befund erscheint im Bericht mit
dem Vermerk "keine gesicherte Bedeutung hinterlegt".

## Sprachmodell

### Adresse einstellen

Drei Wege, staerkster zuletzt:

```yaml
# %PROGRAMDATA%\WinEventAI\wineventai.yaml  - dauerhaft
ai:
  base_url: "http://127.0.0.1:11434"
  model: "llama3.1:8b"
```

```powershell
wineventai run --config .\meine.yaml                 # eigene Datei
wineventai run --ollama-url http://ollama-srv:11434   # einmalig
wineventai doctor --ollama-url http://127.0.0.1:11434 # nur pruefen
```

Ausserhalb von `localhost` braucht es zusaetzlich `ai.allow_cloud: true` - auch
fuer einen Ollama-Host im eigenen LAN. Das ist Absicht: Redigierte Befunde
verlassen dann das untersuchte System, und das soll eine bewusste Entscheidung
sein.

### "Nicht erreichbar", obwohl der Dienst laeuft

`wineventai doctor` unterscheidet die Faelle. In dieser Reihenfolge pruefen:

1. **Modell nicht heruntergeladen.** Haeufigster Fall. `doctor` sagt dann
   "Ollama erreichbar" und listet die vorhandenen Modelle. Abhilfe:
   `ollama pull <modell>` oder `ai.model` auf ein vorhandenes setzen.
2. **Proxy in der Umgebung.** Auf Firmenrechnern setzt `HTTP_PROXY` auch fuer
   `localhost`. WinEventAI umgeht den Proxy fuer lokale Adressen selbst; fuer
   einen Host im LAN bleibt er wirksam.
3. **Port oder Bind-Adresse.** `curl http://localhost:11434/api/tags` beantwortet
   die Frage in einer Zeile.
4. **IPv6 gegen IPv4.** `localhost` kann zu `::1` aufloesen, waehrend Ollama nur
   auf `127.0.0.1` lauscht. Dann `http://127.0.0.1:11434` eintragen.

### Modellwahl

Auswahlkriterien in dieser Reihenfolge:

1. Deklarierte Kontextlaenge ≥ 32k **und** im RAM-Budget bei dieser Laenge -
   der KV-Cache ist der Kostentreiber, nicht die Gewichte.
2. Verlaessliche grammatikgebundene JSON-Ausgabe.
3. Brauchbares Deutsch.
4. Erst dann Parameterzahl.

`num_ctx` wird immer explizit gesetzt und gegen die tatsaechliche Kontextlaenge
aus `/api/show` begrenzt. Fuer die Token-Schaetzung wird bewusst **keine**
externe Tokenizer-Bibliothek verwendet (`tiktoken` laedt beim ersten Gebrauch aus
dem Netz); stattdessen eine Heuristik, die sich gegen `prompt_eval_count` der
Antwort selbst kalibriert.

Jede Modellaussage traegt strukturierte Belege (`provider`, `event_id`,
`timestamp_utc`), die gegen das Eingabebuendel geprueft werden. Verworfen wird
die einzelne Aussage, nicht die gesamte Antwort - und der Bericht zeigt die
Verwerfung, statt sie zu verschweigen.

## Sicherheitsmodus

`--security` wertet zusaetzlich 1102, 104, 4719, 4625-Serien, 4624 Logon Type 10,
4720/4728/4732, 7045/4697, 4104/4103 und 4688 aus und sucht Luecken in der
Zeitachse (nur **innerhalb** laufender Sitzungen - zwischen 6006 und 6005 war der
Rechner aus).

Vorher wird `auditpol` abgefragt. Ist eine Unterkategorie nicht aktiv, meldet der
Bericht "nicht protokolliert" statt "kein Befund". Ohne Adminrechte lautet die
Antwort "Pruefstatus unbekannt" - nicht "aktiv".

Alle Ergebnisse sind ausdruecklich als **Hinweis** gekennzeichnet, nicht als
forensische Feststellung.

## Evidenz

```powershell
wineventai evidence --run <verzeichnis> --channel System --channel Security
```

ZIP mit Original-`.evtx` (`wevtutil epl`), normalisiertem JSON, Bericht,
`manifest.json` und `verify.ps1`. Die Pruefsumme geht ueber das `.evtx`-Original,
nicht ueber den Auszug. Das Bundle ist **nicht** pseudonymisiert - es ist
Evidenz; die Redaction betrifft ausschliesslich den Pfad zum Sprachmodell.

## Datenschutz

Ereignisprotokolle enthalten personenbezogene Daten (Anmeldezeiten, Kontennamen).
`--report-redacted` schreibt zusaetzlich eine weitergabefaehige Fassung mit
stabilen Pseudonymen; die Zuordnungstabelle liegt separat daneben.

Fuer den Regelbetrieb im Support vorher mit Datenschutz und
Arbeitnehmervertretung klaeren.

## Tests

```powershell
pytest
ruff check .
```

Collector, Normalizer, Enricher und Regel-Engine sind ohne Windows und ohne
laufendes Ollama testbar. Eine `autouse`-Fixture laesst jeden Netzzugriff im Test
scheitern.

## Auslieferung

```powershell
.\packaging\build.ps1
```

Gebaut werden zwei ausfuehrbare Dateien aus derselben Analyse:
`wineventai.exe` (Konsole) und `wineventai-gui.exe` (ohne Konsolenfenster).
Sie teilen sich die Bibliotheken, kosten also keinen zweiten Satz DLLs. Ist
PySide6 beim Bauen nicht installiert, entsteht nur die Konsolenfassung.

PyInstaller **one-dir**, nicht one-file: One-file entpackt bei jedem Start nach
`%TEMP%` und sieht fuer EDR nach Packer-Verhalten aus - fuer ein Werkzeug, das
Sicherheitsprotokolle liest, die denkbar schlechteste Signatur.

Ohne Code-Signing-Zertifikat bleibt SmartScreen. Verteilung deshalb ueber
internen Share oder Softwareverteilung, mit dokumentiertem SHA-256 (den
`build.ps1` am Ende ausgibt).

## Nicht-Ziele der Version 1

Keine automatische Reparatur. Kein Minidump-Parser. Kein Agent, keine
Flottenverwaltung. Keine Live-Ueberwachung. Keine Cloud. Kein Machine Learning
ausser dem Sprachmodell.
