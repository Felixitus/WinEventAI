# Weiterarbeit mit OpenCode und einem Qwen-Modell

## Einrichtung

```bash
unzip wineventai-1.2.0-handover.zip
cd winevent-ai
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest -q        # muss 241 passed melden
ruff check src/ tests/     # muss sauber sein
opencode
```

OpenCode liest `AGENTS.md` im Projektwurzelverzeichnis von selbst ein. Das ist
der Arbeitsvertrag; mehr musst du nicht vorgeben.

`opencode.json` im Projektordner, falls du das Modell festnageln willst:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "model": "ollama/qwen2.5-coder:32b",
  "provider": {
    "ollama": {
      "npm": "@ai-sdk/openai-compatible",
      "options": { "baseURL": "http://localhost:11434/v1" },
      "models": { "qwen2.5-coder:32b": {} }
    }
  }
}
```

## Modellwahl

Zwei verschiedene Modelle, nicht verwechseln:

- **Das Modell, das am Code arbeitet** (OpenCode): nimm die groesste
  Coder-Variante, die auf deine Hardware passt. `qwen2.5-coder:32b` ab 24 GB
  VRAM, `qwen2.5-coder:14b` ab 12 GB, `:7b` nur fuer kleine Aenderungen.
- **Das Modell, das WinEventAI zur Laufzeit benutzt** (`ai.model` in der
  Konfiguration, Default `qwen2.5:14b-instruct`): das ist eine offene Frage,
  siehe `HANDOVER.md` Punkt 9.5. Der Abnahmetest `kb bench` ist spezifiziert,
  aber nicht gebaut.

## Erste Aufgabe fuer das Modell

Nimm einen Punkt aus `HANDOVER.md` Abschnitt 9 und nur einen. Vorschlag nach
Nutzen pro Aufwand:

1. **`kb bench` bauen** (Punkt 5). Reiner Python-Code, kein Windows noetig,
   gut testbar, und erst danach laesst sich die Modellwahl begruenden statt
   raten.
2. **Zeitsynchronisierungs-Sonde** (Punkt 6) als vierte Sonde. `probes/time.py`
   plus `probe_time.ps1`, Muster eins zu eins von `probes/services.py`
   abschauen. Haengt an W32Time 36/47.
3. Alles andere braucht eine echte Windows-Maschine und laesst sich nicht
   vorab erledigen.

## Prompt zum Einstieg

> Lies AGENTS.md und HANDOVER.md vollstaendig. Baue danach <Aufgabe>.
> Halte dich an die zehn Regeln in AGENTS.md Abschnitt 7 und an die
> Sprachkonvention in Abschnitt 4: Bezeichner englisch, Kommentare deutsch,
> keine Umlaute im Quelltext. Lege zuerst die Datei an, dann die Tests, dann
> halte an und zeig mir beides. Wenn dir etwas an der Aufgabe technisch
> fragwuerdig vorkommt, sag es, statt es umzusetzen.

## Was ein kleineres Modell erfahrungsgemaess falsch macht

Pruefe diese Punkte bei jedem Vorschlag nach — sie fallen einem schwaecheren
Modell regelmaessig herunter:

- **Umlaute im Quelltext.** Kommt fast immer zurueck. `ae oe ue ss`.
- **`ConvertTo-Json` auf die ganze Pipeline** statt je Zeile.
- **Lookup ueber die Event-ID allein** statt `(provider, event_id)`.
- **Englische Kommentare** oder englische Berichtstexte.
- **`# TODO: implementieren`** statt fertigem Code.
- **Lokalisierte Texte als Matching-Grundlage** (`"Der Dienst wurde..."`).
- **Entlastende Formulierungen bei nicht erfolgter Messung** — "alles in
  Ordnung" statt "nicht messbar".
- **Netzzugriff in Tests.** `tests/conftest.py` blockiert Sockets; wenn ein
  neuer Test `NetworkAccessInTest` wirft, ist der Test falsch, nicht die
  Fixture.
