"""WinEventAI - lokales Diagnosewerkzeug fuer Windows-Ereignisprotokolle.

Die Pipeline ist strikt geschichtet: Collector -> Normalizer -> Enricher ->
Rule-Engine -> AI-Layer -> Reporter. Die Grenze zwischen Erhebung und Auswertung
ist das Laufverzeichnis (siehe ``collect.rundir``); alles ab dem Normalizer liest
ausschliesslich von dort.
"""

__version__ = "1.3.0"
