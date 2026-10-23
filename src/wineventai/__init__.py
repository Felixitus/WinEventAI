"""WinEventAI - local diagnostic tool for Windows event logs.

The pipeline is strictly layered: collector -> normalizer -> enricher ->
rule engine -> AI layer -> reporter. The boundary between collection and
analysis is the run directory (see ``collect.rundir``); everything from the
normalizer onward reads exclusively from there.
"""

__version__ = "2.2.0"
