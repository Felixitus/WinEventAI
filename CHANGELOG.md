# Changelog

All versions of WinEventAI. Rationale and lessons behind each fix are in
`HANDOVER.md`.

## 2.2.0 - 2026-10-23

- Program logo: `docs/logo.svg`, a reduced variant for 16/24 px
  (`docs/logo-small.svg`), generated into a multi-size ICO by
  `packaging/make_icons.py`.
- Both EXE files, the window and the taskbar carry the icon; the HTML report
  embeds the logo inline (still no external resources).
- Fix: console output no longer crashes when redirected to a file or pipe.
  Windows messages contain characters such as U+200E; `kb unknown` ended with
  a `UnicodeEncodeError`.

## 2.1.0 - 2026-10-23

- `wineventai ai bench`: acceptance test for the model choice. Fixed scenarios
  run through the real pipeline; gates for context length, schema-valid
  answers, rejected statements and English; thresholds in `ai.bench`.
- Recommendation with `rejection_tolerance`, so that one rejection more does
  not outweigh an eightfold speed difference.
- Fix: the token estimate includes the system prompt; the calibration warning
  fired on every call before.

## 2.0.0 - 2026-10-22

Breaking: everything in English - code, texts, reports, prompts, documentation.

- Works completely without Ollama: the report comes from the rule engine,
  `doctor` and the GUI show a note instead of an error.
- Cloud guard: models a local Ollama forwards to a cloud service are refused
  without `ai.allow_cloud`.
- Report files `report.html|md|json`, English status values, rule fields and
  JSON keys. German values, rule overlays and knowledge bases of 1.x are still
  read; the knowledge base is migrated in place.

## 1.3.0 - 2026-10-22

- Error sweep: every active Administrative/Operational channel, level 1/2.
- Fixes found on real Windows 11: list parameters into PowerShell, missing
  channels reported as "no hits", `doctor` reporting present channels as
  missing, EXE not starting.
