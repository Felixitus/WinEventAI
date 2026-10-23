# AGENTS.md - WinEventAI

This file is the working contract for every AI model that continues building
this project. Read it completely before you touch the first file.
Detailed state, rationale and open items: `HANDOVER.md`.

---

## 1. Role and way of working

You are a senior software architect, not a code generator. Concretely:

- **Object.** If a requirement is technically questionable, say so and give
  the reason instead of implementing it. That is explicitly wanted.
- **Invent nothing.** If you do not know something for sure - whether a cmdlet
  exists on Server 2019, whether a field is localized - write down that it is
  unconfirmed. Plausible-sounding inventions are the most expensive error in a
  diagnostic tool.
- **Complete code.** No `# TODO: implement`, no omissions, no `...`
  placeholders.
- **Module by module.** One module with its tests, then stop and present it.
  Not eight files at once.
- **Every decision gets its reason.** The docstrings in this project do not
  explain *what* the code does but *why it is built this way and not
  otherwise*. Keep that up - it is the actual value of the code base.

## 2. What the program is

Local Windows diagnostic tool. Reads event logs and further system sources,
condenses them technically, triages them by rules and then optionally lets a
**local** language model (Ollama) formulate cause hypotheses, a risk
assessment and recommendations.

**Ollama is optional.** Without it every command works and every report is
complete - it is built from the rule engine. Never make a code path depend on
the model being present.

Target group: 1st/2nd level support and security staff who can read event ids
but do not have 40 minutes per case.

## 3. Hard constraints - not negotiable

| Rule | Meaning |
|---|---|
| Python 3.11+ | Windows 10/11, Server 2019/2022 |
| Collection via PowerShell | `Get-WinEvent` with FilterHashtable/XPath, as subprocess, NDJSON output |
| Language model local and optional | Ollama HTTP API at `http://localhost:11434`; without it: rules only |
| **No cloud call** | except with explicit opt-in `ai.allow_cloud: true` in the configuration file - this also covers cloud models a local Ollama forwards (`*:cloud`) |
| **Read-only** | The tool repairs NOTHING. A fix only appears as a suggestion: command, expected effect, risk, rollback |
| **Fully offline** | except the one-time model download |
| No paid services, no telemetry | also applies to probes: no speed test against an internet service |
| Configuration in YAML | no tuning knob in the code |

**Non-goals v2:** no automatic repair, no minidump parser, no agent/fleet
management, no live monitoring, no cloud, no machine learning apart from the
language model.

## 4. Language convention

- **Everything in English** since 2.0: identifiers, comments, docstrings,
  user-visible texts, reports, prompts, documentation.
- **No umlauts or other non-ASCII in source code.** Reason: mixed encodings
  between PowerShell, console and file.
- **Exceptions, deliberately German:** `auditpol` subcategory names in
  `security/audit_policy.py` (they are what a German Windows prints) and the
  Windows messages in `tests/fixtures/ndjson` (they prove nothing depends on
  localized text).
- Compatibility with 1.x data (German status values, rule fields, KB columns)
  is kept by `_missing_` on the enums, `model_validator(mode="before")` on
  `RuleDefinition`/`KbEntry` and `kb.store._migrate_legacy_schema`. Do not
  remove these without a major version.

## 5. Commands

```bash
pip install -e ".[dev]"      # development (PySide6 included)
pip install -e ".[gui]"      # user interface only
python -m pytest -q          # 326 tests, all must be green
ruff check src/ tests/       # must be clean
```

On Windows: `install.ps1` in the project folder (removes an existing
installation first - otherwise pip keeps pointing to the old folder).
Release: `packaging\build.ps1` (tests, linter, PyInstaller one-dir, licences,
ZIP, Setup.exe via Inno Setup, SHA256SUMS.txt).

CLI: `collect | analyze | run | report | evidence | doctor | gui | ai bench |
kb {list,search,stats,unknown,reseed} | config {init,path,show}`

## 6. Module map

```
src/wineventai/
  collect/     Collection. PowerShell scripts in collect/scripts/*.ps1,
               including the error sweep (sweep.py, sweep_errors.ps1)
  normalize/   EventRecord schema, masking for the fingerprint
  enrich/      Dedup, burst, boot sessions, correlation, retention
  rules/       YAML rules + deterministic engine (6 files, 31 rules)
  kb/          Knowledge base (SQLite), unknown_ids.csv
  ai/          Ollama client, cloud guard, bundles, redaction, evidence check,
               model acceptance test (bench.py, bench_cases.yaml)
  probes/      Context probes (network, service, storage, time) + scripts/*.ps1
  report/      HTML (Jinja2) / Markdown / JSON from ONE model; compare.py
               compares with the previous run of the same machine
  security/    Security mode, audit policy, blind spots
  gui/         PySide6, contains NO diagnostic logic; elevation.py restarts
               via UAC
  analyze.py   The pipeline wiring
  cli.py       Typer
  resources.py The only place that knows PyInstaller paths and the data
               folder (%LOCALAPPDATA%\WinEventAI - never ProgramData)
```

Order of the pipeline:
`collect -> normalize -> enrich -> rules -> kb -> ai -> probes -> report`

## 7. The ten rules you must not break

1. **The run directory is the pipeline boundary.** The collector writes
   `raw/*.ndjson`; everything after it reads exclusively from there. Never let
   a module from `normalize` onward access Windows directly.
2. **Never `ConvertTo-Json` on the whole pipeline.** Always
   `ForEach-Object { ... | ConvertTo-Json -Compress -Depth 4 }`, one line per
   record. Otherwise PowerShell first builds the whole array in memory.
3. **Never match on localized text.** Windows translates `LevelDisplayName`,
   `TaskDisplayName`, error messages. Use numeric values, .NET **type names**
   (`$_.Exception.GetType().FullName`) and `FullyQualifiedErrorId`. Exception
   only where the script does not run at all (`status_from_stderr`), and then
   against language-neutral identifiers.
4. **"No findings" and "not collected" must never look alike.**
   `SourceStatus` has 10 states; `EMPTY`, `NOT_AVAILABLE`, `NOT_LOGGED`,
   `NO_PERMISSION`, `TIMED_OUT`, `TRUNCATED`, `BLOCKED`, `FAILED` are strictly
   separate. A script without a closing status line is `FAILED`, never
   `EMPTY`. The coverage table comes BEFORE the findings in the report.
5. **The time window is never shrunk silently.** If too much data arrives,
   the number of *retained* raw records is capped
   (`max_retained_per_channel`), never the period. Above 5 million records:
   hard abort with a message. Aggregates and counters are untouched by
   retention.
6. **The fingerprint hangs on the property vector, not the message text.**
   `provider + event_id + event_version + hash(masked property vector)`.
   Message text only as a fallback, and that is marked in the fingerprint
   (`p…` vs. `m…`).
7. **Event ids are only unique per provider.** Every key is
   `(provider, event_id)`. The rule validator rejects rules without
   `provider`. Never build a lookup on the id alone.
8. **Nothing goes into the prompt that the evidence check cannot verify.**
   Model statements carry structured `evidence` fields; a statement without
   cover is rejected individually, not the whole answer. That is why probe
   results do NOT go into the bundle.
9. **An empty field is an invitation to misinterpretation.** Missing
   measurements, disabled probes, missing KB meaning, a missing language model
   get a visible note - never nothing.
10. **The GUI contains no diagnostic logic.** It calls the same functions as
    the CLI. Otherwise one ends up debugging two tools.

## 8. Traps that have already snapped shut here

- **YAML:** a list entry containing `": "` is parsed as a mapping.
  `- With several machines: check.` must be quoted.
- **Lists into PowerShell scripts:** pass ONE `|`-separated string
  (`shell.join_list_arg`). `-EventIds "1,2"` into `[int[]]` fails via `-File`
  under PS 5.1, `-Role a,b` arrives as one element.
- **Burst detection:** the baseline is the density over the **whole** analysis
  window, not the median of occupied hours. Otherwise an outlier hides behind
  itself.
- **Retention:** noise rules must not count as priority 1, otherwise 1400×
  DCOM 10016 fills the quota.
- **`urllib` honours `HTTP_PROXY` for localhost too.** The Ollama client
  therefore installs `ProxyHandler({})` for local addresses.
- **`/api/show` with a missing model returns 404** - that is "model missing",
  not "Ollama unreachable". Separated in `OllamaStatus`.
- **A model under `localhost` can still be a cloud model.** `/api/tags`
  entries with `remote_host` or a `:cloud` name are refused without
  `allow_cloud`.
- **PyInstaller: one-dir, not one-file.** One-file unpacks to `%TEMP%` on
  every start and looks like packer behavior to EDR. `__main__.py` must use
  absolute imports - PyInstaller runs it as a script.
- **PowerShell call via `-File`, never `-EncodedCommand`.** Base64 PowerShell
  is one of the most conspicuous EDR signatures - for a tool that reads
  security logs the worst possible image.
- **PS 5.1 vs. 7:** `Test-Connection` returns `Win32_PingStatus.ResponseTime`
  resp. `PingStatus.Latency`. Hence `System.Net.NetworkInformation.Ping`
  directly. Same class of trap with DateTime serialization - format in the
  script itself.
- **`Get-WinEvent -ListLog * -ErrorAction Stop`** aborts without admin rights
  at the first unreadable channel. Check names individually.
- **Qt rich text** is HTML 4: no flexbox, no grid, no external CSS,
  `border-left` outside tables is not painted.
- **`QStyledItemDelegate.paint`** refills the text itself; painting the text
  yourself afterwards draws it twice.
- **PySide6 (LGPL), not PyQt (GPL).** For internal distribution that is the
  difference between uncritical and licence-bound.

## 9. Test rules

- Tests run **without Windows and without network**. `tests/conftest.py`
  blocks sockets via an autouse fixture (`NetworkAccessInTest`).
- Every layer has a pure evaluation function as test boundary:
  `collect.shell.read_ndjson`, `collect.sweep.parse_sweep` and
  `probes.shell.read_payloads` only know a line iterator and nothing of
  processes.
- **Test names are English sentences** and describe the statement, not the
  function: `test_burst_detects_concentration_in_one_single_hour`.
- Imports in tests: `from helpers import ...`, not `from .conftest import`.
- What can only be proven on real Windows - the `.ps1` files - is not tested
  and is listed as an open item in `HANDOVER.md`.
