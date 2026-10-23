# WinEventAI - Handover

**Version 2.1.0 · 286 tests green · ruff clean · as of 23 Oct 2026**

This file is the complete state of knowledge for further development outside
the original session. The working contract is in `AGENTS.md`; this file holds
scope, rationale and open items.

---

## 1. Scope

~12,700 lines of Python in 76 modules, 9 PowerShell collection/probe scripts,
30 rules in 6 YAML files, 286 tests in 16 files.

| Package | Lines | Task |
|---|---:|---|
| `collect/` | 2384 | Collection, PowerShell, run directory, error sweep |
| `gui/` | 2178 | PySide6 user interface |
| `probes/` | 1507 | Context probes |
| `ai/` | ~2000 | Ollama, bundles, redaction, evidence check, cloud guard, model bench |
| `report/` | 715 | HTML/Markdown/JSON |
| `enrich/` | 704 | Dedup, burst, boot, correlation, retention |
| `rules/` | 615 | Rule schema, loader, engine |
| `kb/` | 464 | Knowledge base incl. legacy migration |
| `config/` | 441 | Model, layering, `config init` |
| `security/` | 412 | Security mode |
| `normalize/` | 371 | Event schema, masking |
| `evidence/` | 206 | Evidence bundle |
| `cli.py` | 764 | Typer |
| `analyze.py` | 224 | Pipeline wiring |

Tests per file: gui 32, probes 29, collect_sweep 27, ai_bench 28, ai 22, collect_shell 19,
rules 18, evidence/config 15, ollama_status 15, enrich 14, config_init 13,
report 13, kb_stats 9, security 8, end_to_end 7, normalize 6.

## 2. Version 2.0: what changed and why

2.0 is a **breaking** release: code, comments, user-visible texts, CLI output,
reports, prompts and documentation are English. Identifiers were English
before; now everything is.

Breaking surfaces and how compatibility is kept:

| Surface | 1.x | 2.0 | Compatibility |
|---|---|---|---|
| Status values | `keine treffer`, `kanal fehlt`, ... | `no hits`, `not available`, ... | `_missing_` on `SourceStatus`, `Severity`, `Classification`, `KbConfidence` accepts the German values (old `sources.json`, old overlays) |
| Rule fields | `bedeutung`, `typische_ursachen`, `empfohlene_pruefungen` | `meaning`, `typical_causes`, `recommended_checks` | `model_validator(mode="before")` maps the old names on `RuleDefinition` and `KbEntry` |
| KB database | German columns, `sicher/unsicher/leer` | `meaning`, `source_url`, `checked_on`, ...; `verified/unverified/empty` | `kb.store._migrate_legacy_schema` renames columns in place, maps confidence, rebuilds `kb_fts` and reloads the seed; user entries are kept |
| Report files | `bericht.html/md/json` | `report.html/md/json` | none - a new run writes the new names |
| JSON report keys, manifest keys, probe payload keys | German | English | none - consumers have to be adapted |
| Prompts | `*.de.txt` | `explainer.en.txt`, `correlator.en.txt` | none |
| Rule ids | `scm-dienst-beendet`, ... | `scm-service-terminated`, ... | none - an overlay with an old id adds a rule instead of overriding |

Deliberately still German:

- `auditpol` subcategory names in `security/audit_policy.py`: they are what a
  German Windows prints (known weakness, see open items).
- NDJSON test fixtures: real German Windows messages prove that nothing
  depends on localized text.

### 2.1 Works without Ollama

The language model is optional end to end:

- `run`/`analyze` with Ollama unreachable, model missing or `--no-ai`: exit 0,
  complete report from the rule engine, note
  `ai.pipeline.RULES_ONLY_NOTE` in the report.
- `doctor` reports an unreachable Ollama as a yellow note, not as an error.
- The GUI checkbox reads *Use language model (not available - rules only)*;
  the status bar says *No Ollama - rule engine only*.
- Verified on Windows 11 26200 with the Ollama service stopped, both with the
  Python package and with the built `wineventai.exe`.

### 2.2 Cloud guard

Ollama can list remote models under `localhost` (e.g. `glm-5.2:cloud`); a
chat with them sends the bundle to a cloud service although the URL is local.
`ai.client.is_remote_model_entry` recognizes `/api/tags` entries with
`remote_host`/`remote_model` or a name ending in `:cloud`/`-cloud`. Without
`ai.allow_cloud: true` such a model counts as unusable in `status()`, and
`chat_json` refuses it again (`CloudCallBlockedError`) - two checks, because
the status may be stale by the time of the call.

## 3. Dependencies

`pydantic>=2.6`, `PyYAML>=6.0`, `Jinja2>=3.1`, `typer>=0.12`.
Optional `[gui]`: `PySide6>=6.6`. Dev additionally `pytest`, `ruff`,
`pyinstaller`.

The Ollama client deliberately uses `urllib` from the standard library rather
than `requests` - one dependency less in the PyInstaller bundle, and proxy
handling has to be controlled by hand anyway.

`tiktoken` was explicitly rejected: it downloads an encoding from the network
on first use and would break "fully offline". The token estimate calibrates
itself against `prompt_eval_count` from the Ollama response instead.

## 4. Pipeline

```
collect ──► raw/*.ndjson ──► normalize ──► enrich ──► rules ──► kb
                                                                 │
                        report ◄── probes ◄── ai ◄───────────────┘
```

### 4.1 collect

- One PowerShell script per source type, called via `-File`.
  `get_events.ps1` is the streaming collector: `ForEach-Object` +
  `ConvertTo-Json -Compress -Depth 4`, one line per record. The script formats
  timestamps itself as `yyyy-MM-ddTHH:mm:ss.fffffffZ` - PowerShell's own
  DateTime serialization differs between 5.1 and 7.
- The last line is always `{"__status": {...}}` with `records`, `truncated`,
  `exception` as .NET **type name** and `error_id` (FullyQualifiedErrorId).
- Lists are passed as ONE `|`-separated string (`shell.LIST_SEPARATOR`,
  `join_list_arg`). Comma lists into `[int[]]`/`[string[]]` fail via `-File`
  under PS 5.1.
- A missing status line means `FAILED`, never `EMPTY`
  (`NdjsonResult.completed`).
- `collect/shell.py` separates `read_ndjson` (knows only lines) from
  `run_script` (knows processes). That is the test boundary.
- `SourceResult` carries `covered_from_utc` / `covered_to_utc` and
  `coverage_gap` per source.
- Limits: 120 s wall clock per channel, `max_retained_per_channel` (default
  200,000) on **retained** raw data, hard abort above 5 million records.
- **Error sweep** (`collect/sweep.py`, `sweep_errors.ps1`): every active
  Administrative/Operational channel apart from the configured ones, filtered
  server-side to level 1/2. ONE PowerShell process for all channels, because
  hundreds of process starts would dominate the run time. So that the shared
  time limit (600 s) swallows nothing, the script first writes
  `{"__plan": ...}` and a `{"__channel": ...}` line after each channel.
  Channels in the plan without a closing line are "timed out", never "no
  hits". Channels without hits are only counted in the summary row
  `sweep:summary`; every channel with hits or incomplete collection gets a row
  `sweep:<channel>`. With `.evtx` input no sweep runs (the source machine's
  channel list is missing) - status "not available" with a note.

### 4.2 normalize

`EventRecord` with numeric `level`/`task`/`opcode`/`keywords`, `properties` as
a positional vector, `event_data` only when XML was requested. `masking.py`
replaces GUID, SID, MAC, IP, UNC, path, hex and numbers - in this order,
specific before general, numbers last.

### 4.3 enrich

One single pass over the descending stream merged with
`heapq.merge(..., reverse=True)` does fingerprint, counters, hour histogram,
boot session, context window and retention. Memory therefore depends on the
number of distinct fingerprints, not on the number of events.

Because the stream runs descending, "context before the crash" technically
becomes forward buffering.

Retention: priority reservoir P1 rule hits, P2 context, P3 level ≤ 2 at 60 %,
P4 reservoir sampling with a fixed seed.

### 4.4 rules

30 rules in `core_application`, `core_system`, `hardware`, `noise`,
`security`, `storage`. Overlay from `%PROGRAMDATA%\WinEventAI\rules`.

Rule ids:
`application-error-1000 application-hang-1002 wer-report minidump-present
kernel-power-41 eventlog-6008 bugcheck-1001 scm-service-terminated
scm-service-start-failed eventlog-boot-marker whea-corrected whea-uncorrected
kernel-pnp-219 windowsupdate-failure dcom-10016 dhcp-warning-1003
perflib-1008 dns-client-1014 sec-log-cleared sec-log-cleared-104
sec-audit-policy-changed sec-logon-failure-series sec-remote-logon
sec-account-and-group sec-new-service sec-powershell-scriptblock
sec-process-creation disk-io-error storahci-reset-129
ntfs-filesystem-corruption`

The schema validator rejects a rule without `provider` and requires a
`locale:` field with `message_regex`.

### 4.5 kb

SQLite. The key is `provider` + `event_id`, not the id alone. `confidence`
has a **consequence in the code**: only `verified` is embedded in the prompt;
everything else appears in the report as "no verified meaning on record".
Uncovered pairs land in `unknown_ids.csv` as a work list. The KB links
sources instead of copying foreign text.

### 4.6 ai

- Structured output: JSON schema in Ollama's `format` field.
- Every statement carries `evidence` as structured fields (provider, id,
  timestamp). `verify.py` checks each statement individually against the
  input and rejects only the uncovered ones - not the whole answer.
- Redaction with stable pseudonyms (`USER_1`, `HOST_1`, ...). The mapping
  table lies next to the report and does **not** go along
  (`--report-redacted`).
- `num_ctx` is capped against `/api/show`.
- `OllamaStatus` separates `reachable`, `model_present` and `remote_model`.
- Local addresses bypass the proxy from the environment.

### 4.7 probes

| Probe | Hangs on | Measures |
|---|---|---|
| `network` | DNS Client 1014, Dhcp-Client 1003, Tcpip 4227/4231, NetBT 4321 | Ping to DNS/gateway/DHCP **plus a real name query** |
| `service` | SCM 7000/7009/7024/7031/7034/7043 | State, start type, account, exit code |
| `storage` | disk 7/11/51/52/153, storahci/stornvme/iaStorA 129, Ntfs 55/98/137, volsnap 25, volmgr 46 | Health, reliability counters, SMART, free space |

Files: `base.py` (terms), `shell.py` (call + NDJSON), `network.py`,
`services.py`, `storage.py`, `runner.py`,
`scripts/probe_{network,services,storage}.ps1`.

Data model:

```python
class ProbeStatus(StrEnum):
    OK = "unremarkable";   WARN = "conspicuous"
    FAILED = "failed";     NOT_APPLICABLE = "not applicable"
    NO_PERMISSION = "no permission"; TIMED_OUT = "timed out"
    DISABLED = "disabled"; UNAVAILABLE = "not measurable"

class ProbeBearing(StrEnum):
    SUPPORTS = "supports the finding"
    WEAKENS  = "speaks against it"
    INCONCLUSIVE = "says nothing about it"
```

`NO_MEASUREMENT` is the set of states in which **nothing was measured** -
`ProbeResult.measured` derives from it. "unremarkable" is a measurement;
everything else is the absence of a measurement and must never look like an
all-clear in the report.

Every probe implements `target_for(finding) -> str | None` and
`run(targets: dict[str, list[Finding]]) -> list[ProbeResult]`. The runner
collects all targets and starts each probe **exactly once**.

### 4.8 report

`ReportModel` is the single source for HTML, Markdown and JSON - the three
arise from the model, not from each other. The HTML is one single file
without external resources: no CDN, no downloaded font. An HTML file that
reaches into the network when opened is the wrong signal on an examined
machine.

### 4.9 gui

PySide6 rather than FastAPI+HTML (client's decision). The run happens in a
`QThread`. No QtWebEngine (~150 MB Chromium); the HTML report opens in the
system browser. `theme.py` shares the palette with the report,
`delegates.py` paints severity and source status as chips - colour alone
would be the only distinction otherwise, and about eight percent of men
cannot tell red from orange.

### 4.10 ai bench (2.1.0)

`ai/bench.py` + `ai/bench_cases.yaml`. Three fixed scenarios (unclean restart
after disk retries, crash series of a user application, print spooler killed
by a driver) go through enrich, rules, redaction, `AiLayer` and the evidence
check unchanged - the bench measures what the report will show.

Gates in this order, thresholds in `ai.bench`: context length the model
supports (`/api/show`; unknown fails), schema-valid answer for every finding,
rejected share of statements (answers without any statement fail too - they
would evade the check), English by a stop-word heuristic. Speed and GPU offload
(`/api/ps`, `size_vram / size`) are reported, not judged.

"not tested" (missing model, cloud model without opt-in, embedding model by
`capabilities`) is kept apart from "failed". Recommendation: fewest
rejections, then speed - deliberately not parameter count. Nothing is changed;
the JSON result with every answer goes to `%PROGRAMDATA%\WinEventAIench\`.

Recommendation: among passed models, every model whose rejected share is
within `rejection_tolerance` (0.1) of the best counts as equally reliable; the
fastest of them wins. A strict "fewest rejections first" ranked noise.

**First live run** (23 Oct 2026, RX 7900 XTX 24 GB, Ollama, 3 scenarios,
8 findings, `num_ctx` 16384):

| Model | Size | Status | Statements | Rejected | Time |
|---|---|---|---:|---:|---:|
| qwen3-coder:30b | 30.5B Q4_K_M | passed | 16 | 1 (6 %) | 46 s |
| deepseek-r1:8b | 8.2B Q4_K_M | passed | 17 | 0 | 393 s |
| gemma4:26b | 25.8B Q4_K_M | failed: schema violation for Kernel-Power 41 twice | 19 | 0 | 569 s |
| glm-5.2:cloud | - | not tested (cloud, no opt-in) | - | - | - |

All three fit 100 % into video memory. Reading the answers: qwen3-coder names
the printer driver as the cause with "high" confidence and gives concrete
checks; deepseek-r1 stays vague ("might be a system error", "unclear").
The one qwen3-coder rejection was "verify that Event ID 6006 is not missing" -
a strict but correct rejection: the id is not in the bundle. Not yet
measured: the original default `qwen2.5:14b-instruct` (not installed here).

Found by the first live run: the calibration warning "token estimate deviates
clearly" fired on every call, because Ollama's `prompt_eval_count` includes the
system prompt and the estimate did not. Fixed in `pipeline._explain`.

## 5. Run directory

```
%PROGRAMDATA%\WinEventAI\runs\2026-09-10T14-22-03Z_WS-4711\
  run.json                 time window, host, account, tool version, TZ offset
  sources.json             per source: status, covered period, figures
  raw\*.ndjson             one record per line, descending by time
  derived\groups.json      fingerprint groups
  derived\findings.json    rule hits (including "probes")
  derived\bundles\*.json   exactly what went to the model (after redaction)
  derived\ai\*.json        exactly what came back, plus verification result
  report\report.html|md|json
  unknown_ids.csv          work list for the knowledge base
  applog.jsonl             own application log, separate from the material
```

## 6. Configuration

Layering: bundled defaults → `%PROGRAMDATA%\WinEventAI\wineventai.yaml` →
`--config` → CLI switches. Lists are **replaced**, not merged.

`config init` writes the file **completely commented out**. Only what someone
uncomments takes effect. Reason: a file nobody created is read by nobody - but
it still freezes values.

**Documented trap in the file header:** whoever uncomments only `#   days: 7`
without the parent key `collect:` ends up with a top-level `days`, and
pydantic rejects it. There is a dedicated test
(`test_a_forgotten_parent_key_fails_visibly`).

Sections: `collect` (including `error_sweep`), `enrich`, `rules`, `ai`,
`probes`, `report`, `log_level`.

`Microsoft-Windows-Kernel-Power/Operational` was removed from the default
channels: it does not exist on Windows 11, and Kernel-Power 41 is in System
anyway.

## 7. Delivery

- Development via pip, delivery via PyInstaller **one-dir**
  (`packaging/wineventai.spec`, `packaging/build.ps1`).
- Two EXEs from one analysis: `wineventai.exe` (`console=True`) and
  `wineventai-gui.exe` (`console=False`). `__main__.wants_gui` picks the mode
  by the EXE name. QtWebEngine, QML, Quick, Charts are excluded. `upx=False`.
- No code-signing certificate. Distribution via an internal share with the
  documented SHA-256.
- `resources.py` is the only place that knows `_MEIPASS`, the EXE directory
  and `importlib.resources`.

## 8. Evidence

ZIP with the **original `.evtx`**. The hash is taken over the original, not
over the extract. The bundle is **not redacted** - it is evidence; redaction
applies exclusively to the path to the language model, and the mapping table
is not exported.

## 9. Fixed bugs (with the lesson behind them)

| Version | Bug | Lesson |
|---|---|---|
| - | Burst never fired on concentrated events: median of occupied hours = 64 when all 64 events lie in one hour | Baseline over the whole window, not over occupied hours |
| - | 1400× DCOM 10016 filled the P1 quota | Noise rules do not count as rule hits |
| - | YAML list entry with `": "` became a mapping | Quote those entries |
| 1.0.1 | A missing model reported itself as "Ollama not reachable" | 404 from `/api/show` is not "unreachable"; `OllamaStatus` separates both |
| 1.0.1 | `urllib` used `HTTP_PROXY` for localhost too | `ProxyHandler({})` for local addresses |
| 1.0.2 | The user configuration never came into existence | `config init`, completely commented out |
| 1.1.0 | `GuiLogStream` attached the **process-wide** log to the signal of ONE worker; after its death every log call raised "Signal source has been deleted" | The stream catches `RuntimeError`, the worker detaches the global log in `finally` |
| 1.1.1 | `pip install "wineventai[gui]"` failed | Documentation error - the package is not on PyPI; `install.ps1` removes an existing installation first |
| 1.3.0 | System, Application and Setup reported "no hits, 0 read" on a real Windows 11. `-XmlForIds "1001,4624,..."` failed via `-File` on the `[int[]]` conversion, the script never ran, and zero lines without a status line counted as empty | Lists go as a `\|`-separated string; without a status line the source is `FAILED` with the FullyQualifiedErrorId from stderr - never `EMPTY` |
| 1.3.0 | The same for the probes: `-Role "dns,gateway"` arrived as ONE element | Same list convention |
| 1.3.0 | A missing channel appeared as "no hits" | Distinguished by the language-neutral FullyQualifiedErrorId: `NoMatchingEventsFound` = empty, `NoMatchingLogsFound` = channel missing (`base.ERROR_ID_STATUS`) |
| 1.3.0 | `doctor` reported present channels as missing: `-ListLog * -ErrorAction Stop` aborted without admin rights on the first unreadable channel | `list_channels.ps1` checks each configured name individually and separates missing / unreadable |
| 1.3.0 | Status chips labelled twice | `QStyledItemDelegate.paint` refills the text internally; the background is now painted directly via `drawControl` |
| 1.3.0 | The built EXE did not start: `__main__.py` imported relatively, but PyInstaller runs the file as a script without a package | Absolute imports, switch by EXE name (`wants_gui`); both EXEs started and checked on Windows 11 |
| 2.0.0 | A cloud model listed by the local Ollama would have received the bundle although `allow_cloud` was off | Cloud guard on `/api/tags` entries, checked in `status()` and again in `chat_json` |

## 10. Open items

**Needs real Windows:**

1. **The `.ps1` files are only partly proven.** Evaluation from
   `read_ndjson` / `read_payloads` / `parse_sweep` onward is fully tested, the
   scripts themselves are not.
   - `get_events.ps1`, `sweep_errors.ps1`, `list_channels.ps1`,
     `get_reliability.ps1` **ran on Windows 11 26200 / PS 5.1 without admin
     rights** (sweep: 146 channels, ~4,100 errors in 6 s). Unconfirmed: with
     admin rights, under PowerShell 7, on Server.
   - The three probe scripts (English payload keys since 2.0) **ran on the
     same machine**: network (gateway, DHCP, DNS plus name query), services
     (found/not found), storage (5 disks, volumes, SMART note). Unconfirmed:
     server systems, PowerShell 7.
   - Decision to review: unreadable channels do NOT make the sweep summary row
     incomplete, they only appear there as a number. Without admin rights the
     sweep would otherwise always be "incomplete" and the marking would lose
     its meaning. The script does not know the names of these channels.
   - Does `Win32_NetworkAdapterConfiguration.DHCPServer` reliably return a
     value on server systems?
   - Does `MSStorageDriver_FailurePredictStatus` exist outside Hyper-V?
   - Does `Resolve-DnsName -QuickTimeout` work as expected under PowerShell
     5.1?
2. **Objection E02:** are `Microsoft-Windows-WHEA-Logger` and `storahci`
   really only providers in the System channel and no channels of their own?
   `wineventai doctor` checks this - needs a real machine.
3. **Collector throughput unmeasured** on a real Security log, before deciding
   on `pywin32` as an alternative.
4. **Security without admin rights** also yields `NoMatchingEventsFound`; only
   the `requires_admin` precheck protects against a false "no hits".
   Unconfirmed for PowerShell 7 and Server.
5. **`audit_policy.py` parses localized `auditpol` output.** It works on
   German and English systems only. Better: query by subcategory GUID
   (`auditpol /get /subcategory:{GUID} /r`) and decode the console output with
   the OEM code page.

**Not built yet:**

6. ~~`ai bench`~~ - **built in 2.1.0**, see 4.10. Still open: the default
   `ai.model` should follow from a bench run on target hardware, not from this
   developer machine alone.
7. **Further probes**, but only by the same criterion (every probe has to
   explain or rule out a finding):
   - Domain controller for Netlogon 5719 - needs a reliable source for the DC
     address without `nltest`. Unsolved.
   - Time synchronization for W32Time 36/47 - plausible candidate.
8. **Unassessed error groups** from the sweep only get the original Windows
   message. A model description for them would need its own evidence rules.

## 11. Decisions deliberately NOT taken

- **No internet speed test.** It would break three promises at once: "works
  offline", "no telemetry" (the own IP would go to the provider) and
  "read-only" (it saturates the line and creates exactly the disturbance one
  is looking for on a disturbed machine).
- **No automatic shrinking of the time window for large data volumes.** The
  result would be silently incomplete, and someone reads "no findings" for a
  period that was never analyzed.
- **No probe results in the prompt.** They carry no event ids, so the evidence
  check cannot hold them against the input. Everything uncheckable in the
  bundle is an invitation to invent. That is why the probes run after the AI
  layer in `analyze_run` - structurally, not by convention.
- **No measurement on a foreign machine.** The runner compares `RunMeta.host`
  with the local name and measures nothing if they differ.
- **No `nltest`, no `fsutil dirty`, no self-test.** All either not read-only
  or not reliably available.
