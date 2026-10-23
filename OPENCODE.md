# Continuing with OpenCode and a local model

## Setup

```bash
git clone https://github.com/Felixitus/WinEventAI.git
cd WinEventAI
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest -q        # must report 286 passed
ruff check src/ tests/     # must be clean
opencode
```

OpenCode reads `AGENTS.md` in the project root by itself. That is the working
contract; you do not need to specify more.

`opencode.json` in the project folder (ignored by git) if you want to pin the
model:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "model": "ollama/qwen3-coder:30b",
  "provider": {
    "ollama": {
      "npm": "@ai-sdk/openai-compatible",
      "options": { "baseURL": "http://localhost:11434/v1" },
      "models": { "qwen3-coder:30b": {} }
    }
  }
}
```

## Model choice

Two different models, do not mix them up:

- **The model that works on the code** (OpenCode): take the largest coder
  variant that fits your hardware. A 30B coder from 24 GB VRAM, a 14B coder
  from 12 GB, 7B only for small changes.
- **The model WinEventAI uses at run time** (`ai.model` in the configuration):
  optional - without it the report comes from the rule engine. Choose it with
  `wineventai ai bench`, not by size.

## First task for the model

Take one item from `HANDOVER.md` section 10 and only one. Suggestion by benefit
per effort:

1. **Time synchronization probe** (item 7) as a fourth probe. `probes/time.py`
   plus `probe_time.ps1`, copy the pattern one to one from
   `probes/services.py`. Hangs on W32Time 36/47.
2. Everything else needs a real Windows machine.

## Prompt to start

> Read AGENTS.md and HANDOVER.md completely. Then build <task>.
> Follow the ten rules in AGENTS.md section 7 and the language convention in
> section 4: everything in English, no non-ASCII characters in source code.
> Create the file first, then the tests, then stop and show me both. If
> something about the task seems technically questionable to you, say so
> instead of implementing it.

## What a smaller model tends to get wrong

Check these points with every proposal - a weaker model drops them
regularly:

- **`ConvertTo-Json` on the whole pipeline** instead of per line.
- **Comma lists into `[int[]]` script parameters** instead of one
  `|`-separated string.
- **Lookup by the event id alone** instead of `(provider, event_id)`.
- **`# TODO: implement`** instead of finished code.
- **Localized texts as matching basis** (`"The service terminated..."`).
- **Reassuring wording when nothing was measured** - "all fine" instead of
  "not measurable".
- **A code path that requires Ollama.** Every feature must work without it.
- **Network access in tests.** `tests/conftest.py` blocks sockets; if a new
  test raises `NetworkAccessInTest`, the test is wrong, not the fixture.
