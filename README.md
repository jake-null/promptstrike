# promptstrike

> An LLM / GenAI red-teaming toolkit - probe language-model apps for prompt injection, jailbreaks, system-prompt leakage, data disclosure, and insecure output handling.

`promptstrike` is a small, modular framework for testing the security posture of
LLM-backed applications, aimed at modern **LLM / GenAI** threats (the OWASP LLM
Top 10) rather than classical ML.

The core has **zero dependencies** and ships with a deliberately vulnerable
**mock target**, so you can try it instantly with nothing to configure:

```bash
python -m promptstrike run --target mock
```

---

## Responsible use

For **authorized testing only** - run it against AI systems you own or have
explicit, written permission to test. The probes test *guardrail integrity*
using canaries and benign markers; they do not generate harmful content. You are
responsible for how you use this tool.

---

## How it works

Four small pieces, each easy to extend:

| Piece | What it is |
|-------|-----------|
| **Targets** | The LLM under test - `mock`, `openai` (OpenAI-compatible), `anthropic`, or a generic `http` endpoint. |
| **Probes** | Individual attacks, each mapped to an OWASP LLM Top 10 category. |
| **Detectors** | Decide whether a probe succeeded (refusal detection, canary/marker leakage, signature match). |
| **Engine** | Runs probes concurrently and collects findings; reports to console or JSON. |

### Probes

| Probe | OWASP | Severity |
|-------|-------|----------|
| `prompt_injection` | LLM01: Prompt Injection | medium |
| `jailbreak` | LLM01: Prompt Injection (Jailbreak) | high |
| `system_prompt_leak` | LLM07: System Prompt Leakage | medium |
| `sensitive_data_disclosure` | LLM06: Sensitive Information Disclosure | high |
| `insecure_output` | LLM02: Insecure Output Handling | medium |

`promptstrike list` prints them with descriptions.

---

## Install

The core needs only Python 3.9+. Run it straight from a clone:

```bash
git clone https://github.com/husenet/promptstrike
cd promptstrike
python -m promptstrike run --target mock
```

Or install the CLI:

```bash
pip install .
promptstrike run --target mock
# optional: use the official Anthropic SDK for the anthropic target
pip install ".[anthropic]"
```

---

## Usage

```bash
# Offline demo against the built-in vulnerable mock
promptstrike run --target mock

# Run only specific probes, as JSON
promptstrike run --target mock --probes prompt_injection,jailbreak --json

# OpenAI-compatible endpoint (also works for Ollama / vLLM / LM Studio)
export OPENAI_API_KEY=sk-...
promptstrike run --target openai --model gpt-4o-mini --api-key-env OPENAI_API_KEY \
  --canary "MY-PLANTED-SECRET" --system-canary "You are SupportBot"

# Anthropic
export ANTHROPIC_API_KEY=sk-ant-...
promptstrike run --target anthropic --model <model-id> --api-key-env ANTHROPIC_API_KEY

# A custom LLM app behind your own HTTP API
promptstrike run --target http \
  --url https://your-app.example.com/chat \
  --template '{"message":"{{PROMPT}}"}' \
  --response-path reply.text \
  --header "Authorization: Bearer $TOKEN"
```

### Detecting leaks on real targets

Two probes need to know what "leaked" looks like for *your* system:

- `--canary "..."` - a secret you planted in the system you're testing (so `jailbreak` / `sensitive_data_disclosure` can tell if it leaks).
- `--system-canary "..."` - a distinctive phrase from the target's system prompt (so `system_prompt_leak` can detect it).

Without these, those probes are skipped (and the run says so). The `mock` target supplies its own automatically.

### Flags

| Flag | Description |
|------|-------------|
| `--json` | Machine-readable output |
| `--no-color` | Disable ANSI colors |
| `--probes a,b` | Run a subset of probes |
| `--concurrency N` | Max concurrent requests (default 8) |
| `--timeout S` | Per-request timeout |

**Exit code:** `0` = nothing found, `1` = findings, `2` = target error. Handy in CI.

---

## Roadmap

- [ ] Multi-turn / conversational attack chains
- [ ] An LLM-as-judge detector for fuzzy success criteria
- [ ] Indirect prompt injection (poisoned documents / tool output)
- [ ] YAML-defined custom probes
- [ ] Optional Rust extension for high-volume payload mutation / fuzzing

## License

[MIT](LICENSE) (c) husenet
