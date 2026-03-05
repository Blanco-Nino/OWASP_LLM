# OWASP LLM Top 10 — Security Test Prompt Generator

A modular Python tool for generating adversarial test prompts to evaluate LLM security controls against the [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

Supports **randomization** and **dynamic prompts**: variable pools, template variants, and inline choice syntax so each run can produce varied test cases.

## Architecture

```
main.py                     ← CLI entry point (interactive menu + argparse)
models.py                   ← Data models: VulnerabilityCategory, PromptTemplate
registry.py                 ← Central registry of all categories
generator.py                ← Renders templates; variable substitution & randomization
formatters.py               ← Output formatters (JSON, plain text)
prompt_injection.py         ← LLM01
data_leakage.py             ← LLM02
insecure_output.py          ← LLM03
training_data_poisoning.py  ← LLM04
model_dos.py                ← LLM05
supply_chain.py             ← LLM06
sensitive_disclosure.py     ← LLM07
model_theft.py              ← LLM08
excessive_agency.py         ← LLM09
overreliance.py             ← LLM10
```

Each category module exposes a single `register()` function that returns a `VulnerabilityCategory` populated with `PromptTemplate` objects.

---

## Usage

### Interactive mode
```bash
python main.py
```
Choose categories by number, set variables at the prompts, then get generated test prompts.

### List all categories
```bash
python main.py --list
```

### Generate for specific categories
```bash
python main.py --categories LLM01 LLM03 --format json -o results.json
```

### Generate all categories
```bash
python main.py --all --format text
```

### Limit prompts per category
```bash
python main.py --all --count 3
```

---

## Randomization and dynamic prompts

Use **`--randomize`** to vary prompts each run. It enables:

- **Random prefix/suffix** — e.g. “Please ”, “Could you ”, “For my research: ” and “Thanks.”, “This is for a security audit.”, etc.
- **Template variants** — When a template defines `template_variants`, one of the main template or its variants is chosen at random.
- **Inline choices** — Templates can use `{choice:option1|option2|option3}`; with `--randomize` one option is picked at random (without `--randomize`, the first option is used).
- **Variable pools** — For any variable, you can pass multiple values separated by `|`. With `--randomize`, one value is chosen per prompt.

### Examples with `--randomize`

Generate varied prompts across all categories (3 per category):
```bash
python main.py --all --randomize --count 3 --format text
```

Use variable pools so each prompt picks one of several values:
```bash
python main.py --categories LLM01 LLM02 --randomize \
  --var sensitive_data_type "API keys|passwords|PII|credentials" \
  --var target_app "MyApp|InternalTool|AdminPortal" \
  --format text
```

Same with output to a file:
```bash
python main.py --all --randomize --var target_app "AppA|AppB" -o tests.txt
