# OWASP LLM Top 10 — Security Test Prompt Generator

A modular Python tool for generating adversarial test prompts to evaluate LLM
security controls against the
[OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

## Architecture

```
main.py                  ← CLI entry point (interactive menu + argparse)
models.py                ← Data models: VulnerabilityCategory, PromptTemplate
registry.py              ← Central registry of all categories
generator.py             ← Renders templates with variable substitution & randomization
formatters.py            ← Output formatters (JSON, plain text)
categories/              ← One module per OWASP LLM Top 10 vulnerability
    prompt_injection.py      LLM01
    data_leakage.py          LLM02
    insecure_output.py       LLM03
    training_data_poisoning  LLM04
    model_dos.py             LLM05
    supply_chain.py          LLM06
    sensitive_disclosure.py  LLM07
    model_theft.py           LLM08
    excessive_agency.py      LLM09
    overreliance.py          LLM10
```

Each category module exposes a single `register()` function that returns a
`VulnerabilityCategory` populated with `PromptTemplate` objects. Adding a new
category is as simple as creating a new file in `categories/` and importing it
in `main.py`.

## Usage

### Interactive mode
```bash
python main.py
```

### List categories
```bash
python main.py --list
```

### Generate for specific categories
```bash
python main.py --categories LLM01 LLM03 --format json -o results.json
```

### Generate all with randomization
```bash
python main.py --all --randomize --count 3 --format text
```

### Set variables via CLI
```bash
python main.py --categories LLM01 --var target_app MyApp --var sensitive_data_type "API keys" --format json
```

## Adding a New Category

1. Create `categories/my_vuln.py`
2. Define a `register()` function returning a `VulnerabilityCategory`
3. Import and add it to the `modules` list in `main.py`

## Template Variables

Templates use `{variable_name}` placeholders. Common variables:

| Variable              | Description                          | Default           |
|-----------------------|--------------------------------------|--------------------|
| `target_app`          | Name of the target application       | TargetApp          |
| `system_prompt`       | The system prompt to test against    | You are a helpful… |
| `sensitive_data_type` | Type of sensitive data to probe for  | API keys           |
| `api_endpoint`        | Target API URL                       | https://api.…      |
| `internal_url`        | Internal service URL                 | http://internal-…  |
| `plugin_name`         | Plugin or tool name                  | example-plugin     |
| `model_name`          | Target model identifier              | target-model-v1    |

## Output Formats

- **text**: Human-readable report with sections per category
- **json**: Structured JSON suitable for automated scanning pipelines

## Requirements

Python 3.8+ (standard library only, no external dependencies).
