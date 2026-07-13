# shhh-ai 🔐

> AI-assisted secret-candidate triage with pattern matching, entropy analysis, redaction-by-default output, and conservative LLM review.

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4.1--mini-412991?style=flat-square&logo=openai&logoColor=white)](https://openai.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Security](https://img.shields.io/badge/Category-DevSecOps-red?style=flat-square)]()
[![Stars](https://img.shields.io/github/stars/whathehack81/shhh-ai?style=flat-square)](https://github.com/whathehack81/shhh-ai/stargazers)

## Origin and attribution

`shhh-ai` is derived from the MIT-licensed [`rawqubit/gitleaks-ai`](https://github.com/rawqubit/gitleaks-ai) project.

The original copyright notice remains in [`LICENSE`](LICENSE), as required by the MIT license. This fork is maintained by `whathehack81` and includes additional work such as:

- Rebranding and CLI/documentation updates
- Redaction-by-default output
- Conservative AI-failure behavior that does not silently suppress findings
- Explicit machine-readable findings artifacts
- Safer external-AI review payloads with candidate values redacted
- Additional false-positive handling and scanner refinements

See [`NOTICE`](NOTICE) for the attribution record.

## Detection pipeline

```text
Input → Pattern matching → Entropy analysis → Optional AI context review → Findings
```

1. **Pattern matching** identifies common credential and token formats.
2. **Entropy analysis** helps prioritize random-looking candidate values.
3. **Optional AI review** evaluates surrounding context while receiving a redacted candidate value.

AI review is advisory. Failures leave findings unresolved rather than automatically marking them safe.

## Data handling and review model

- Finding values are redacted in normal output by default.
- Candidate secret values are replaced before external AI review.
- Surrounding source context may still be sent to the configured AI provider.
- Do not enable AI review for source code you are not permitted to share with that provider.
- Do not treat an AI false-positive verdict as authoritative without human review.
- Use `--trusted-ai-gate` only when you have explicitly accepted AI verdicts as part of your CI policy.

## Benchmark status

No independently reproducible benchmark dataset is currently published with this repository. Performance and false-positive reduction depend on the repository, detector patterns, entropy threshold, and model behavior.

Earlier numerical benchmark claims have been removed until the dataset, methodology, and results can be published and reproduced.

## Features

- Common secret and credential patterns
- Shannon entropy scoring
- Optional batched AI context review
- Composite risk scoring
- Redaction-by-default output
- JSON, Markdown, and terminal output
- Machine-readable findings files
- Static remediation guidance
- Conservative CI behavior

## Installation

```bash
git clone https://github.com/whathehack81/shhh-ai.git
cd shhh-ai
pip install -r requirements.txt
```

AI review additionally requires an OpenAI API key:

```bash
export OPENAI_API_KEY="sk-..."
```

## Usage

```bash
# Scan the current directory
python main.py scan .

# Save machine-readable findings
python main.py scan . --output json --findings findings.json

# Enable AI-assisted review
python main.py scan /path/to/repo --ai-review

# Generate a remediation report
python main.py scan . --ai-review --report remediation.md

# Tune the entropy threshold
python main.py scan . --min-entropy 4.5
```

## Architecture

```text
shhh-ai/
├── main.py              # Click CLI and output handling
├── src/
│   ├── scanner.py       # Pattern matching and entropy analysis
│   └── ai_reviewer.py   # Redacted, conservative AI review
└── requirements.txt
```

## CI example

```yaml
- name: Scan for secrets
  run: |
    pip install -r requirements.txt
    python main.py scan . --ai-review --no-fp
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

For high-assurance environments, keep AI verdicts advisory and require human confirmation before suppressing a finding.

## Maintainer and intent

This fork is maintained by **Rob (`whathehack81`)** as part of a broader validation-first security tooling effort.

The goal is not to replace analyst judgment with an LLM. The goal is to make secret-candidate review safer, more structured, and easier to audit while keeping uncertain findings visible until a human can verify them.

That same philosophy drives [`Casper`](https://github.com/whathehack81/Casper): preserve the evidence, state uncertainty honestly, and never suppress or escalate a finding beyond what the evidence supports.

## Contributing

Contributions are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

Useful contribution areas include:

- Reproducible benchmark datasets
- Additional service-specific patterns
- False-positive regression fixtures
- Provider-neutral AI review adapters
- Secret-manager integration

## License

MIT License. The original upstream copyright notice is preserved in [`LICENSE`](LICENSE). See [`NOTICE`](NOTICE) for provenance and fork attribution.
