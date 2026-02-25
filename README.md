# guardrails

Lightweight content safety scanning for Go LLM applications.

[![Go Reference](https://pkg.go.dev/badge/github.com/promptrails/guardrails.svg)](https://pkg.go.dev/github.com/promptrails/guardrails)
[![CI](https://github.com/promptrails/guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/promptrails/guardrails/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/promptrails/guardrails)](https://goreportcard.com/report/github.com/promptrails/guardrails)

```go
guard := guardrails.New(
    guardrails.WithScanner(scanners.NewPII(), guardrails.ActionRedact),
    guardrails.WithScanner(scanners.NewToxicity(), guardrails.ActionBlock),
    guardrails.WithScanner(scanners.NewPromptInjection(), guardrails.ActionBlock),
)

result := guard.Scan(ctx, userInput)
if !result.Passed {
    // Input blocked
}
```

## Install

```bash
go get github.com/promptrails/guardrails
```

## Scanners

| Scanner | Detects | Redaction |
|---------|---------|-----------|
| **PII** | Email, phone, SSN, credit card, IP address | Yes |
| **Toxicity** | Offensive language (keyword matching) | No |
| **BanSubstrings** | Custom banned words/phrases | Yes |
| **PromptInjection** | Override instructions, jailbreaks, role hijacking | No |
| **Secrets** | API keys, tokens, private keys, connection strings | Yes |

## Actions

| Action | Behavior |
|--------|----------|
| `ActionBlock` | Stop processing, mark as failed |
| `ActionRedact` | Replace matches with labels, continue |
| `ActionLog` | Record violation, continue unchanged |

## Documentation

| | |
|---|---|
| [Getting Started](docs/getting-started.md) | Installation and quick start |
| [Scanners](docs/scanners.md) | All scanners with config options |
| [Custom Scanners](docs/custom-scanners.md) | Build your own scanner |

Full docs: [promptrails.github.io/guardrails](https://promptrails.github.io/guardrails)

## Scope

This library provides fast, local, regex-based content scanning with zero dependencies. It's designed for common safety checks in Go LLM applications.

For ML-powered scanning with higher accuracy (transformer-based toxicity detection, NER-based PII, etc.), see [LLM Guard](https://github.com/protectai/llm-guard) (Python).

## License

MIT — [PromptRails](https://promptrails.com)
