# GuardRails

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
| **InvisibleText** | Hidden Unicode characters (prompt injection) | Yes |
| **NoRefusal** | LLM refusal phrases ("I'm sorry", "As an AI") | No |
| **TokenLimit** | Max word count enforcement | No |
| **ReadingTime** | Max reading time in seconds | No |
| **JSONValidator** | JSON structure + required keys | No |
| **URLReachability** | Hallucinated/unreachable URLs | No |
| **BanCode** | Code snippets (10 language patterns) | No |
| **MaliciousURL** | Suspicious TLDs, IP hosts, phishing keywords | No |
| **Sentiment** | Negative sentiment (lexicon-based) | No |

## Actions

| Action | Behavior |
|--------|----------|
| `ActionBlock` | Stop processing, mark as failed |
| `ActionRedact` | Replace matches with labels, continue |
| `ActionLog` | Record violation, continue unchanged |

## LLM Guard Integration

For ML-powered scanning, the `llmguard` sub-package connects to [LLM Guard](https://llm-guard.com):

```go
import "github.com/promptrails/guardrails/llmguard"

client := llmguard.NewClient("http://localhost:8000", "")

guard := guardrails.New(
    guardrails.WithScanner(
        llmguard.NewScanner(client, "Toxicity", guardrails.ScannerToxicity),
        guardrails.ActionBlock,
    ),
)
```

## Documentation

| | |
|---|---|
| [Getting Started](docs/getting-started.md) | Installation and quick start |
| [Scanners](docs/scanners.md) | All scanners with config options |
| [LLM Guard](docs/llm-guard.md) | ML-powered scanning via LLM Guard API |
| [Custom Scanners](docs/custom-scanners.md) | Build your own scanner |

Full docs: [promptrails.github.io/guardrails](https://promptrails.github.io/guardrails)

## License

MIT — [PromptRails](https://promptrails.com)

## Part of the PromptRails AI Toolkit

- [LangRails](https://github.com/promptrails/langrails) — Unified LLM provider
- **GuardRails** — Content safety scanning
- [MemoryRails](https://github.com/promptrails/memoryrails) — Agent memory
- [MediaRails](https://github.com/promptrails/mediarails) — AI media generation
- [Go AI Toolkit](https://github.com/promptrails/go-ai-toolkit) — Demo app
