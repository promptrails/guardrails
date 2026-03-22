# LLM Guard Integration

The `llmguard` sub-package provides an HTTP client and scanner adapter for [LLM Guard](https://protectai.github.io/llm-guard/), a Python-based ML scanning service.

While the built-in scanners in `guardrails/scanners` are fast regex-based checks, LLM Guard provides transformer-based scanning with higher accuracy for toxicity, PII (NER), prompt injection, bias, and more.

## Installation

```bash
go get github.com/promptrails/guardrails
```

The `llmguard` package is included — no separate install needed.

## Running LLM Guard

### Docker Compose

```yaml
services:
  llm-guard:
    image: laiyer/llm-guard-api:latest
    ports:
      - "8000:8000"
    environment:
      - APP_PORT=8000
      - LOG_LEVEL=INFO
    volumes:
      - ./scanners.yml:/home/user/app/config/scanners.yml
```

Create a `scanners.yml` to configure which scanners to enable:

```yaml
input_scanners:
  - type: Toxicity
  - type: Anonymize
  - type: PromptInjection
  - type: BanTopics
    params:
      topics: ["violence", "drugs"]
  - type: Secrets
  - type: InvisibleText

output_scanners:
  - type: Toxicity
  - type: Bias
  - type: MaliciousURLs
  - type: NoRefusal
  - type: Sensitive
  - type: Language
    params:
      valid_languages: ["en"]
```

Start with:

```bash
docker compose up llm-guard
```

## Client Usage

```go
import "github.com/promptrails/guardrails/llmguard"

// Create client
client := llmguard.NewClient("http://localhost:8000", "optional-bearer-token")

// Scan user input
resp, err := client.ScanPrompt(ctx, "user message here")
if err != nil {
    log.Fatal(err)
}

fmt.Println("Valid:", resp.IsValid)
fmt.Println("Sanitized:", resp.SanitizedPrompt)
for _, r := range resp.Results {
    fmt.Printf("  %s: risk=%.2f valid=%v\n", r.ScannerName, r.RiskScore, r.IsValid)
}

// Scan LLM output
resp, err = client.ScanOutput(ctx, "original prompt", "llm response")
```

## As a guardrails.Scanner

The `llmguard.Scanner` implements `guardrails.Scanner` and `guardrails.Redactor`, so it plugs directly into the Guard pipeline:

```go
import (
    "github.com/promptrails/guardrails"
    "github.com/promptrails/guardrails/llmguard"
)

client := llmguard.NewClient("http://localhost:8000", "")

guard := guardrails.New(
    // ML-powered scanners via LLM Guard
    guardrails.WithScanner(
        llmguard.NewScanner(client, "Toxicity", guardrails.ScannerToxicity),
        guardrails.ActionBlock,
    ),
    guardrails.WithScanner(
        llmguard.NewScanner(client, "Anonymize", guardrails.ScannerPII),
        guardrails.ActionRedact,
    ),
    guardrails.WithScanner(
        llmguard.NewScanner(client, "PromptInjection", guardrails.ScannerPromptInjection,
            llmguard.WithThreshold(0.3), // stricter threshold
        ),
        guardrails.ActionBlock,
    ),
)

result := guard.Scan(ctx, userInput)
if !result.Passed {
    fmt.Println("Blocked:", result.Reason())
}
```

## Batch Scanning

For efficiency, you can make a single API call and evaluate multiple scanners from the cached response:

```go
client := llmguard.NewClient("http://localhost:8000", "")

// Single API call
resp, err := client.ScanPrompt(ctx, content)
if err != nil {
    log.Fatal(err)
}

// Evaluate multiple scanners from cached response
toxicity := llmguard.NewScanner(client, "Toxicity", guardrails.ScannerToxicity)
pii := llmguard.NewScanner(client, "Anonymize", guardrails.ScannerPII)

toxResult := toxicity.ScanFromCached(resp)
piiResult := pii.ScanFromCached(resp)
```

## Custom Threshold

Each scanner defaults to a risk score threshold of 0.5. Override it per-scanner:

```go
// Block if risk score >= 0.3 (stricter)
scanner := llmguard.NewScanner(client, "Toxicity", guardrails.ScannerToxicity,
    llmguard.WithThreshold(0.3),
)

// Block if risk score >= 0.8 (more lenient)
scanner := llmguard.NewScanner(client, "Bias", guardrails.ScannerToxicity,
    llmguard.WithThreshold(0.8),
)
```

## Available LLM Guard Scanners

| Scanner Name | Category | Description |
|-------------|----------|-------------|
| `Toxicity` | Input/Output | Hate speech, profanity, threats |
| `Anonymize` | Input | PII detection (names, emails, phones, SSNs) |
| `PromptInjection` | Input | Jailbreaks, override attempts |
| `BanTopics` | Input | Custom topic blocking |
| `Secrets` | Input | API keys, credentials |
| `InvisibleText` | Input | Hidden Unicode characters |
| `Bias` | Output | Gender, racial, political bias |
| `MaliciousURLs` | Output | Phishing, malware URLs |
| `NoRefusal` | Output | LLM refusal detection |
| `Sensitive` | Output | Sensitive information leakage |
| `Language` | Output | Language validation |

See [LLM Guard docs](https://protectai.github.io/llm-guard/) for the full list and configuration options.
