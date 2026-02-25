# Getting Started

## Installation

```bash
go get github.com/promptrails/guardrails
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"

    "github.com/promptrails/guardrails"
    "github.com/promptrails/guardrails/scanners"
)

func main() {
    guard := guardrails.New(
        guardrails.WithScanner(scanners.NewPII(), guardrails.ActionRedact),
        guardrails.WithScanner(scanners.NewToxicity(), guardrails.ActionBlock),
        guardrails.WithScanner(scanners.NewPromptInjection(), guardrails.ActionBlock),
        guardrails.WithScanner(scanners.NewSecrets(), guardrails.ActionBlock),
    )

    // Scan user input before sending to LLM
    result := guard.Scan(context.Background(), "My email is alice@example.com")

    if !result.Passed {
        fmt.Println("Blocked:", result.Reason())
        return
    }

    // Use result.Content (may be redacted)
    fmt.Println("Safe content:", result.Content)
}
```

## Scanning LLM Input

```go
// Check user input before sending to provider
result := guard.Scan(ctx, userInput)
if !result.Passed {
    return fmt.Errorf("input blocked: %s", result.Reason())
}

resp, _ := provider.Complete(ctx, &langrails.CompletionRequest{
    Model:    "gpt-4o",
    Messages: []langrails.Message{{Role: "user", Content: result.Content}},
})
```

## Scanning LLM Output

```go
// Check LLM output before returning to user
outputGuard := guardrails.New(
    guardrails.WithScanner(scanners.NewPII(), guardrails.ActionRedact),
    guardrails.WithScanner(scanners.NewSecrets(), guardrails.ActionRedact),
)

result := outputGuard.Scan(ctx, resp.Content)
fmt.Println(result.Content) // PII and secrets redacted
```

## Redact Only

If you just want to sanitize content without blocking:

```go
clean := guard.Redact(ctx, "Email: alice@example.com, Key: sk-abc123...")
// clean: "Email: [EMAIL_REDACTED], Key: [OPENAI_KEY_REDACTED]..."
```

## Actions

| Action | Behavior |
|--------|----------|
| `ActionBlock` | Scan fails, `result.Passed = false` |
| `ActionRedact` | Content sanitized, scan continues |
| `ActionLog` | Violation recorded, no action taken |

## Next Steps

- [Scanners](scanners.md) — Detailed scanner documentation
- [Custom Scanners](custom-scanners.md) — Build your own
