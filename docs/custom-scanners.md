# Custom Scanners

Implement the `Scanner` interface to create your own scanner. Optionally implement `Redactor` for content sanitization.

## Scanner Interface

```go
type Scanner interface {
    Scan(ctx context.Context, content string) *Result
    Type() ScannerType
}

type Redactor interface {
    Redact(ctx context.Context, content string) string
}
```

## Example: Language Filter

```go
package main

import (
    "context"
    "strings"

    "github.com/promptrails/guardrails"
)

type LanguageFilter struct {
    allowed []string
}

func NewLanguageFilter(allowed ...string) *LanguageFilter {
    return &LanguageFilter{allowed: allowed}
}

func (f *LanguageFilter) Type() guardrails.ScannerType {
    return "language_filter"
}

func (f *LanguageFilter) Scan(_ context.Context, content string) *guardrails.Result {
    // Simple heuristic: check for non-ASCII characters
    for _, r := range content {
        if r > 127 {
            return &guardrails.Result{
                Passed:  false,
                Scanner: f.Type(),
                Message: "non-ASCII characters detected",
            }
        }
    }
    return &guardrails.Result{Passed: true, Scanner: f.Type()}
}
```

## Using Custom Scanners

```go
guard := guardrails.New(
    guardrails.WithScanner(NewLanguageFilter("en"), guardrails.ActionBlock),
    guardrails.WithScanner(scanners.NewPII(), guardrails.ActionRedact),
)
```

## Example: Word Count Limit

```go
type WordCountLimit struct {
    max int
}

func (w *WordCountLimit) Type() guardrails.ScannerType { return "word_count" }

func (w *WordCountLimit) Scan(_ context.Context, content string) *guardrails.Result {
    words := strings.Fields(content)
    if len(words) > w.max {
        return &guardrails.Result{
            Passed:  false,
            Scanner: w.Type(),
            Message: fmt.Sprintf("content exceeds %d words (has %d)", w.max, len(words)),
        }
    }
    return &guardrails.Result{Passed: true, Scanner: w.Type()}
}
```

## Example: Regex Scanner with Redaction

```go
type RegexScanner struct {
    name    string
    pattern *regexp.Regexp
    label   string
}

func (s *RegexScanner) Type() guardrails.ScannerType {
    return guardrails.ScannerType(s.name)
}

func (s *RegexScanner) Scan(_ context.Context, content string) *guardrails.Result {
    if s.pattern.MatchString(content) {
        return &guardrails.Result{
            Passed:  false,
            Scanner: s.Type(),
            Message: fmt.Sprintf("%s pattern detected", s.name),
        }
    }
    return &guardrails.Result{Passed: true, Scanner: s.Type()}
}

func (s *RegexScanner) Redact(_ context.Context, content string) string {
    return s.pattern.ReplaceAllString(content, s.label)
}
```
